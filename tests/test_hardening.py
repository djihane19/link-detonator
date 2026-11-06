"""Regression tests for abuse limits, honest evidence and hostile-report rendering.

Offline: nothing leaves 127.0.0.1. Docker and the firewall are not exercised here, and these
tests prove nothing about them.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import re
import subprocess
import sys
import threading
import time
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import httpx
import playwright
import pytest
import pytest_asyncio
from loopback_server import LoopbackServer

from app import urlpolicy
from app.config import SECRET_CANARY_ENV, Settings
from app.main import create_app
from app.models import ScanTarget, validate_worker_event
from app.ratelimit import SlidingWindowLimiter
from app.sandbox import _DockerClient, plant_secret_canary
from app.scans import MAX_CONCURRENT_LOG_READS, ReadersBusyError, ScanManager
from app.urlpolicy import ResolverBusy, UrlPolicyError, check_url_syntax

ROOT = Path(__file__).resolve().parent.parent
CODE = "test-access-code-not-real"
FIXTURE = ScanTarget(kind="fixture", value="benign")


def load_worker() -> Any:
    spec = importlib.util.spec_from_file_location("ld_worker_under_test", ROOT / "worker" / "worker.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


worker = load_worker()


class Runner:
    """Holds every scan open until released, so queues and caps can be observed."""

    isolated = True

    def __init__(self, hold: bool = False) -> None:
        self.release = asyncio.Event()
        if not hold:
            self.release.set()

    async def reap(self) -> int:
        return 0

    async def run(self, _: str, __: ScanTarget, emit: Any) -> None:
        await emit("worker_started", {"url": "u", "mode": "fixture", "offline": False}, "worker")
        await self.release.wait()
        await emit("worker_finished", {"status": "ok", "error": None}, "worker")


async def resolver(_: str) -> list[str]:
    return ["93.184.216.34"]


class Api:
    def __init__(self, app: Any, client: httpx.AsyncClient, runner: Runner) -> None:
        self.app, self.client, self.runner = app, client, runner

    async def post(self, payload: dict[str, Any], ip: str = "203.0.113.1") -> httpx.Response:
        return await self.client.post("/api/scans", json=payload, headers={"X-Forwarded-For": ip})


@pytest_asyncio.fixture
async def make_api(tmp_path: Path) -> AsyncIterator[Any]:
    opened: list[tuple[Any, httpx.AsyncClient, Runner]] = []

    async def make(hold: bool = False, **overrides: Any) -> Api:
        runner = Runner(hold)
        settings = Settings(data_dir=tmp_path, trust_proxy=True, **overrides)
        app = create_app(settings=settings, runner=runner, resolver=resolver)
        context = app.router.lifespan_context(app)
        await context.__aenter__()
        transport = httpx.ASGITransport(app=app, client=("198.51.100.7", 1234))
        client = httpx.AsyncClient(transport=transport, base_url="http://testserver")
        opened.append((context, client, runner))
        return Api(app, client, runner)

    yield make
    for context, client, runner in opened:
        runner.release.set()
        await client.aclose()
        await context.__aexit__(None, None, None)


# ---- Live URL access


@pytest.mark.asyncio
async def test_live_url_is_off_without_a_configured_code(make_api: Any) -> None:
    api = await make_api()
    response = await api.post({"url": "https://public.example.com/"})
    assert response.status_code == 403
    assert "not enabled" in response.json()["detail"]


@pytest.mark.asyncio
async def test_live_url_needs_the_code_but_fixtures_do_not(make_api: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LD_LIVE_ACCESS_CODE", CODE)
    api = await make_api()
    assert (await api.post({"url": "https://public.example.com/"})).status_code == 403
    assert (await api.post({"url": "https://public.example.com/", "access_code": "wrong"})).status_code == 403
    assert (await api.post({"fixture": "benign", "access_code": "wrong"})).status_code == 403
    assert (await api.post({"fixture": "benign"})).status_code == 202
    assert (await api.post({"url": "https://public.example.com/", "access_code": CODE})).status_code == 202


@pytest.mark.asyncio
async def test_no_lookup_happens_for_a_live_url_without_the_code(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LD_LIVE_ACCESS_CODE", CODE)
    lookups: list[str] = []

    async def counting(host: str) -> list[str]:
        lookups.append(host)
        return ["93.184.216.34"]

    app = create_app(settings=Settings(data_dir=tmp_path), runner=Runner(), resolver=counting)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app, client=("198.51.100.7", 1234))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.post("/api/scans", json={"url": "https://public.example.com/"})
    assert response.status_code == 403
    assert lookups == []


@pytest.mark.asyncio
async def test_kill_switch_stops_live_scans_even_with_the_code(make_api: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LD_LIVE_ACCESS_CODE", CODE)
    api = await make_api(live_scans_enabled=False)
    response = await api.post({"url": "https://public.example.com/", "access_code": CODE})
    assert response.status_code == 403
    assert "switched off" in response.json()["detail"]
    assert (await api.post({"fixture": "benign"})).status_code == 202


@pytest.mark.asyncio
async def test_daily_live_budget_applies_to_code_holders(make_api: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LD_LIVE_ACCESS_CODE", CODE)
    api = await make_api(live_scans_per_day=1)
    body = {"url": "https://public.example.com/", "access_code": CODE}
    assert (await api.post(body)).status_code == 202
    refused = await api.post(body)
    assert refused.status_code == 429
    assert "budget" in refused.json()["detail"]
    assert (await api.post({"fixture": "benign"})).status_code == 202


# ---- Per-client and global limits


@pytest.mark.asyncio
async def test_one_client_cannot_hold_more_than_its_share_of_the_queue(make_api: Any) -> None:
    api = await make_api(hold=True, max_active_per_client=2, concurrency=1)
    assert (await api.post({"fixture": "benign"})).status_code == 202
    assert (await api.post({"fixture": "benign"})).status_code == 202
    refused = await api.post({"fixture": "benign"})
    assert refused.status_code == 429
    assert (await api.post({"fixture": "benign"}, ip="203.0.113.2")).status_code == 202


@pytest.mark.asyncio
async def test_cap_frees_up_when_a_scan_finishes(make_api: Any) -> None:
    api = await make_api(hold=True, max_active_per_client=1)
    first = await api.post({"fixture": "benign"})
    assert (await api.post({"fixture": "benign"})).status_code == 429
    api.runner.release.set()
    scan = api.app.state.manager.get(first.json()["id"])
    async with asyncio.timeout(5):
        while not scan.is_final:
            await asyncio.sleep(0.005)
    assert (await api.post({"fixture": "benign"})).status_code == 202


@pytest.mark.asyncio
async def test_global_budget_limits_many_clients(make_api: Any) -> None:
    api = await make_api(global_scans_per_hour=2)
    assert (await api.post({"fixture": "benign"}, ip="203.0.113.1")).status_code == 202
    assert (await api.post({"fixture": "benign"}, ip="203.0.113.2")).status_code == 202
    refused = await api.post({"fixture": "benign"}, ip="203.0.113.3")
    assert refused.status_code == 429
    assert int(refused.headers["Retry-After"]) >= 1


@pytest.mark.asyncio
async def test_a_budget_refusal_does_not_use_up_the_clients_quota() -> None:
    limiter = SlidingWindowLimiter(1, 10)
    assert limiter.peek("a").allowed
    assert limiter.peek("a").allowed
    assert limiter.check("a").allowed
    assert not limiter.peek("a").allowed


@pytest.mark.asyncio
async def test_reserved_places_let_a_code_holder_past_a_full_queue(make_api: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LD_LIVE_ACCESS_CODE", CODE)
    api = await make_api(hold=True, concurrency=1, queue_size=2, reserved_queue_slots=1)
    manager = api.app.state.manager
    assert (await api.post({"fixture": "benign"}, ip="203.0.113.1")).status_code == 202
    async with asyncio.timeout(5):
        while manager.load_stats()["running"] != 1:
            await asyncio.sleep(0.005)
    for index in (2, 3):
        assert (await api.post({"fixture": "benign"}, ip=f"203.0.113.{index}")).status_code == 202
    assert (await api.post({"fixture": "benign"}, ip="203.0.113.9")).status_code == 503
    assert (await api.post({"fixture": "benign", "access_code": CODE}, ip="203.0.113.9")).status_code == 202


# ---- Reads


@pytest.mark.asyncio
async def test_reads_are_rate_limited_per_client(make_api: Any) -> None:
    api = await make_api(read_rate_per_minute=2)
    scan_id = (await api.post({"fixture": "benign"})).json()["id"]
    headers = {"X-Forwarded-For": "203.0.113.5"}
    assert (await api.client.get(f"/api/scans/{scan_id}", headers=headers)).status_code == 200
    assert (await api.client.get(f"/api/scans/{scan_id}", headers=headers)).status_code == 200
    assert (await api.client.get(f"/api/scans/{scan_id}", headers=headers)).status_code == 429
    assert (await api.client.get(f"/api/scans/{scan_id}", headers={"X-Forwarded-For": "203.0.113.6"})).status_code == 200


async def wait_final(manager: ScanManager, scan_id: str) -> None:
    async with asyncio.timeout(5):
        while not manager.get(scan_id).is_final:  # type: ignore[union-attr]
            await asyncio.sleep(0.005)


@pytest.mark.asyncio
async def test_finished_snapshot_is_cached_and_forgotten_when_pruned(tmp_path: Path) -> None:
    manager = ScanManager(Settings(data_dir=tmp_path), Runner())
    await manager.start()
    try:
        scan = manager.submit(FIXTURE)
        await wait_final(manager, scan.id)
        first = await manager.snapshot_body(scan.id)
        assert first is not None
        assert json.loads(first)["status"] == "ok"
        assert await manager.snapshot_body(scan.id) is first
        await manager._remove([scan])
        assert await manager.snapshot_body(scan.id) is None
        assert manager._snapshot_cache_size == 0
    finally:
        await manager.stop()


@pytest.mark.asyncio
async def test_uncached_final_read_is_refused_when_every_slot_is_busy(tmp_path: Path) -> None:
    manager = ScanManager(Settings(data_dir=tmp_path), Runner())
    await manager.start()
    try:
        scan = manager.submit(FIXTURE)
        await wait_final(manager, scan.id)
        for _ in range(MAX_CONCURRENT_LOG_READS):
            await manager._read_slots.acquire()
        with pytest.raises(ReadersBusyError):
            await manager.snapshot_body(scan.id)
    finally:
        for _ in range(MAX_CONCURRENT_LOG_READS):
            manager._read_slots.release()
        await manager.stop()


# ---- Event streams, over real HTTP so that open connections really stay open


def test_one_client_cannot_take_every_stream(tmp_path: Path) -> None:
    async def never_finish(_: str, __: ScanTarget, emit: Any) -> None:
        await asyncio.sleep(30)

    class Hanging(Runner):
        run = staticmethod(never_finish)  # type: ignore[assignment]

    app = create_app(
        settings=Settings(data_dir=tmp_path, trust_proxy=True, max_streams_per_client=2),
        runner=Hanging(),
    )
    with LoopbackServer(app) as base, httpx.Client(base_url=base, timeout=5) as client:
        heavy = {"X-Forwarded-For": "203.0.113.1"}
        scan_id = client.post("/api/scans", json={"fixture": "benign"}, headers=heavy).json()["id"]
        url = f"/api/scans/{scan_id}/events"
        with client.stream("GET", url, headers=heavy) as one, client.stream("GET", url, headers=heavy) as two:
            assert (one.status_code, two.status_code) == (200, 200)
            assert client.get(url, headers=heavy).status_code == 429
            with client.stream("GET", url, headers={"X-Forwarded-For": "203.0.113.2"}) as other:
                assert other.status_code == 200
        # Closed streams give their places back.
        for _ in range(100):
            with client.stream("GET", url, headers=heavy) as again:
                if again.status_code == 200:
                    break
            time.sleep(0.02)
        else:
            pytest.fail("stream slots were not released")


@pytest.mark.asyncio
async def test_restart_keeps_sse_replay_for_finished_scans(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path)
    first = ScanManager(settings, Runner())
    await first.start()
    scan = first.submit(FIXTURE)
    await wait_final(first, scan.id)
    last = first.last_seq(scan)
    await first.stop()
    assert last >= 3

    second = ScanManager(settings, Runner())
    await second.start()
    try:
        reloaded = second.get(scan.id)
        assert reloaded is not None
        assert second.last_seq(reloaded) == last
    finally:
        await second.stop()


@pytest.mark.asyncio
async def test_restart_restores_replay_for_logs_written_before_meta_had_it(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path)
    first = ScanManager(settings, Runner())
    await first.start()
    scan = first.submit(FIXTURE)
    await wait_final(first, scan.id)
    last = first.last_seq(scan)
    await first.stop()
    meta_path = tmp_path / "scans" / scan.id / "meta.json"
    meta = json.loads(meta_path.read_text())
    del meta["next_seq"]
    meta_path.write_text(json.dumps(meta))

    second = ScanManager(settings, Runner())
    await second.start()
    try:
        assert second.last_seq(second.get(scan.id)) == last  # type: ignore[arg-type]
    finally:
        await second.stop()


# ---- Retention


@pytest.mark.asyncio
async def test_concurrent_prunes_do_not_collide(tmp_path: Path) -> None:
    manager = ScanManager(Settings(data_dir=tmp_path, disk_cap_mb=1), Runner())
    await manager.start()
    try:
        scans = [manager.submit(FIXTURE) for _ in range(3)]
        for scan in scans:
            await wait_final(manager, scan.id)
            (tmp_path / "scans" / scan.id / "ballast.bin").write_bytes(b"x" * (1024 * 1024))
        await asyncio.gather(manager.prune(), manager.prune(), manager.prune())
    finally:
        await manager.stop()


@pytest.mark.asyncio
async def test_a_failing_sweep_does_not_end_the_retention_loop(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.scans.RETENTION_SWEEP_S", 0.001)
    manager = ScanManager(Settings(data_dir=tmp_path), Runner())
    calls = 0

    async def failing() -> None:
        nonlocal calls
        calls += 1
        raise KeyError("boom")

    monkeypatch.setattr(manager, "prune", failing)
    task = asyncio.create_task(manager._retention_loop())
    await asyncio.sleep(0.05)
    assert not task.done()
    task.cancel()
    assert calls >= 2


# ---- URL policy


def test_lone_surrogate_is_refused() -> None:
    with pytest.raises(UrlPolicyError):
        check_url_syntax("http://public.example.org/\ud800")


@pytest.mark.asyncio
async def test_lone_surrogate_in_a_body_gets_a_400(make_api: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LD_LIVE_ACCESS_CODE", CODE)
    api = await make_api()
    raw = ('{"url":"http://public.example.org/\\ud800","access_code":"' + CODE + '"}').encode()
    response = await api.client.post("/api/scans", content=raw, headers={"Content-Type": "application/json"})
    assert response.status_code == 400


@pytest.mark.parametrize(
    "host",
    ["faß.de", "βόλος.gr", "bücher.example.org", "BÜCHER.example.org", "xn--bcher-kva.example.org"],
)
def test_idn_host_matches_what_chromium_would_open(host: str) -> None:
    sync_api = pytest.importorskip("playwright.sync_api")
    with sync_api.sync_playwright() as driver:
        try:
            browser = driver.chromium.launch()
        except sync_api.Error as exc:
            pytest.skip(f"Chromium is not available: {exc}")
        page = browser.new_page()
        # about:blank only: new URL() parses without any network.
        expected = page.evaluate("(host) => new URL(`http://${host}/`).hostname", host)
        browser.close()
    assert check_url_syntax(f"http://{host}/").host == expected


def test_deviation_characters_are_not_folded_into_another_domain() -> None:
    assert check_url_syntax("http://faß.de/").host == "xn--fa-hia.de"
    assert check_url_syntax("http://βόλος.gr/").host == "xn--nxasmm1c.gr"


def test_joiner_in_a_host_is_refused_rather_than_deleted() -> None:
    with pytest.raises(UrlPolicyError):
        check_url_syntax("http://pay‍pal-like.example.org/")


@pytest.mark.asyncio
async def test_slow_lookups_do_not_touch_the_shared_pool_and_refuse_when_full(monkeypatch: pytest.MonkeyPatch) -> None:
    release = threading.Event()

    def blocked(*_: Any, **__: Any) -> list[Any]:
        release.wait(10)
        raise OSError("no answer")

    monkeypatch.setattr(urlpolicy.socket, "getaddrinfo", blocked)
    monkeypatch.setattr(urlpolicy, "DNS_TIMEOUT_S", 0.05)
    bounded = urlpolicy._BoundedResolver(workers=2, max_in_flight=2)
    try:
        for _ in range(2):
            with pytest.raises(TimeoutError):
                await bounded("slow.example.org")
        # Both given up on, but their threads are still stuck: the places stay taken.
        with pytest.raises(ResolverBusy):
            await bounded("next.example.org")
        started = time.monotonic()
        await asyncio.to_thread(lambda: None)
        assert time.monotonic() - started < 1
    finally:
        release.set()
    for _ in range(100):
        if bounded._in_flight == 0:
            break
        await asyncio.sleep(0.01)
    assert bounded._in_flight == 0


@pytest.mark.asyncio
async def test_busy_resolver_answers_503(make_api: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("LD_LIVE_ACCESS_CODE", CODE)

    async def busy(_: str) -> list[str]:
        raise ResolverBusy

    app = create_app(settings=Settings(data_dir=tmp_path), runner=Runner(), resolver=busy)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app, client=("198.51.100.7", 1234))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.post(
                "/api/scans", json={"url": "https://public.example.com/", "access_code": CODE}
            )
    assert response.status_code == 503


# ---- Worker: reporting private answers, and live-mode restraint


def test_worker_feature_list_keeps_everything_playwright_disables() -> None:
    bundle = Path(playwright.__file__).parent / "driver" / "package" / "lib" / "coreBundle.js"
    source = bundle.read_text(encoding="utf-8", errors="replace")
    block = re.search(r"disabledFeatures = \[(.*?)\]\.filter", source, re.S)
    assert block is not None
    without_comments = re.sub(r"//[^\n]*", "", block.group(1))
    assert set(re.findall(r'"([A-Za-z0-9]+)"', without_comments)) <= set(worker.PLAYWRIGHT_DISABLED_FEATURES)


@pytest.mark.parametrize("offline", [True, False])
def test_chromium_gate_is_turned_off_in_a_single_flag(offline: bool) -> None:
    flags = [arg for arg in worker.chromium_args(offline) if arg.startswith("--disable-features=")]
    assert len(flags) == 1
    for feature in ("LocalNetworkAccessChecks", "BlockInsecurePrivateNetworkRequests", "HttpsUpgrades"):
        assert feature in flags[0]


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://169.254.169.254/x", True),
        ("http://10.0.0.1/", True),
        ("http://127.0.0.1:8000/", True),
        ("http://[::1]:8000/", True),
        ("http://intranet/", True),
        ("http://a.internal/", True),
        ("https://public.example.org/", False),
        ("http://93.184.216.34/", False),
        ("http://fixtures.invalid/benign", False),
    ],
)
def test_worker_url_classifier(url: str, expected: bool) -> None:
    assert worker.url_is_non_public(url) is expected


class FakeResponse:
    def __init__(self, url: str, peer: str | None, status: int = 200) -> None:
        self.url, self.status, self._peer = url, status, peer
        self.request = object()

    async def server_addr(self) -> dict[str, Any] | None:
        return {"ipAddress": self._peer, "port": 80} if self._peer else None


class Recorder:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    def emit(self, event_type: str, data: dict[str, Any]) -> bool:
        self.events.append((event_type, data))
        return True


def make_scan(recorder: Recorder) -> Any:
    config = worker.Config("http://x/", "fixture", False, 30.0, 1.0, Path("/nonexistent"))
    return worker.Scan(config, recorder, worker.Deadline(30.0), Path("/nonexistent"))


@pytest.mark.asyncio
async def test_worker_reports_a_subresource_answered_by_a_private_literal() -> None:
    recorder = Recorder()
    make_scan(recorder)._check_response_destination(FakeResponse("http://169.254.169.254/x", None))
    assert recorder.events == [("response", {"url": "http://169.254.169.254/x", "status": 200, "peer_ip": None})]
    assert validate_worker_event("response", recorder.events[0][1]) is not None


@pytest.mark.asyncio
async def test_worker_reports_a_public_name_that_connected_to_a_private_address() -> None:
    recorder = Recorder()
    scan = make_scan(recorder)
    scan._check_response_destination(FakeResponse("http://rebind.example.org/", "10.1.2.3"))
    await asyncio.gather(*scan._peer_lookups)
    assert recorder.events[0][1]["peer_ip"] == "10.1.2.3"


@pytest.mark.asyncio
async def test_worker_stays_quiet_for_public_peers_and_fixtures() -> None:
    recorder = Recorder()
    scan = make_scan(recorder)
    scan._check_response_destination(FakeResponse("https://public.example.org/", "93.184.216.34"))
    scan._check_response_destination(FakeResponse("http://fixtures.invalid/benign", None))
    await asyncio.gather(*scan._peer_lookups)
    assert recorder.events == []


class FakeRoute:
    def __init__(self, method: str, url: str = "https://public.example.org/x") -> None:
        self.request = type("Req", (), {"method": method, "url": url})()
        self.outcome: str | None = None

    async def continue_(self) -> None:
        self.outcome = "continued"

    async def abort(self, reason: str) -> None:
        self.outcome = reason


@pytest.mark.parametrize(
    ("method", "outcome"),
    [("GET", "continued"), ("HEAD", "continued"), ("OPTIONS", "continued"), ("POST", "blockedbyclient"), ("PUT", "blockedbyclient"), ("DELETE", "blockedbyclient")],
)
@pytest.mark.asyncio
async def test_live_mode_only_lets_reads_through(method: str, outcome: str) -> None:
    route = FakeRoute(method)
    await make_scan(Recorder())._route_live_mode(route)
    assert route.outcome == outcome


def test_worker_finished_carries_structured_flags() -> None:
    read_fd, write_fd = os.pipe()
    writer = worker.EventWriter(write_fd)
    writer.tracking_shed = True
    writer.deadline_reached = True
    writer.finish("partial", "internal deadline reached")
    line = os.read(read_fd, 65536)
    data = json.loads(line)["data"]
    assert data["tracking_shed"] is True and data["deadline_reached"] is True
    clean = validate_worker_event("worker_finished", data)
    assert clean is not None and clean["tracking_shed"] is True and clean["deadline_reached"] is True


def test_response_events_outlast_the_total_cap() -> None:
    assert "response" in worker.ESSENTIAL_EVENTS


def test_canary_is_planted_once_and_never_passed_to_the_docker_client(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(SECRET_CANARY_ENV, raising=False)
    first = plant_secret_canary()
    assert len(first) >= 32
    assert plant_secret_canary() == first
    assert SECRET_CANARY_ENV not in _DockerClient(Settings()).env


def test_a_future_key_is_audited_without_configuration() -> None:
    settings = Settings(secret_env_names=())
    assert settings.secret_values({"SOME_LLM_API_KEY": "long-enough-value", "OTHER": "x"}) == ["long-enough-value"]
    assert settings.secret_values({"SHORT_TOKEN": "1"}) == []
    assert settings.secret_values({"LD_SECRET_ENV_NAMES": "VULTR_API_KEY"}) == []


# ---- Deploy scripts: text and helpers only. Nothing here runs iptables or Docker.


@pytest.mark.parametrize("script", sorted(p.name for p in (ROOT / "deploy").glob("*.sh")))
def test_deploy_script_syntax(script: str) -> None:
    subprocess.run(["bash", "-n", str(ROOT / "deploy" / script)], check=True)


def firewall_rules() -> list[str]:
    result = subprocess.run(
        ["bash", str(ROOT / "deploy" / "firewall.sh"), "--print-rules"],
        check=True, capture_output=True, text=True,
    )
    return result.stdout.splitlines()


def test_firewall_keeps_rejecting_and_throttles_in_the_right_order() -> None:
    rules = firewall_rules()
    index = {name: next(i for i, rule in enumerate(rules) if name in rule) for name in
             ("ld-egress-bytes", "ESTABLISHED", "169.254.0.0/16", "connlimit", "ld-new-conns", "--dport 443")}
    assert index["ld-egress-bytes"] < index["ESTABLISHED"], "an upload is established traffic"
    assert index["169.254.0.0/16"] < index["connlimit"], "private targets get the plain rejection first"
    assert index["connlimit"] < index["--dport 443"]
    assert index["ld-new-conns"] < index["--dport 443"]
    assert all("icmp-admin-prohibited" in rule for rule in rules if "169.254" in rule or "10.0.0.0/8" in rule)


def run_checker(check: str, events: list[dict[str, Any]]) -> list[list[str]]:
    lines = "\n".join(json.dumps(event) for event in events) + "\nnot json\n"
    result = subprocess.run(
        [sys.executable, str(ROOT / "deploy" / "check_worker_events.py"), check],
        input=lines, capture_output=True, text=True, check=True,
    )
    return [line.split("\t") for line in result.stdout.splitlines()]


def failed(url: str, error: str) -> dict[str, Any]:
    return {"type": "request_failed", "data": {"url": url, "error": error}}


def test_vm_check_passes_only_on_the_firewall_signature() -> None:
    good = run_checker("private-network", [failed("http://10.0.0.1/", "net::ERR_ADDRESS_UNREACHABLE"), failed("http://127.0.0.1:1/", "net::ERR_CONNECTION_REFUSED")])
    assert [row[0] for row in good] == ["PASS", "PASS"]
    bad = run_checker("private-network", [failed("http://10.0.0.1/", "net::ERR_FAILED")])
    assert bad[0][0] == "FAIL"
    assert "net::ERR_FAILED" in bad[0][2]
    assert run_checker("private-network", [])[0][0] == "FAIL"


def test_vm_check_fails_on_a_private_answer() -> None:
    events = [
        failed("http://10.0.0.1/", "net::ERR_ADDRESS_UNREACHABLE"),
        {"type": "response", "data": {"url": "http://169.254.169.254/", "status": 200, "peer_ip": None}},
    ]
    assert run_checker("private-network", events)[1][0] == "FAIL"


def test_vm_check_for_a_live_page() -> None:
    ok = [{"type": "navigation", "data": {"url": "https://x/", "status": 200, "redirected_from": None}}]
    assert run_checker("live-page", ok)[0][0] == "PASS"
    assert run_checker("live-page", [])[0][0] == "FAIL"


# ---- Report page in real Chromium, on loopback


@pytest.fixture
def browser() -> Iterator[Any]:
    sync_api = pytest.importorskip("playwright.sync_api")
    with sync_api.sync_playwright() as driver:
        try:
            instance = driver.chromium.launch()
        except sync_api.Error as exc:
            pytest.skip(f"Chromium is not available: {exc}")
        yield instance
        instance.close()


class Scripted:
    isolated = True

    def __init__(self, script: Any) -> None:
        self.script = script

    async def reap(self) -> int:
        return 0

    async def run(self, _: str, __: ScanTarget, emit: Any) -> None:
        await self.script(emit)


def report_page(browser: Any, base: str, scan_id: str) -> Any:
    context = browser.new_context()
    context.route("**/*", lambda route: route.continue_() if route.request.url.startswith(base) else route.abort())
    page = context.new_page()
    page.goto(f"{base}/r/{scan_id}")
    return page


def post_and_wait(client: httpx.Client, status: str = "final") -> str:
    scan_id = client.post("/api/scans", json={"fixture": "benign"}).json()["id"]
    if status == "final":
        for _ in range(500):
            if client.get(f"/api/scans/{scan_id}").json()["status"] not in ("queued", "running"):
                break
            time.sleep(0.01)
    return scan_id


def test_invisible_flood_cannot_freeze_the_report(browser: Any, tmp_path: Path) -> None:
    flood = ("a" + "​" * 1990) * 400

    async def script(emit: Any) -> None:
        concealed = [{"source": "hidden_css", "text": ("x" + "​" * 1990) * 1 + f"{i}", "selector": "s"} for i in range(400)]
        for index in range(10):
            await emit("text_layers", {"visible_text": flood[: 20_000] + str(index), "concealed": concealed}, "worker")
        await emit("worker_finished", {"status": "ok", "error": None}, "worker")

    settings = Settings(data_dir=tmp_path, read_rate_per_minute=100_000)
    with LoopbackServer(create_app(settings=settings, runner=Scripted(script))) as base, httpx.Client(base_url=base, timeout=30) as client:
        scan_id = post_and_wait(client)
        started = time.monotonic()
        page = report_page(browser, base, scan_id)
        page.locator("#blast-rows .row").first.wait_for(timeout=15_000)
        page.locator("#scan-state[data-state='ok']").wait_for(timeout=15_000)
        assert time.monotonic() - started < 15
        assert page.evaluate("document.querySelectorAll('*').length") < 60_000
        marker = page.locator(".concealed-text .ctrl").first.inner_text()
        assert marker == "U+200B x1990"
        page.context.close()


def test_tag_characters_are_revealed(browser: Any, tmp_path: Path) -> None:
    async def script(emit: Any) -> None:
        text = "Hello\U000E0041\U000E0042 world\U000E0100 x"
        await emit("text_layers", {"visible_text": text, "concealed": []}, "worker")
        await emit("worker_finished", {"status": "ok", "error": None}, "worker")

    with LoopbackServer(create_app(settings=Settings(data_dir=tmp_path), runner=Scripted(script))) as base, httpx.Client(base_url=base, timeout=30) as client:
        scan_id = post_and_wait(client)
        page = report_page(browser, base, scan_id)
        page.locator(".layer-visible .ctrl").first.wait_for(timeout=10_000)
        shown = page.locator(".layer-visible").inner_text()
        assert "U+E0041" in shown and "U+E0100" in shown
        assert "\U000E0041" not in shown
        page.context.close()


def test_wall_is_closed_only_after_the_host_reports_a_sandbox(browser: Any, tmp_path: Path) -> None:
    async def no_sandbox(emit: Any) -> None:
        await emit("scan_error", {"message": "The docker client could not be started."}, "host")

    async def sandbox(emit: Any) -> None:
        await emit("sandbox_created", {"name": "ld-x", "image": "i", "runtime": "runc", "policy": {}}, "host")
        await emit("worker_finished", {"status": "ok", "error": None}, "worker")

    for script, expected, directory in ((no_sandbox, "no", "a"), (sandbox, "yes", "b")):
        settings = Settings(data_dir=tmp_path / directory)
        with LoopbackServer(create_app(settings=settings, runner=Scripted(script))) as base, httpx.Client(base_url=base, timeout=30) as client:
            scan_id = post_and_wait(client)
            page = report_page(browser, base, scan_id)
            page.locator("#blast-rows .row").first.wait_for(timeout=10_000)
            assert page.locator("#chamber").get_attribute("data-walled") == expected
            page.context.close()


def test_a_refused_stream_falls_back_to_polling_without_announcing_the_end(browser: Any, tmp_path: Path) -> None:
    gate = threading.Event()

    async def script(emit: Any) -> None:
        await emit("worker_started", {"url": "u", "mode": "fixture", "offline": False}, "worker")
        while not gate.is_set():
            await asyncio.sleep(0.02)
        await emit("worker_finished", {"status": "ok", "error": None}, "worker")

    settings = Settings(data_dir=tmp_path, max_streams_per_client=1)
    with LoopbackServer(create_app(settings=settings, runner=Scripted(script))) as base, httpx.Client(base_url=base, timeout=30) as client:
        scan_id = post_and_wait(client, status="running")
        with client.stream("GET", f"/api/scans/{scan_id}/events") as held:
            assert held.status_code == 200
            page = report_page(browser, base, scan_id)
            page.locator("#stream-note:not([hidden])").wait_for(timeout=10_000)
            assert "every few seconds" in page.locator("#stream-note").inner_text()
            assert "finished" not in page.locator("#live-announcer").inner_text().lower()
            gate.set()
            page.locator("#scan-state[data-state='ok']").wait_for(timeout=15_000)
            page.wait_for_function("document.getElementById('live-announcer').textContent.includes('finished')", timeout=5_000)
            page.context.close()
