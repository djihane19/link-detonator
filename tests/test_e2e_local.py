"""Whole-system paths over real HTTP on loopback.

Part one runs the real worker and real Chromium through LocalFixtureRunner, offline. Part
two runs the DockerRunner path against tests/fake_docker.py: it proves what the app does
given a docker client's behaviour, and proves nothing about Docker, the firewall or
isolation themselves. No test here loads anything outside 127.0.0.1.
"""

from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import pytest
from loopback_server import LoopbackServer

from app.config import Settings
from app.main import FIXTURE_CATALOG, create_app
from app.models import FIXTURE_NAMES
from app.sandbox import DockerRunner, LocalFixtureRunner

JPEG_MAGIC = b"\xff\xd8\xff"
SCAN_TIMEOUT_S = 90.0
ISOLATION_EVENTS = {"sandbox_created", "secret_audit", "sandbox_exit", "sandbox_removed"}
SECRET_VALUE = "e2e-secret-value-not-real"


@dataclass
class SseRead:
    status_code: int
    events: list[dict[str, Any]] = field(default_factory=list)
    ids: list[str] = field(default_factory=list)
    rows: list[dict[str, Any]] | None = None


def read_sse(
    client: httpx.Client, scan_id: str, last_event_id: str | None = None, stop_after: int | None = None
) -> SseRead:
    headers = {} if last_event_id is None else {"Last-Event-ID": last_event_id}
    url = f"/api/scans/{scan_id}/events"
    with client.stream("GET", url, headers=headers, timeout=SCAN_TIMEOUT_S) as response:
        read = SseRead(response.status_code)
        if response.status_code != 200:
            return read
        event_name = None
        for line in response.iter_lines():
            if line.startswith("event: "):
                event_name = line.removeprefix("event: ")
            elif line.startswith("id: "):
                read.ids.append(line.removeprefix("id: "))
            elif line.startswith("data: "):
                payload = json.loads(line.removeprefix("data: "))
                if event_name == "blast_radius":
                    read.rows = payload["rows"]
                else:
                    read.events.append(payload)
            elif not line:
                event_name = None
                if stop_after is not None and len(read.events) >= stop_after:
                    break
    return read


def post_fixture(client: httpx.Client, fixture: str) -> str:
    response = client.post("/api/scans", json={"fixture": fixture})
    assert response.status_code == 202, response.text
    return response.json()["id"]


def rows_by_id(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {row["id"]: row for row in rows}


def of_type(events: list[dict[str, Any]], event_type: str) -> list[dict[str, Any]]:
    return [event for event in events if event["type"] == event_type]


def read_log(data_dir: Path, scan_id: str) -> list[dict[str, Any]]:
    path = data_dir / "scans" / scan_id / "events.ndjson"
    return [json.loads(line) for line in path.read_text().splitlines()]


def assert_screenshot_served(client: httpx.Client, image_url: str) -> bytes:
    response = client.get(image_url)
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/jpeg"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.content.startswith(JPEG_MAGIC)
    return response.content


def assert_report_page(base: str, scan_id: str, expect_dev_banner: bool) -> dict[str, str]:
    """Loads the report in real Chromium and returns what each row displays."""
    sync_api = pytest.importorskip("playwright.sync_api")
    problems: list[str] = []
    with sync_api.sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        context = browser.new_context()
        context.route(
            "**/*",
            lambda route: route.continue_() if route.request.url.startswith(base) else route.abort(),
        )
        page = context.new_page()
        page.on("pageerror", lambda error: problems.append(str(error)))
        page.on(
            "console",
            lambda message: problems.append(message.text) if message.type == "error" else None,
        )
        page.goto(f"{base}/r/{scan_id}")
        page.locator("#blast-rows .row").first.wait_for()
        assert page.locator(".dev-banner").is_visible() is expect_dev_banner
        assert "no ai verdict" in page.locator("#verdict-title").inner_text().lower()
        displayed = page.locator("#blast-rows .row").evaluate_all(
            "(rows) => rows.map((row) => [row.dataset.row, row.dataset.status])"
        )
        browser.close()
    assert problems == []
    return dict(displayed)


# ---- Real worker and real Chromium, offline, through LocalFixtureRunner


@dataclass
class GauntletRun:
    base: str
    client: httpx.Client
    scan_id: str
    data_dir: Path
    settings: Settings
    status_when_disconnected: str
    first: SseRead
    second: SseRead
    snapshot: dict[str, Any]

    @property
    def events(self) -> list[dict[str, Any]]:
        return self.snapshot["events"]

    @property
    def rows(self) -> dict[str, dict[str, Any]]:
        return rows_by_id(self.snapshot["blast_radius"])


@pytest.fixture(scope="module")
def gauntlet(tmp_path_factory: pytest.TempPathFactory) -> Iterator[GauntletRun]:
    data_dir = tmp_path_factory.mktemp("e2e-local")
    settings = Settings(
        dev_local_runner=True,
        bind_host="127.0.0.1",
        data_dir=data_dir,
        python_bin=sys.executable,
    )
    app = create_app(settings=settings, runner=LocalFixtureRunner(settings))
    with LoopbackServer(app) as base, httpx.Client(base_url=base, timeout=30) as client:
        scan_id = post_fixture(client, "hostile-gauntlet")
        # Dropped mid-scan on purpose, so the resume below is a real one and not a replay.
        first = read_sse(client, scan_id, stop_after=2)
        status = client.get(f"/api/scans/{scan_id}").json()["status"]
        second = read_sse(client, scan_id, last_event_id=first.ids[-1])
        snapshot = client.get(f"/api/scans/{scan_id}").json()
        yield GauntletRun(base, client, scan_id, data_dir, settings, status, first, second, snapshot)


def test_gauntlet_produces_real_evidence(gauntlet: GauntletRun) -> None:
    assert gauntlet.snapshot["runner"] == "dev"
    assert gauntlet.snapshot["target"] == {"kind": "fixture", "value": "hostile-gauntlet"}
    assert gauntlet.snapshot["status"] in {"ok", "partial"}

    started = of_type(gauntlet.events, "worker_started")[0]["data"]
    assert started["offline"] is True
    assert started["mode"] == "fixture"

    for expected in ("navigation", "screenshot", "request", "request_failed", "form", "text_layers"):
        assert of_type(gauntlet.events, expected), f"no {expected} event"
    layers = of_type(gauntlet.events, "text_layers")[-1]["data"]
    assert layers["concealed"], "the gauntlet hides text, so some must be extracted"
    finished = of_type(gauntlet.events, "worker_finished")
    assert len(finished) == 1
    assert finished[0]["source"] == "worker"


def test_sse_resumed_mid_scan_delivers_every_event_once(gauntlet: GauntletRun) -> None:
    assert gauntlet.status_when_disconnected == "running"
    streamed = gauntlet.first.events + gauntlet.second.events
    assert [event["seq"] for event in streamed] == list(range(1, len(streamed) + 1))
    assert streamed == gauntlet.events
    assert [int(value) for value in gauntlet.first.ids + gauntlet.second.ids] == [
        event["seq"] for event in streamed
    ]
    assert streamed[-1]["type"] == "scan_finished"
    assert streamed[-1]["source"] == "host"
    assert streamed[-1]["data"]["status"] == gauntlet.snapshot["status"]


def test_events_are_persisted_without_image_data(gauntlet: GauntletRun) -> None:
    persisted = read_log(gauntlet.data_dir, gauntlet.scan_id)
    assert persisted == gauntlet.events
    meta = json.loads((gauntlet.data_dir / "scans" / gauntlet.scan_id / "meta.json").read_text())
    assert meta["status"] == gauntlet.snapshot["status"]
    assert meta["runner"] == "dev"
    for event in [*persisted, *gauntlet.first.events, *gauntlet.second.events]:
        assert "b64" not in event["data"]


def test_screenshots_are_served_from_disk(gauntlet: GauntletRun) -> None:
    shots = of_type(gauntlet.events, "screenshot")
    assert shots
    stored = [shot for shot in shots if shot["data"]["image_url"]]
    assert stored
    for shot in stored:
        content = assert_screenshot_served(gauntlet.client, shot["data"]["image_url"])
        on_disk = gauntlet.data_dir / "scans" / gauntlet.scan_id / f"{shot['seq']}.jpg"
        assert on_disk.read_bytes() == content


def test_local_mode_never_claims_containment(gauntlet: GauntletRun) -> None:
    rows = gauntlet.rows
    assert list(rows) == [
        "downloads", "private_network", "freeze", "memory",
        "concealed_text", "secrets", "limits", "destroyed",
    ]  # fmt: skip
    assert {row["status"] for row in rows.values()}.isdisjoint({"contained", "clear"})

    private = rows["private_network"]
    assert private["status"] == "not_applicable"
    assert "firewall" in private["detail"].lower()
    assert private["evidence_seqs"]
    assert any(
        event["data"].get("blocked_locally") is True
        for event in gauntlet.events
        if event["seq"] in private["evidence_seqs"] and event["type"] == "request_failed"
    )

    assert rows["concealed_text"]["status"] == "observed"
    assert rows["secrets"]["status"] == "not_observed"
    assert rows["destroyed"]["status"] == "not_observed"

    host_types = {event["type"] for event in gauntlet.events if event["source"] == "host"}
    assert host_types.isdisjoint(ISOLATION_EVENTS)
    assert gauntlet.second.rows == gauntlet.snapshot["blast_radius"]


def test_verdict_stays_pending(gauntlet: GauntletRun) -> None:
    assert gauntlet.snapshot["verdict"] == {"status": "pending"}
    verdicts = of_type(gauntlet.events, "verdict")
    assert len(verdicts) == 1
    assert verdicts[0]["source"] == "host"
    assert verdicts[0]["data"] == {"status": "pending"}


def test_replay_honours_last_event_id(gauntlet: GauntletRun) -> None:
    middle = len(gauntlet.events) // 2
    replay = read_sse(gauntlet.client, gauntlet.scan_id, last_event_id=str(middle))
    assert replay.status_code == 200
    assert replay.events == gauntlet.events[middle:]
    assert replay.rows == gauntlet.snapshot["blast_radius"]

    malformed = read_sse(gauntlet.client, gauntlet.scan_id, last_event_id="not-a-number")
    assert malformed.events == gauntlet.events

    last = str(gauntlet.events[-1]["seq"])
    assert read_sse(gauntlet.client, gauntlet.scan_id, last_event_id=last).status_code == 204


def test_report_page_tells_the_same_story(gauntlet: GauntletRun) -> None:
    displayed = assert_report_page(gauntlet.base, gauntlet.scan_id, expect_dev_banner=True)
    assert displayed == {row["id"]: row["status"] for row in gauntlet.snapshot["blast_radius"]}


def test_dev_runner_refuses_live_urls_and_reports_itself(gauntlet: GauntletRun) -> None:
    before = gauntlet.client.get("/healthz").json()
    assert before["runner"] == "dev"
    response = gauntlet.client.post("/api/scans", json={"url": "https://example.com/"})
    assert response.status_code == 400
    assert "not sandboxed" in response.json()["detail"]
    assert gauntlet.client.get("/api/fixtures").json()["dev_runner"] is True


def test_finished_scan_survives_a_restart(gauntlet: GauntletRun) -> None:
    app = create_app(settings=gauntlet.settings, runner=LocalFixtureRunner(gauntlet.settings))
    with LoopbackServer(app) as base, httpx.Client(base_url=base, timeout=30) as client:
        assert client.get(f"/api/scans/{gauntlet.scan_id}").json() == gauntlet.snapshot


def test_every_fixture_is_known_to_the_catalog_and_the_worker() -> None:
    fixtures = Path(Settings().worker_path).parent / "fixtures"
    assert set(FIXTURE_CATALOG) == set(FIXTURE_NAMES)
    assert {path.stem for path in fixtures.glob("*.html")} == set(FIXTURE_NAMES)


def test_dev_runner_refuses_a_connection_that_arrived_off_loopback(tmp_path: Path) -> None:
    settings = Settings(dev_local_runner=True, data_dir=tmp_path)
    app = create_app(settings=settings, runner=LocalFixtureRunner(settings))

    async def post_via(address: str) -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url=f"http://{address}") as client:
            return await client.post("/api/scans", json={"url": "https://example.com/"})

    assert asyncio.run(post_via("192.0.2.10")).status_code == 403
    assert asyncio.run(post_via("127.0.0.1")).status_code == 400


# ---- DockerRunner against the stub CLI. Proves the app's reaction only, not Docker.


@dataclass
class DockerRun:
    base: str
    client: httpx.Client
    scan_id: str
    stream: SseRead
    snapshot: dict[str, Any]

    @property
    def events(self) -> list[dict[str, Any]]:
        return self.snapshot["events"]

    @property
    def rows(self) -> dict[str, dict[str, Any]]:
        return rows_by_id(self.snapshot["blast_radius"])


@pytest.fixture
def docker_scan(fake_docker: Any, tmp_path: Path) -> Iterator[Any]:
    data_dir = tmp_path / "data"
    open_contexts: list[tuple[LoopbackServer, httpx.Client]] = []

    def scan(fixture: str = "benign", settings: dict[str, Any] | None = None, **config: Any) -> DockerRun:
        fake_docker.configure(**config)
        active = fake_docker.settings(data_dir=data_dir, **(settings or {}))
        server = LoopbackServer(create_app(settings=active, runner=DockerRunner(active)))
        base = server.__enter__()
        client = httpx.Client(base_url=base, timeout=30)
        open_contexts.append((server, client))
        scan_id = post_fixture(client, fixture)
        stream = read_sse(client, scan_id)
        snapshot = client.get(f"/api/scans/{scan_id}").json()
        return DockerRun(base, client, scan_id, stream, snapshot)

    yield scan
    for server, client in open_contexts:
        client.close()
        server.__exit__()


def test_docker_path_full_lifecycle(docker_scan: Any, fake_docker: Any, tmp_path: Path) -> None:
    run = docker_scan(fixture="hostile-gauntlet")

    assert run.snapshot["runner"] == "sandbox"
    assert run.snapshot["status"] == "ok"
    assert [event["type"] for event in run.events] == [
        "sandbox_created", "secret_audit",
        "worker_started", "navigation", "request", "screenshot", "text_layers", "worker_finished",
        "sandbox_exit", "sandbox_removed", "verdict", "scan_finished",
    ]  # fmt: skip
    assert run.stream.events == run.events
    assert read_log(tmp_path / "data", run.scan_id) == run.events
    assert run.client.get("/healthz").json()["runner"] == "sandbox"

    for event in run.events:
        expected = "worker" if event["type"].startswith(("worker_", "navigation", "request", "screenshot", "text_")) else "host"
        assert event["source"] == expected, event["type"]

    # The app really drove the stub: real flags in, no offline shortcut, container gone.
    argv = fake_docker.call_for("run")["argv"]
    assert argv[argv.index("--network") + 1] == "ld-sandbox"
    assert "--offline" not in argv
    assert not {"-e", "--env", "--env-file", "-v", "--volume", "--mount", "--privileged"} & set(argv)
    assert argv[-4:-2] == ["--fixture", "hostile-gauntlet"]
    assert not fake_docker.container_exists(f"ld-{run.scan_id}")

    shot = of_type(run.events, "screenshot")[0]
    assert_screenshot_served(run.client, shot["data"]["image_url"])

    assert run.snapshot["verdict"] == {"status": "pending"}
    assert run.rows["destroyed"]["status"] == "contained"
    assert run.rows["private_network"]["status"] == "not_observed"
    # No secret was configured here, so nothing was compared and "clear" would overclaim.
    # No secret is configured, but the planted canary means the audit still did real work.
    assert run.rows["secrets"]["status"] == "clear"
    assert run.rows["limits"]["status"] == "clear"

    middle = len(run.events) // 2
    replay = read_sse(run.client, run.scan_id, last_event_id=str(middle))
    assert replay.events == run.events[middle:]
    last = str(run.events[-1]["seq"])
    assert read_sse(run.client, run.scan_id, last_event_id=last).status_code == 204

    displayed = assert_report_page(run.base, run.scan_id, expect_dev_banner=False)
    assert displayed == {row["id"]: row["status"] for row in run.snapshot["blast_radius"]}


@pytest.mark.parametrize(
    ("scenario", "expected"),
    [
        ("private_blocked", "contained"),
        ("private_local_abort", "not_applicable"),
        ("private_reached", "failed"),
    ],
)
def test_docker_path_private_network_row(docker_scan: Any, scenario: str, expected: str) -> None:
    run = docker_scan(scenario=scenario)
    assert run.rows["private_network"]["status"] == expected


def test_docker_path_removal_failure_is_reported(docker_scan: Any) -> None:
    run = docker_scan(rm_fails=True)
    assert run.rows["destroyed"]["status"] == "failed"
    assert of_type(run.events, "sandbox_removed")[0]["data"]["verified"] is False
    # The worker said ok, and the host fact outranks it.
    assert of_type(run.events, "worker_finished")[0]["data"]["status"] == "ok"
    assert run.snapshot["status"] == "partial"


def test_docker_path_secret_leak_stops_the_scan(
    docker_scan: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("VULTR_API_KEY", SECRET_VALUE)
    run = docker_scan(
        settings={"secret_env_names": ("VULTR_API_KEY",)},
        env=["PATH=/usr/bin", f"LEAK={SECRET_VALUE}"],
    )
    assert run.rows["secrets"]["status"] == "failed"
    assert run.snapshot["status"] == "error"
    assert [event for event in run.events if event["source"] == "worker"] == []
    assert SECRET_VALUE not in json.dumps(run.snapshot)
    assert SECRET_VALUE not in (tmp_path / "data" / "scans" / run.scan_id / "events.ndjson").read_text()


def test_docker_path_clean_secret_audit_is_clear(
    docker_scan: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("VULTR_API_KEY", SECRET_VALUE)
    run = docker_scan(settings={"secret_env_names": ("VULTR_API_KEY",)})
    assert of_type(run.events, "secret_audit")[0]["data"] == {"ok": True, "checked_count": 2, "canary": True}
    assert run.rows["secrets"]["status"] == "clear"


def test_docker_path_worker_cannot_assert_host_facts(docker_scan: Any) -> None:
    run = docker_scan(scenario="spoofed")
    assert len(of_type(run.events, "scan_finished")) == 1
    assert run.snapshot["verdict"] == {"status": "pending"}
    for event_type in ("sandbox_created", "secret_audit", "sandbox_exit", "sandbox_removed", "scan_finished", "verdict"):
        assert {event["source"] for event in of_type(run.events, event_type)} == {"host"}
    assert of_type(run.events, "sandbox_created")[0]["data"]["name"] == f"ld-{run.scan_id}"
    assert [event["seq"] for event in run.events] == list(range(1, len(run.events) + 1))


def test_docker_path_deadline_kill(docker_scan: Any) -> None:
    run = docker_scan(scenario="hang", settings={"deadline_s": 4.0})
    assert of_type(run.events, "deadline_killed")[0]["source"] == "host"
    assert run.rows["limits"]["status"] == "contained"
    assert run.rows["freeze"]["status"] == "contained"
    assert run.rows["destroyed"]["status"] == "contained"
    assert run.snapshot["status"] == "partial"
