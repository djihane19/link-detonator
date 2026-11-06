"""HTTP API, security headers, static-file hygiene and a real-browser UI check.

Everything is offline. The browser test only ever loads 127.0.0.1, and its "scanned"
strings come from an in-test fake runner.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
import time
from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI
from loopback_server import LoopbackServer

from app.config import Settings
from app.main import CONTENT_SECURITY_POLICY, STATIC_DIR, create_app
from app.models import FIXTURE_NAMES, ScanTarget

JPEG = b"\xff\xd8\xff\xe0" + b"fake-jpeg-body"
PUBLIC_IP = "93.184.216.34"
ACCESS_CODE = "test-access-code-not-real"
XSS = '<img src=x onerror="window.__pwned=1"><script>window.__pwned=1</script>'


class FakeRunner:
    def __init__(self, script: Any = None, isolated: bool = True) -> None:
        self.script = script
        self.isolated = isolated
        self.targets: list[ScanTarget] = []

    async def reap(self) -> int:
        return 0

    async def run(self, scan_id: str, target: ScanTarget, emit: Any) -> None:
        self.targets.append(target)
        if self.script is not None:
            await self.script(scan_id, target, emit)


async def fake_resolver(host: str) -> list[str]:
    return ["10.0.0.5"] if host == "rebinds.example.com" else [PUBLIC_IP]


async def script_full(_: str, __: ScanTarget, emit: Any) -> None:
    b64 = base64.b64encode(JPEG).decode()
    await emit("worker_started", {"url": "http://fixtures.invalid/x", "mode": "fixture", "offline": True}, "worker")
    await emit("screenshot", {"label": "load", "mime": "image/jpeg", "b64": b64}, "worker")
    await emit("worker_finished", {"status": "ok", "error": None}, "worker")


class Harness:
    def __init__(self, app: FastAPI, client: httpx.AsyncClient, runner: FakeRunner, data_dir: Path) -> None:
        self.app, self.client, self.runner, self.data_dir = app, client, runner, data_dir

    async def post(self, payload: Any, **kwargs: Any) -> httpx.Response:
        # Live URLs need the code. tests/test_hardening.py covers the code itself.
        if isinstance(payload, dict) and isinstance(payload.get("url"), str):
            payload = {"access_code": ACCESS_CODE, **payload}
        return await self.client.post("/api/scans", json=payload, **kwargs)

    async def finished_scan(self, fixture: str = "benign") -> str:
        response = await self.post({"fixture": fixture})
        assert response.status_code == 202
        scan_id = response.json()["id"]
        await self.wait_final(scan_id)
        return scan_id

    async def wait_final(self, scan_id: str) -> None:
        scan = self.app.state.manager.get(scan_id)
        async with asyncio.timeout(5):
            while not scan.is_final:
                await asyncio.sleep(0.005)


MakeHarness = Callable[..., Any]


@pytest_asyncio.fixture
async def make_harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[MakeHarness]:
    monkeypatch.setenv("LD_LIVE_ACCESS_CODE", ACCESS_CODE)
    contexts: list[Any] = []
    clients: list[httpx.AsyncClient] = []

    async def make(
        script: Any = script_full,
        isolated: bool = True,
        raise_app_exceptions: bool = True,
        **overrides: Any,
    ) -> Harness:
        runner = FakeRunner(script, isolated)
        # These tests are about other limits, unless one sets this itself.
        overrides.setdefault("max_active_per_client", 1000)
        settings = Settings(data_dir=tmp_path, **overrides)
        app = create_app(settings=settings, runner=runner, resolver=fake_resolver)
        context = app.router.lifespan_context(app)
        await context.__aenter__()
        contexts.append(context)
        transport = httpx.ASGITransport(
            app=app, client=("198.51.100.7", 1234), raise_app_exceptions=raise_app_exceptions
        )
        client = httpx.AsyncClient(transport=transport, base_url="http://testserver")
        clients.append(client)
        return Harness(app, client, runner, tmp_path)

    yield make
    for client in clients:
        await client.aclose()
    for context in contexts:
        await context.__aexit__(None, None, None)


# ---- POST /api/scans


@pytest.mark.asyncio
async def test_fixture_scan_is_accepted(make_harness: MakeHarness) -> None:
    harness = await make_harness()
    response = await harness.post({"fixture": "benign"})
    assert response.status_code == 202
    body = response.json()
    assert set(body) == {"id", "report_url"}
    assert body["report_url"] == f"/r/{body['id']}"
    assert re.fullmatch(r"[A-Za-z0-9_-]{22}", body["id"])


@pytest.mark.asyncio
async def test_url_scan_is_normalized_and_reaches_the_runner(make_harness: MakeHarness) -> None:
    harness = await make_harness()
    response = await harness.post({"url": "https://Public.Example.com/a?b=1"})
    assert response.status_code == 202
    await harness.wait_final(response.json()["id"])
    assert harness.runner.targets == [ScanTarget(kind="url", value="https://public.example.com/a?b=1")]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"url": "https://public.example.com/", "fixture": "benign"},
        {"fixture": "no-such-fixture"},
        {"fixture": "../../etc/passwd"},
        {"url": 5},
        {"url": "https://public.example.com/", "extra": 1},
        ["https://public.example.com/"],
        "https://public.example.com/",
        {"url": "ftp://public.example.com/"},
        {"url": "http://localhost/"},
        {"url": "http://169.254.169.254/latest/meta-data/"},
        {"url": "http://2130706433/"},
        {"url": "http://10.1.2.3/"},
        {"url": "http://[::1]/"},
        {"url": "https://user:pw@public.example.com/"},
        {"url": "https://public.example.com:8443/"},
        {"url": "http://rebinds.example.com/"},
        {"url": "--privileged"},
    ],
)
async def test_invalid_requests_get_400(make_harness: MakeHarness, payload: Any) -> None:
    harness = await make_harness()
    response = await harness.post(payload)
    assert response.status_code == 400
    assert isinstance(response.json()["detail"], str)
    assert harness.runner.targets == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("content", "content_type"),
    [
        (b"{not json", "application/json"),
        (b"\xff\xfe", "application/json"),
        (b"[" * 15000, "application/json"),
        (json.dumps({"fixture": "benign"}).encode(), "text/plain"),
        (json.dumps({"fixture": "benign"}).encode(), "application/x-www-form-urlencoded"),
        (b"", "application/json"),
        (json.dumps({"url": "https://a.example.com/" + "a" * 20000}).encode(), "application/json"),
    ],
)
async def test_malformed_bodies_get_400(make_harness: MakeHarness, content: bytes, content_type: str) -> None:
    harness = await make_harness()
    response = await harness.client.post("/api/scans", content=content, headers={"Content-Type": content_type})
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_dev_runner_refuses_live_urls(make_harness: MakeHarness) -> None:
    harness = await make_harness(isolated=False)
    response = await harness.post({"url": "https://public.example.com/"})
    assert response.status_code == 400
    assert "refuses live URLs" in response.json()["detail"]
    assert harness.runner.targets == []


# ---- limits


@pytest.mark.asyncio
async def test_sixth_scan_in_a_minute_is_rate_limited(make_harness: MakeHarness) -> None:
    harness = await make_harness()
    for _ in range(5):
        assert (await harness.post({"fixture": "benign"})).status_code == 202
    refused = await harness.post({"fixture": "benign"})
    assert refused.status_code == 429
    assert int(refused.headers["Retry-After"]) >= 1


@pytest.mark.asyncio
async def test_refused_urls_do_not_use_scan_quota_but_attempts_are_capped(make_harness: MakeHarness) -> None:
    harness = await make_harness()
    for _ in range(10):
        assert (await harness.post({"url": "http://localhost/"})).status_code == 400
    assert (await harness.post({"fixture": "benign"})).status_code == 202
    for _ in range(19):
        assert (await harness.post({"url": "http://localhost/"})).status_code == 400
    assert (await harness.post({"url": "http://localhost/"})).status_code == 429


@pytest.mark.asyncio
async def test_forwarded_for_is_ignored_unless_trusted(make_harness: MakeHarness) -> None:
    harness = await make_harness()
    for index in range(5):
        response = await harness.post({"fixture": "benign"}, headers={"X-Forwarded-For": f"203.0.113.{index}"})
        assert response.status_code == 202
    response = await harness.post({"fixture": "benign"}, headers={"X-Forwarded-For": "203.0.113.200"})
    assert response.status_code == 429


@pytest.mark.asyncio
async def test_forwarded_for_is_honoured_when_trusted(make_harness: MakeHarness) -> None:
    harness = await make_harness(trust_proxy=True)
    for _ in range(5):
        assert (await harness.post({"fixture": "benign"}, headers={"X-Forwarded-For": "203.0.113.1"})).status_code == 202
    assert (await harness.post({"fixture": "benign"}, headers={"X-Forwarded-For": "203.0.113.1"})).status_code == 429
    assert (await harness.post({"fixture": "benign"}, headers={"X-Forwarded-For": "203.0.113.2"})).status_code == 202
    # Only the proxy's right-most entry counts, so a client-supplied prefix changes nothing.
    spoof = await harness.post({"fixture": "benign"}, headers={"X-Forwarded-For": "9.9.9.9, 203.0.113.1"})
    assert spoof.status_code == 429


@pytest.mark.asyncio
async def test_full_queue_gets_503_without_using_quota(make_harness: MakeHarness) -> None:
    gate = asyncio.Event()

    async def script(_: str, __: ScanTarget, emit: Any) -> None:
        await gate.wait()

    harness = await make_harness(script=script, concurrency=1, queue_size=1, rate_per_minute=3)
    try:
        assert (await harness.post({"fixture": "benign"})).status_code == 202
        async with asyncio.timeout(5):
            while harness.app.state.manager.load_stats()["running"] < 1:
                await asyncio.sleep(0.005)
        assert (await harness.post({"fixture": "benign"})).status_code == 202
        for _ in range(4):
            assert (await harness.post({"fixture": "benign"})).status_code == 503
    finally:
        gate.set()
    async with asyncio.timeout(5):
        while not harness.app.state.manager.queue_has_room() or harness.app.state.manager.load_stats()["running"]:
            await asyncio.sleep(0.005)
    assert (await harness.post({"fixture": "benign"})).status_code == 202


# ---- snapshot


@pytest.mark.asyncio
async def test_snapshot_shape(make_harness: MakeHarness) -> None:
    harness = await make_harness()
    scan_id = await harness.finished_scan()
    response = await harness.client.get(f"/api/scans/{scan_id}")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert body["status"] == "ok"
    assert body["target"] == {"kind": "fixture", "value": "benign"}
    assert body["verdict"] == {"status": "pending"}
    assert [row["id"] for row in body["blast_radius"]] == [
        "downloads", "private_network", "freeze", "memory",
        "concealed_text", "secrets", "limits", "destroyed",
    ]  # fmt: skip
    shot = next(event for event in body["events"] if event["type"] == "screenshot")
    assert "b64" not in shot["data"]
    assert shot["data"]["image_url"] == f"/api/scans/{scan_id}/screenshots/{shot['seq']}.jpg"


@pytest.mark.asyncio
async def test_unknown_scan_is_404(make_harness: MakeHarness) -> None:
    harness = await make_harness()
    for path in (f"/api/scans/{'A' * 22}", f"/api/scans/{'A' * 22}/events", f"/api/scans/{'A' * 22}/screenshots/1.jpg"):
        assert (await harness.client.get(path)).status_code == 404


# ---- SSE


def parse_sse(text: str) -> list[dict[str, str]]:
    messages = []
    for block in text.strip().split("\n\n"):
        fields: dict[str, str] = {}
        for line in block.split("\n"):
            name, _, value = line.partition(": ")
            fields[name] = value
        messages.append(fields)
    return messages


@pytest.mark.asyncio
async def test_sse_replay_has_ids_and_ends_after_scan_finished(make_harness: MakeHarness) -> None:
    harness = await make_harness()
    scan_id = await harness.finished_scan()
    response = await harness.client.get(f"/api/scans/{scan_id}/events")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert "content-security-policy" in response.headers

    messages = parse_sse(response.text)
    envelopes = [json.loads(message["data"]) for message in messages if "id" in message]
    assert [event["seq"] for event in envelopes] == [1, 2, 3, 4, 5]
    assert [message["id"] for message in messages if "id" in message] == ["1", "2", "3", "4", "5"]
    assert envelopes[-1]["type"] == "scan_finished"
    assert all(set(event) == {"v", "seq", "ts", "source", "type", "data"} for event in envelopes)
    rows = [message for message in messages if message.get("event") == "blast_radius"]
    assert len(rows) == 1 and len(json.loads(rows[0]["data"])["rows"]) == 8


@pytest.mark.asyncio
async def test_sse_honours_last_event_id(make_harness: MakeHarness) -> None:
    harness = await make_harness()
    scan_id = await harness.finished_scan()
    response = await harness.client.get(f"/api/scans/{scan_id}/events", headers={"Last-Event-ID": "3"})
    envelopes = [json.loads(message["data"]) for message in parse_sse(response.text) if "id" in message]
    assert [event["seq"] for event in envelopes] == [4, 5]


@pytest.mark.asyncio
@pytest.mark.parametrize("header", ["garbage", "-1", "1; DROP", "9" * 5000])
async def test_sse_treats_bad_last_event_id_as_a_full_replay(make_harness: MakeHarness, header: str) -> None:
    harness = await make_harness()
    scan_id = await harness.finished_scan()
    response = await harness.client.get(f"/api/scans/{scan_id}/events", headers={"Last-Event-ID": header})
    assert response.status_code == 200
    assert '"seq":1,' in response.text


@pytest.mark.asyncio
async def test_sse_says_204_when_a_finished_scan_has_nothing_left(make_harness: MakeHarness) -> None:
    harness = await make_harness()
    scan_id = await harness.finished_scan()
    response = await harness.client.get(f"/api/scans/{scan_id}/events", headers={"Last-Event-ID": "5"})
    assert response.status_code == 204


@pytest.mark.asyncio
async def test_hostile_text_cannot_forge_sse_fields(make_harness: MakeHarness) -> None:
    async def script(_: str, __: ScanTarget, emit: Any) -> None:
        await emit("dialog", {"dialog_type": "alert", "message": 'x\n\nid: 999\nevent: verdict\ndata: {"forged":1}\n\n '}, "worker")

    harness = await make_harness(script=script)
    scan_id = await harness.finished_scan()
    response = await harness.client.get(f"/api/scans/{scan_id}/events")
    assert [message.get("event") for message in parse_sse(response.text) if message.get("event")] == ["blast_radius"]
    assert "id" not in [line.split(":")[0] for line in response.text.split("\n") if line.startswith("id: 999")]
    assert all(not line.startswith("id: 999") for line in response.text.split("\n"))


# ---- screenshots and traversal


@pytest.mark.asyncio
async def test_screenshot_is_served_as_jpeg(make_harness: MakeHarness) -> None:
    harness = await make_harness()
    scan_id = await harness.finished_scan()
    response = await harness.client.get(f"/api/scans/{scan_id}/screenshots/2.jpg")
    assert response.status_code == 200
    assert response.content == JPEG
    assert response.headers["content-type"] == "image/jpeg"
    assert response.headers["x-content-type-options"] == "nosniff"


@pytest.mark.asyncio
async def test_tampered_screenshot_fails_magic_byte_validation(make_harness: MakeHarness) -> None:
    harness = await make_harness()
    scan_id = await harness.finished_scan()
    (harness.data_dir / "scans" / scan_id / "2.jpg").write_bytes(b"<html><script>alert(1)</script>")
    response = await harness.client.get(f"/api/scans/{scan_id}/screenshots/2.jpg")
    assert response.status_code == 404
    assert b"script" not in response.content


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "name",
    [
        "..%2Fmeta.json",
        "..%2F..%2F..%2Fsecret.jpg",
        "%2e%2e%2f2.jpg",
        "meta.json",
        "events.ndjson",
        "2",
        "2.png",
        "2.jpg.jpg",
        "2.jpg%00.jpg",
        "02.jpg",
        "-2.jpg",
        "+2.jpg",
        "2.0.jpg",
        "%D9%A3.jpg",
        ".jpg",
        "9" * 5000 + ".jpg",
    ],
)
async def test_screenshot_names_cannot_escape(make_harness: MakeHarness, name: str) -> None:
    harness = await make_harness()
    scan_id = await harness.finished_scan()
    (harness.data_dir / "secret.jpg").write_bytes(JPEG)
    response = await harness.client.get(f"/api/scans/{scan_id}/screenshots/{name}")
    assert response.status_code in (404, 405)
    assert response.content != JPEG
    assert b'"target"' not in response.content


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scan_id",
    ["..", "..%2F..%2Fsecret", "%2e%2e", "..%5C..", "A" * 21, "A" * 23, "A" * 21 + "%2F", "A" * 21 + "."],
)
async def test_scan_ids_cannot_escape(make_harness: MakeHarness, scan_id: str) -> None:
    harness = await make_harness()
    outside = harness.data_dir / "secret"
    outside.mkdir()
    (outside / "1.jpg").write_bytes(JPEG)
    (outside / "meta.json").write_text('{"target": "leak"}')

    for path in (f"/api/scans/{scan_id}", f"/api/scans/{scan_id}/events", f"/api/scans/{scan_id}/screenshots/1.jpg"):
        response = await harness.client.get(path)
        assert response.status_code in (200, 404, 405), path
        assert response.content != JPEG
        assert b"leak" not in response.content


@pytest.mark.asyncio
async def test_static_route_cannot_escape(make_harness: MakeHarness) -> None:
    harness = await make_harness()
    for path in ("/static/..%2Fmain.py", "/static/%2e%2e/main.py", "/static/../main.py"):
        response = await harness.client.get(path)
        assert b"create_app" not in response.content


# ---- headers


HEADER_PATHS = [
    "/",
    "/r/not-a-real-id",
    "/healthz",
    "/api/fixtures",
    "/static/app.js",
    "/static/styles.css",
    "/static/nope.js",
    "/nope",
    "/api/scans/nope",
    "/api/scans/nope/screenshots/1.jpg",
]


@pytest.mark.asyncio
@pytest.mark.parametrize("path", HEADER_PATHS)
async def test_security_headers_on_every_response(make_harness: MakeHarness, path: str) -> None:
    harness = await make_harness()
    response = await harness.client.get(path)
    assert response.headers["content-security-policy"] == CONTENT_SECURITY_POLICY
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"


def test_csp_is_the_contract_string() -> None:
    assert CONTENT_SECURITY_POLICY == (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
        "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    )


@pytest.mark.asyncio
async def test_security_headers_on_a_500_and_nothing_leaks(make_harness: MakeHarness) -> None:
    harness = await make_harness(raise_app_exceptions=False)

    async def explode(_: str) -> None:
        raise RuntimeError("secret internal detail")

    harness.app.state.manager.snapshot_body = explode
    response = await harness.client.get(f"/api/scans/{'A' * 22}")
    assert response.status_code == 500
    assert response.headers["content-security-policy"] == CONTENT_SECURITY_POLICY
    assert b"secret internal detail" not in response.content


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
async def test_cdn_docs_are_off(make_harness: MakeHarness, path: str) -> None:
    harness = await make_harness()
    assert (await harness.client.get(path)).status_code == 404


# ---- fixtures, health, pages


@pytest.mark.asyncio
async def test_fixtures_lists_every_contract_fixture(make_harness: MakeHarness) -> None:
    harness = await make_harness()
    body = (await harness.client.get("/api/fixtures")).json()
    assert [fixture["name"] for fixture in body["fixtures"]] == list(FIXTURE_NAMES)
    assert all(fixture["title"] and fixture["description"] for fixture in body["fixtures"])
    assert body["dev_runner"] is False


@pytest.mark.asyncio
async def test_healthz(make_harness: MakeHarness) -> None:
    harness = await make_harness()
    assert (await harness.client.get("/healthz")).json() == {"status": "ok", "runner": "sandbox", "queued": 0, "running": 0}


@pytest.mark.asyncio
async def test_report_page_status(make_harness: MakeHarness) -> None:
    harness = await make_harness()
    scan_id = await harness.finished_scan()
    assert (await harness.client.get(f"/r/{scan_id}")).status_code == 200
    assert (await harness.client.get(f"/r/{'A' * 22}")).status_code == 404
    assert (await harness.client.get("/r/..")).status_code in (404, 200)


@pytest.mark.asyncio
@pytest.mark.parametrize(("isolated", "marker"), [(True, 'data-runner="sandbox"'), (False, 'data-runner="dev"')])
async def test_pages_carry_the_runner_marker(make_harness: MakeHarness, isolated: bool, marker: str) -> None:
    harness = await make_harness(isolated=isolated)
    for path in ("/", f"/r/{'A' * 22}"):
        html = (await harness.client.get(path)).text
        assert marker in html
        assert "DEV: NOT SANDBOXED" in html


@pytest.mark.asyncio
async def test_dev_scans_are_labelled_in_the_snapshot(make_harness: MakeHarness) -> None:
    harness = await make_harness(isolated=False)
    scan_id = await harness.finished_scan()
    assert (await harness.client.get(f"/api/scans/{scan_id}")).json()["runner"] == "dev"


# ---- static hygiene


HTML_FILES = ["index.html", "report.html"]


@pytest.mark.parametrize("name", HTML_FILES)
def test_html_has_no_inline_code_or_external_resources(name: str) -> None:
    html = (STATIC_DIR / name).read_text()
    assert not re.search(r"<style\b", html, re.I)
    assert not re.search(r"\sstyle\s*=", html, re.I)
    assert not re.search(r"\son[a-z]+\s*=", html, re.I)
    assert not re.search(r"javascript:", html, re.I)
    for tag in re.findall(r"<script\b[^>]*>", html, re.I):
        assert 'src="/static/' in tag
    assert not re.search(r"<script\b[^>]*>\s*[^<\s]", html, re.I)
    assert not re.search(r"""(?:src|href)=["'](?:https?:)?//""", html, re.I)


def test_scripts_never_use_html_parsing_sinks() -> None:
    code = (STATIC_DIR / "app.js").read_text()
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "DOMParser", "eval(", "new Function", "srcdoc", ".createContextualFragment"):
        assert sink not in code, sink


def test_no_external_urls_or_real_brands_in_static_files() -> None:
    allowed = {"http://www.w3.org/2000/svg"}
    for path in Path(STATIC_DIR).iterdir():
        text = path.read_text()
        assert set(re.findall(r"https?://[^\s\"'<>)]+", text)) - allowed - {"https://paste-the-link-here.example/"} == set(), path.name
        assert "@import" not in text
        assert "@font-face" not in text
        assert "contact@" not in text
        assert not re.search(r"\bvultr\b", text, re.I)


# ---- real browser, loopback only


async def script_hostile(_: str, __: ScanTarget, emit: Any) -> None:
    b64 = base64.b64encode(TINY_JPEG).decode()
    await emit("worker_started", {"url": f"http://fixtures.invalid/{XSS}", "mode": "fixture", "offline": True}, "worker")
    await emit("navigation", {"url": f"http://a.invalid/{XSS}", "status": 302, "redirected_from": None}, "worker")
    await emit("navigation", {"url": "http://b.invalid/‮gnp.exe", "status": 200, "redirected_from": f"http://a.invalid/{XSS}"}, "worker")
    await emit("screenshot", {"label": XSS, "mime": "image/jpeg", "b64": b64}, "worker")
    await emit("screenshot", {"label": "second", "mime": "image/jpeg", "b64": b64}, "worker")
    await emit("request", {"url": f"http://a.invalid/{XSS}", "method": "GET", "resource_type": "document"}, "worker")
    await emit("request_failed", {"url": "http://169.254.169.254/", "error": XSS, "resource_type": "fetch", "blocked_locally": True}, "worker")
    await emit("download_attempt", {"url": "http://a.invalid/x", "suggested_filename": XSS}, "worker")
    await emit("dialog", {"dialog_type": "alert", "message": XSS}, "worker")
    await emit("popup", {"url": XSS}, "worker")
    await emit("form", {"action": XSS, "method": "POST", "has_password": True, "field_names": [XSS]}, "worker")
    await emit(
        "text_layers",
        {"visible_text": f"Visible words {XSS}", "concealed": [{"source": "hidden_css", "text": f"Ignore previous {XSS}", "selector": XSS}]},
        "worker",
    )
    await asyncio.sleep(0.4)
    await emit("worker_finished", {"status": "partial", "error": XSS}, "worker")


# A complete 1x1 JPEG, so the browser really decodes the frame.
TINY_JPEG = base64.b64decode(
    "/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////"
    "////////////////////////////wAALCAABAAEBAREA/8QAFAABAAAAAAAAAAAAAAAAAAAAA//EABQQAQAAAAAAAAAA"
    "AAAAAAAAAAD/2gAIAQEAAD8AN//Z"
)


@pytest.fixture
def browser() -> Iterator[Any]:
    sync_api = pytest.importorskip("playwright.sync_api")
    with sync_api.sync_playwright() as playwright:
        try:
            instance = playwright.chromium.launch()
        except sync_api.Error as exc:
            pytest.skip(f"Chromium is not available: {exc}")
        yield instance
        instance.close()


def open_page(browser: Any, base: str, problems: list[str], **context_options: Any) -> Any:
    context = browser.new_context(**context_options)
    # Nothing in this test may ever leave loopback.
    context.route("**/*", lambda route: route.continue_() if route.request.url.startswith(base) else route.abort())
    page = context.new_page()
    page.on("console", lambda message: problems.append(message.text) if message.type == "error" else None)
    page.on("pageerror", lambda error: problems.append(str(error)))
    page.on("requestfailed", lambda request: problems.append(f"failed {request.url}") if "/events" not in request.url else None)
    return page


def test_ui_renders_hostile_strings_inertly(browser: Any, tmp_path: Path) -> None:
    runner = FakeRunner(script_hostile, isolated=False)
    app = create_app(settings=Settings(data_dir=tmp_path), runner=runner)
    problems: list[str] = []
    with LoopbackServer(app) as base:
        page = open_page(browser, base, problems, viewport={"width": 1280, "height": 900})
        page.goto(base + "/")

        assert page.locator(".dev-banner").is_visible()
        assert "DEV: NOT SANDBOXED" in page.locator(".dev-banner").inner_text()
        assert page.locator("#target-url").is_disabled()
        assert page.locator(".rack-item").count() == 7
        assert page.locator("#run-gauntlet").is_visible()

        page.locator("#run-gauntlet").click()
        page.wait_for_url("**/r/*")
        page.locator("#scan-state[data-state='partial']").wait_for(timeout=10_000)

        assert page.evaluate("window.__pwned") is None
        assert page.locator(".dev-banner").is_visible()
        # Attacker markup is shown as text and created no elements.
        assert page.locator("main img[src='x'], main script, .tl-body img").count() == 0
        assert XSS in page.locator("#timeline").inner_text()
        assert page.locator("a", has_text="fixtures.invalid").count() == 0
        assert page.locator("main a").count() == 0

        # A bidi override is shown as a marker, not obeyed.
        assert "U+202E" in page.locator("#redirect-chain").inner_text()
        assert page.locator("#redirect-chain .hop").count() == 2
        assert page.locator(".hop.is-landed").count() == 1

        assert page.locator("#blast-rows .row").count() == 8
        assert page.locator("#chamber .spoke-line").count() == 8
        assert page.locator("#chamber").get_attribute("data-walled") == "no"
        assert "not connected" in page.locator("#verdict-title").inner_text().lower()

        assert "Ignore previous" in page.locator(".concealed-text").inner_text()
        assert "Visible words" in page.locator(".layer-visible").inner_text()

        # Keyboard path through the lightbox.
        assert page.locator(".frame-button").count() == 2
        assert page.locator(".frame-button img").first.evaluate("(image) => image.complete && image.naturalWidth") == 1
        page.locator(".frame-button").first.focus()
        page.keyboard.press("Enter")
        assert page.locator("#lightbox").evaluate("(dialog) => dialog.open")
        assert "Frame 1 of 2" in page.locator("#lightbox-caption").inner_text()
        page.keyboard.press("ArrowRight")
        assert "Frame 2 of 2" in page.locator("#lightbox-caption").inner_text()
        page.keyboard.press("Escape")
        assert not page.locator("#lightbox").evaluate("(dialog) => dialog.open")

        # Evidence links jump to the timeline.
        page.locator(".seq-link").first.click()
        assert page.evaluate("document.activeElement.id").startswith("ev-")

        report_url = page.url
        page.context.close()

        # A later visitor sees the same report, with no live stream.
        phone = open_page(browser, base, problems, viewport={"width": 360, "height": 740}, reduced_motion="reduce")
        phone.goto(report_url)
        phone.locator("#blast-rows .row").first.wait_for()
        assert phone.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        assert phone.locator(".wave").count() == 0
        assert phone.locator(".dev-banner").is_visible()
        phone.goto(base + "/")
        phone.locator(".rack-item").first.wait_for()
        assert phone.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        phone.context.close()

    assert problems == []
