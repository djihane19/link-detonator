"""QR input adapter: the decoder boundary, payload rules, explicit confirmation and the
link into the normal scan pipeline. Decoding runs the real decoder script locally
(LocalQrDecoder); the Docker isolation itself is checked on the VM."""

from __future__ import annotations

import asyncio
import io
import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import pytest_asyncio
import segno
from PIL import Image

from app import qr as qr_input
from app.config import Settings
from app.main import create_app
from app.models import ScanTarget

ACCESS_CODE = "test-access-code-not-real"


def qr_png(*payloads: str, scale: int = 6) -> bytes:
    images = []
    for text in payloads:
        buffer = io.BytesIO()
        segno.make(text, error="m", micro=False).save(buffer, kind="png", scale=scale, border=4)
        images.append(Image.open(io.BytesIO(buffer.getvalue())).convert("RGB"))
    width = sum(i.width for i in images) + 40 * len(images)
    canvas = Image.new("RGB", (width, max(i.height for i in images) + 40), "white")
    x = 20
    for image in images:
        canvas.paste(image, (x, 20))
        x += image.width + 40
    out = io.BytesIO()
    canvas.save(out, format="PNG")
    return out.getvalue()


def convert(png: bytes, fmt: str) -> bytes:
    out = io.BytesIO()
    Image.open(io.BytesIO(png)).convert("RGB").save(out, format=fmt, quality=95)
    return out.getvalue()


class FakeRunner:
    isolated = True

    def __init__(self) -> None:
        self.targets: list[ScanTarget] = []

    async def reap(self) -> int:
        return 0

    async def run(self, scan_id: str, target: ScanTarget, emit: Any) -> None:
        self.targets.append(target)
        await emit("qr_source", {"forged": True}, "worker")
        await emit("worker_finished", {"status": "ok", "error": None}, "worker")


class Harness:
    def __init__(self, app: Any, client: httpx.AsyncClient, runner: FakeRunner, lookups: list[str], data_dir: Path) -> None:
        self.app, self.client, self.runner, self.lookups, self.data_dir = app, client, runner, lookups, data_dir

    async def upload(self, data: bytes, content_type: str = "image/png") -> httpx.Response:
        return await self.client.post("/api/qr", content=data, headers={"Content-Type": content_type})

    async def wait_final(self, scan_id: str) -> None:
        scan = self.app.state.manager.get(scan_id)
        async with asyncio.timeout(5):
            while not scan.is_final:
                await asyncio.sleep(0.005)


@pytest_asyncio.fixture
async def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[Harness]:
    monkeypatch.setenv("LD_LIVE_ACCESS_CODE", ACCESS_CODE)
    lookups: list[str] = []

    async def resolver(host: str) -> list[str]:
        lookups.append(host)
        return ["93.184.216.34"]

    settings = Settings(data_dir=tmp_path, max_active_per_client=1000)
    runner = FakeRunner()
    app = create_app(settings=settings, runner=runner, resolver=resolver, qr_decoder=qr_input.LocalQrDecoder(settings))
    context = app.router.lifespan_context(app)
    await context.__aenter__()
    transport = httpx.ASGITransport(app=app, client=("198.51.100.7", 1234))
    client = httpx.AsyncClient(transport=transport, base_url="http://testserver")
    yield Harness(app, client, runner, lookups, tmp_path)
    await client.aclose()
    await context.__aexit__(None, None, None)


def only(body: dict[str, Any]) -> dict[str, Any]:
    assert body["codes_found"] == 1 and len(body["payloads"]) == 1
    return body["payloads"][0]


# ---- decoding, with no side effects


@pytest.mark.asyncio
@pytest.mark.parametrize("url", ["http://example.com/offer", "https://example.com/login?next=/a"])
async def test_web_link_is_decoded_but_nothing_is_opened(harness: Harness, url: str) -> None:
    response = await harness.upload(qr_png(url))
    assert response.status_code == 200
    payload = only(response.json())
    assert payload["kind"] == "web_url" and payload["investigable"] and payload["display"] == url
    assert harness.runner.targets == [] and harness.lookups == []
    assert harness.app.state.manager.load_stats() == {"queued": 0, "running": 0}


@pytest.mark.asyncio
@pytest.mark.parametrize("fmt,ctype", [("JPEG", "image/jpeg"), ("WEBP", "image/webp")])
async def test_jpeg_and_webp(harness: Harness, fmt: str, ctype: str) -> None:
    response = await harness.upload(convert(qr_png("https://example.com/x"), fmt), ctype)
    assert response.status_code == 200 and only(response.json())["display"] == "https://example.com/x"


@pytest.mark.asyncio
async def test_shortened_url_is_flagged_as_unknown_destination(harness: Harness) -> None:
    payload = only((await harness.upload(qr_png("https://bit.ly/3abcXYZ"))).json())
    assert payload["investigable"] and "shortener" in payload["note"]


@pytest.mark.asyncio
@pytest.mark.parametrize("url", [
    "http://10.0.0.1/admin", "http://192.168.1.1/", "http://169.254.169.254/latest/meta-data/",
    "http://[::ffff:169.254.169.254]/", "http://localhost/", "http://127.0.0.1:8000/", "http://2852039166/",
])
async def test_internal_destinations_cannot_be_investigated(harness: Harness, url: str) -> None:
    payload = only((await harness.upload(qr_png(url))).json())
    assert payload["kind"] == "web_url" and not payload["investigable"] and payload["target"] is None
    assert payload["note"].startswith("Refused")


@pytest.mark.asyncio
@pytest.mark.parametrize("text,kind", [
    ("javascript:alert(document.cookie)", "dangerous_uri"),
    ("data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", "dangerous_uri"),
    ("file:///etc/passwd", "dangerous_uri"),
    ("bitcoin:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh?amount=0.5", "payment_request"),
    ("BCD\n002\n1\nSCT\nBICCODE\nLarkspur Test\nDE00000000000000000000\nEUR10.00", "payment_request"),
    ("mailto:help@example.com", "other_uri"),
    ("Meeting room 4, floor 2", "text"),
])
async def test_non_web_payloads_are_shown_not_opened_and_not_called_malicious(harness: Harness, text: str, kind: str) -> None:
    payload = only((await harness.upload(qr_png(text))).json())
    assert payload["kind"] == kind and not payload["investigable"] and payload["target"] is None
    assert "malicious" not in payload["note"].lower() or kind == "text"


@pytest.mark.asyncio
async def test_wifi_password_is_never_returned_or_stored(harness: Harness) -> None:
    response = await harness.upload(qr_png("WIFI:S:Larkspur Guest;T:WPA;P:hunter2-secret;;"))
    payload = only(response.json())
    assert payload["kind"] == "wifi_config" and "hunter2-secret" not in response.text
    stored = next((harness.data_dir / "qr").glob("*/meta.json")).read_text()
    assert "hunter2-secret" not in stored and "[hidden]" in stored


@pytest.mark.asyncio
async def test_multiple_codes_are_all_listed(harness: Harness) -> None:
    body = (await harness.upload(qr_png("https://example.com/one", "https://example.com/two"))).json()
    assert body["codes_found"] == 2
    assert sorted(p["display"] for p in body["payloads"]) == ["https://example.com/one", "https://example.com/two"]


@pytest.mark.asyncio
async def test_image_without_a_code(harness: Harness) -> None:
    out = io.BytesIO()
    Image.new("RGB", (200, 200), "white").save(out, format="PNG")
    body = (await harness.upload(out.getvalue())).json()
    assert body["codes_found"] == 0 and body["payloads"] == []


# ---- refusals before or at the decoder


@pytest.mark.asyncio
async def test_malformed_image_with_a_valid_signature(harness: Harness) -> None:
    response = await harness.upload(qr_input.PNG_MAGIC + b"\x00garbage" * 50)
    assert response.status_code == 400 and "readable image" in response.json()["detail"]


@pytest.mark.asyncio
async def test_file_disguised_as_an_image_is_refused_before_decoding(harness: Harness) -> None:
    response = await harness.upload(b"<html><script>alert(1)</script></html>", "image/png")
    assert response.status_code == 400 and "not the image type" in response.json()["detail"]
    jpeg_as_png = await harness.upload(convert(qr_png("https://example.com"), "JPEG"), "image/png")
    assert jpeg_as_png.status_code == 400


@pytest.mark.asyncio
async def test_other_content_types_are_refused(harness: Harness) -> None:
    for ctype in ("text/plain", "image/svg+xml", "image/gif", "application/pdf"):
        assert (await harness.upload(b"x" * 100, ctype)).status_code == 415


@pytest.mark.asyncio
async def test_oversized_upload(harness: Harness) -> None:
    big = qr_input.PNG_MAGIC + b"\x00" * (qr_input.MAX_UPLOAD_BYTES + 1)
    assert (await harness.upload(big)).status_code == 413


@pytest.mark.asyncio
async def test_oversized_dimensions_are_refused_by_the_decoder(harness: Harness) -> None:
    out = io.BytesIO()
    Image.new("1", (5000, 20), 1).save(out, format="PNG")
    response = await harness.upload(out.getvalue())
    assert response.status_code == 400 and "too large" in response.json()["detail"]


# ---- explicit confirmation and the link into the pipeline


@pytest.mark.asyncio
async def test_investigation_needs_a_second_request_and_records_the_qr_evidence(harness: Harness) -> None:
    upload = (await harness.upload(qr_png("https://example.com/offer"))).json()
    target = upload["payloads"][0]["target"]
    response = await harness.client.post("/api/scans", json={"url": target["value"], "qr_id": upload["id"], "access_code": ACCESS_CODE})
    assert response.status_code == 202
    scan_id = response.json()["id"]
    await harness.wait_final(scan_id)
    assert harness.runner.targets == [ScanTarget(kind="url", value="https://example.com/offer")]
    assert harness.lookups == ["example.com"]  # the normal validation ran, at investigation time only
    events = (await harness.client.get(f"/api/scans/{scan_id}")).json()["events"]
    sources = [e for e in events if e["type"] == "qr_source"]
    assert len(sources) == 1 and sources[0]["source"] == "host" and sources[0]["seq"] == 1
    assert sources[0]["data"]["qr_id"] == upload["id"] and sources[0]["data"]["sha256"] == upload["sha256"]


@pytest.mark.asyncio
async def test_live_qr_links_still_need_the_access_code(harness: Harness) -> None:
    upload = (await harness.upload(qr_png("https://example.com/offer"))).json()
    response = await harness.client.post("/api/scans", json={"url": "https://example.com/offer", "qr_id": upload["id"]})
    assert response.status_code == 403 and harness.runner.targets == []


@pytest.mark.asyncio
async def test_a_qr_cannot_vouch_for_a_target_it_did_not_contain(harness: Harness) -> None:
    upload = (await harness.upload(qr_png("https://example.com/offer"))).json()
    other = await harness.client.post("/api/scans", json={"url": "https://example.org/else", "qr_id": upload["id"], "access_code": ACCESS_CODE})
    assert other.status_code == 400
    unknown = await harness.client.post("/api/scans", json={"fixture": "benign", "qr_id": "A" * 22})
    assert unknown.status_code == 400 and harness.runner.targets == []


@pytest.mark.asyncio
async def test_refused_payload_cannot_be_investigated_through_its_qr(harness: Harness) -> None:
    upload = (await harness.upload(qr_png("http://169.254.169.254/latest/"))).json()
    response = await harness.client.post("/api/scans", json={"url": "http://169.254.169.254/latest/", "qr_id": upload["id"], "access_code": ACCESS_CODE})
    assert response.status_code == 400 and harness.runner.targets == []


@pytest.mark.asyncio
async def test_test_page_qr_runs_as_a_fixture(harness: Harness) -> None:
    upload = (await harness.upload(qr_png("http://fixtures.invalid/lab-direct-injection"))).json()
    payload = upload["payloads"][0]
    assert payload["kind"] == "test_page" and payload["target"] == {"kind": "fixture", "value": "lab-direct-injection"}
    response = await harness.client.post("/api/scans", json={"fixture": "lab-direct-injection", "qr_id": upload["id"]})
    assert response.status_code == 202


@pytest.mark.asyncio
async def test_worker_cannot_forge_qr_evidence(harness: Harness) -> None:
    response = await harness.client.post("/api/scans", json={"fixture": "benign"})
    scan_id = response.json()["id"]
    await harness.wait_final(scan_id)
    events = (await harness.client.get(f"/api/scans/{scan_id}")).json()["events"]
    assert not any(e["type"] == "qr_source" for e in events)


@pytest.mark.asyncio
async def test_preview_is_the_sandbox_drawn_png_and_ids_are_checked(harness: Harness) -> None:
    upload = (await harness.upload(convert(qr_png("https://example.com"), "JPEG"), "image/jpeg")).json()
    preview = await harness.client.get(upload["preview_url"])
    assert preview.status_code == 200 and preview.headers["content-type"] == "image/png"
    assert preview.content.startswith(qr_input.PNG_MAGIC) and preview.headers["x-content-type-options"] == "nosniff"
    for bad in ("../../etc/passwd", "A" * 22, "short"):
        assert (await harness.client.get(f"/api/qr/{bad}/preview.png")).status_code == 404
    assert not (harness.data_dir / "qr" / upload["id"] / "original.bin").read_bytes().startswith(qr_input.PNG_MAGIC)


# ---- the decoder boundary


def test_decoder_container_has_no_network_mounts_or_environment() -> None:
    argv = qr_input.build_decoder_argv("ld-qr-test", Settings())
    joined = " ".join(argv)
    assert argv[argv.index("--network") + 1] == "none" and "-i" in argv and "--read-only" in argv
    assert argv[argv.index("--memory") + 1] == "256m" and argv[argv.index("--cap-drop") + 1] == "ALL"
    assert "link-detonator.owner=app" in argv and "no-new-privileges" in argv
    for forbidden in ("-v", "--volume", "--mount", "-e", "--env", "--env-file", "--privileged", "host"):
        assert forbidden not in argv, forbidden
    assert argv[-2:] == ["python", "/worker/qr_decode.py"] and "--runtime" not in joined


@pytest.mark.parametrize("stdout", [
    b"",
    b"not json",
    b'{"ok": true}',
    json.dumps({"ok": True, "format": "gif", "width": 1, "height": 1, "codes_found": 0, "payloads": [], "preview_png_b64": ""}).encode(),
    json.dumps({"ok": True, "format": "png", "width": 1, "height": 1, "codes_found": 9, "payloads": ["a"] * 9, "preview_png_b64": ""}).encode(),
    json.dumps({"ok": True, "format": "png", "width": 1, "height": 1, "codes_found": 1, "payloads": [{"x": 1}], "preview_png_b64": ""}).encode(),
    json.dumps({"ok": True, "format": "png", "width": 1, "height": 1, "codes_found": 0, "payloads": [], "preview_png_b64": "PGh0bWw+"}).encode(),
    b"x" * (qr_input.MAX_DECODER_OUTPUT_BYTES + 1),
])
def test_hostile_decoder_output_is_rejected(stdout: bytes) -> None:
    with pytest.raises(qr_input.QrError):
        qr_input.parse_decoder_output(stdout)
