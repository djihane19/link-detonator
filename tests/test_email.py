"""Email input adapter: the extractor boundary, indicators, explicit confirmation and the
link into the normal scan pipeline. Extraction runs the real extractor script locally
(LocalEmailExtractor); the Docker isolation itself is checked on the VM."""

from __future__ import annotations

import asyncio
import base64
import html
import io
import json
import time
from collections.abc import AsyncIterator
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import httpx
import pytest
import pytest_asyncio
import segno

from app import email_intake
from app import qr as qr_input
from app.config import PROJECT_ROOT, Settings
from app.main import create_app
from app.models import ScanTarget
from loopback_server import LoopbackServer
from test_api import browser, open_page  # noqa: F401  (browser is a fixture)

ACCESS_CODE = "test-access-code-not-real"
XSS = '<img src=x onerror="window.__pwned=1"><script>window.__pwned=2</script>'
DEMO = PROJECT_ROOT / "demo" / "email"


def qr_bytes(text: str) -> bytes:
    buffer = io.BytesIO()
    segno.make(text, error="m", micro=False).save(buffer, kind="png", scale=6, border=4)
    return buffer.getvalue()


def make_email(
    *, html: str | None = None, text: str | None = "Hello.", sender: str = "Larkspur Bank <alerts@larkspur-bank.invalid>",
    reply_to: str | None = None, auth: str | None = None, subject: str = "Your account", attachments: list[tuple[str, str, bytes]] = (),
) -> bytes:
    message = EmailMessage()
    message["From"] = sender
    message["To"] = "customer@example.com"
    message["Subject"] = subject
    message["Date"] = "Sat, 07 Nov 2026 08:00:00 +0000"
    message["Message-ID"] = "<test@example.com>"
    if reply_to:
        message["Reply-To"] = reply_to
    if auth:
        message["Authentication-Results"] = auth
    if text is not None:
        message.set_content(text)
    if html is not None:
        if text is None:
            message.set_content(html, subtype="html")
        else:
            message.add_alternative(html, subtype="html")
    for filename, ctype, data in attachments:
        maintype, subtype = ctype.split("/")
        message.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
    return bytes(message)


class FakeRunner:
    isolated = True

    def __init__(self) -> None:
        self.targets: list[ScanTarget] = []

    async def reap(self) -> int:
        return 0

    async def run(self, scan_id: str, target: ScanTarget, emit: Any) -> None:
        self.targets.append(target)
        await emit("email_source", {"forged": True, "subject": "forged"}, "worker")
        await emit("email_source", {"forged": True}, "host")  # a worker cannot claim host either
        await emit("worker_finished", {"status": "ok", "error": None}, "worker")


class CountingExtractor:
    """Wraps the real extractor so a test can prove it was never reached."""

    def __init__(self, inner: email_intake.EmailExtractor) -> None:
        self.inner, self.calls = inner, 0
        self.sandboxed = inner.sandboxed

    async def extract(self, data: bytes) -> email_intake.Extracted:
        self.calls += 1
        return await self.inner.extract(data)


class Harness:
    def __init__(self, app: Any, client: httpx.AsyncClient, runner: FakeRunner, lookups: list[str],
                 data_dir: Path, extractor: CountingExtractor) -> None:
        self.app, self.client, self.runner, self.lookups, self.data_dir, self.extractor = app, client, runner, lookups, data_dir, extractor

    async def upload(self, data: bytes, content_type: str = "message/rfc822") -> httpx.Response:
        return await self.client.post("/api/email", content=data, headers={"Content-Type": content_type})

    async def ok(self, data: bytes) -> dict[str, Any]:
        response = await self.upload(data)
        assert response.status_code == 200, response.text
        return response.json()

    async def wait_final(self, scan_id: str) -> None:
        scan = self.app.state.manager.get(scan_id)
        async with asyncio.timeout(5):
            while not scan.is_final:
                await asyncio.sleep(0.005)

    async def events(self, scan_id: str) -> list[dict[str, Any]]:
        await self.wait_final(scan_id)
        return (await self.client.get(f"/api/scans/{scan_id}")).json()["events"]


@pytest_asyncio.fixture
async def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[Harness]:
    monkeypatch.setenv("LD_LIVE_ACCESS_CODE", ACCESS_CODE)
    lookups: list[str] = []

    async def resolver(host: str) -> list[str]:
        lookups.append(host)
        return ["93.184.216.34"]

    settings = Settings(data_dir=tmp_path, max_active_per_client=1000)
    runner = FakeRunner()
    extractor = CountingExtractor(email_intake.LocalEmailExtractor(settings))
    app = create_app(settings=settings, runner=runner, resolver=resolver,
                     qr_decoder=qr_input.LocalQrDecoder(settings), email_extractor=extractor)
    context = app.router.lifespan_context(app)
    await context.__aenter__()
    transport = httpx.ASGITransport(app=app, client=("198.51.100.7", 1234))
    client = httpx.AsyncClient(transport=transport, base_url="http://testserver")
    yield Harness(app, client, runner, lookups, tmp_path, extractor)
    await client.aclose()
    await context.__aexit__(None, None, None)


def indicator_ids(body: dict[str, Any]) -> set[str]:
    return {i["id"] for i in body["indicators"]}


def link(body: dict[str, Any], display: str) -> dict[str, Any]:
    return next(item for item in body["links"] if item["display"] == display)


# ---- extraction, with no side effects


@pytest.mark.asyncio
async def test_phishing_link_with_mismatched_text_is_found_but_nothing_is_opened(harness: Harness) -> None:
    html = '<p>Sign in:</p><a href="https://example.com/collect?id=1">https://www.larkspur-bank.invalid/login</a>'
    body = await harness.ok(make_email(html=html))
    item = link(body, "https://example.com/collect?id=1")
    assert item["anchor_text"] == "https://www.larkspur-bank.invalid/login" and item["text_mismatch"]
    assert item["source"] == "html_href" and item["kind"] == "web_url" and item["investigable"]
    assert "link_text_mismatch" in indicator_ids(body)
    assert body["headers"]["subject"] == "Your account" and body["extractor"] == "dev_unsandboxed"
    assert harness.runner.targets == [] and harness.lookups == []
    assert harness.app.state.manager.load_stats() == {"queued": 0, "running": 0}


@pytest.mark.asyncio
@pytest.mark.parametrize("anchor,href,mismatch", [
    ("larkspur-bank.invalid", "https://example.com/", True),
    ("www.example.com", "https://example.com/a", False),
    ("Click here to verify", "https://example.com/a", False),
    ("support@larkspur-bank.invalid", "mailto:support@larkspur-bank.invalid", False),
    ("https://example.com/x", "javascript:alert(1)", True),
])
async def test_link_text_mismatch_rules(harness: Harness, anchor: str, href: str, mismatch: bool) -> None:
    body = await harness.ok(make_email(html=f'<a href="{href}">{anchor}</a>', text=None))
    assert body["links"][0]["text_mismatch"] is mismatch
    assert ("link_text_mismatch" in indicator_ids(body)) is mismatch


@pytest.mark.asyncio
async def test_hidden_link_and_area_are_extracted(harness: Harness) -> None:
    html = ('<p>Hi</p><a href="https://example.com/hidden" style="display: none">x</a>'
            '<map><area href="https://example.com/area" alt="Map"></map><a href="#top">top</a>')
    body = await harness.ok(make_email(html=html))
    assert link(body, "https://example.com/hidden")["hidden"] is True
    assert link(body, "https://example.com/area")["hidden"] is False
    assert not any(item["display"].startswith("#") for item in body["links"])


@pytest.mark.asyncio
async def test_text_only_links_are_found_and_deduplicated(harness: Harness) -> None:
    text = ("Visit https://example.com/a, or http://example.com/b.\nAgain: https://example.com/a\n"
            "Call tel:+15550100 or run javascript:alert(1)")
    body = await harness.ok(make_email(text=text))
    displays = [item["display"] for item in body["links"]]
    assert displays == ["https://example.com/a", "http://example.com/b", "tel:+15550100", "javascript:alert(1)"]
    assert all(item["source"] == "text" for item in body["links"])
    assert link(body, "tel:+15550100")["kind"] == "other_uri"


@pytest.mark.asyncio
async def test_reply_to_domain_mismatch(harness: Harness) -> None:
    other = await harness.ok(make_email(reply_to="Desk <desk@larkspur-support.invalid>"))
    assert "reply_to_differs" in indicator_ids(other)
    same = await harness.ok(make_email(reply_to="help@mail.larkspur-bank.invalid"))
    assert "reply_to_differs" not in indicator_ids(same)


@pytest.mark.asyncio
async def test_authentication_results_tokens_are_reported_not_trusted(harness: Harness) -> None:
    body = await harness.ok(make_email(auth="mx.example.com; spf=softfail smtp.mailfrom=x.invalid; dkim=fail; dmarc=bogus"))
    assert body["auth"] == {"spf": "softfail", "dkim": "fail", "dmarc": "unknown"}
    assert next(i for i in body["indicators"] if i["id"] == "auth_failed")["count"] == 2
    clean = await harness.ok(make_email(auth="mx.example.com; spf=pass; dkim=pass; dmarc=pass"))
    assert clean["auth"] == {"spf": "pass", "dkim": "pass", "dmarc": "pass"} and "auth_failed" not in indicator_ids(clean)
    missing = await harness.ok(make_email())
    assert missing["auth"] == {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}


@pytest.mark.asyncio
async def test_qr_attachment_is_decoded_and_can_be_investigated(harness: Harness) -> None:
    eml = make_email(attachments=[("scan-me.png", "image/png", qr_bytes("http://fixtures.invalid/lab-indirect-injection"))])
    body = await harness.ok(eml)
    assert len(body["qr_payloads"]) == 1
    code = body["qr_payloads"][0]
    assert code["kind"] == "test_page" and code["target"] == {"kind": "fixture", "value": "lab-indirect-injection"}
    assert "scan-me.png" in code["part"] and "qr_in_email" in indicator_ids(body)
    assert body["attachments"][0]["filename"] == "scan-me.png" and not body["attachments"][0]["risky"]
    response = await harness.client.post("/api/scans", json={"fixture": "lab-indirect-injection", "email_id": body["id"]})
    assert response.status_code == 202
    source = next(e for e in await harness.events(response.json()["id"]) if e["type"] == "email_source")
    assert source["data"]["found_in"] == "qr" and source["data"]["link_display"] == "http://fixtures.invalid/lab-indirect-injection"


@pytest.mark.asyncio
async def test_inline_and_embedded_images_are_read_for_qr_codes(harness: Harness) -> None:
    message = EmailMessage()
    message["From"] = "a@example.com"
    message["Subject"] = "Inline"
    message.set_content("See the image.")
    message.add_alternative('<p>Scan:</p><img src="cid:qr1">', subtype="html")
    html_part = message.get_payload()[1]
    html_part.add_related(qr_bytes("https://example.com/inline"), maintype="image", subtype="png", cid="<qr1>", disposition="inline")
    embedded = base64.b64encode(qr_bytes("https://example.com/embedded")).decode()
    message.add_alternative(f'<img src="data:image/png;base64,{embedded}">', subtype="html")
    body = await harness.ok(bytes(message))
    found = {item["display"]: item for item in body["qr_payloads"]}
    assert set(found) == {"https://example.com/inline", "https://example.com/embedded"}
    assert found["https://example.com/inline"]["part"].startswith("inline image")
    assert body["attachments"][0]["inline"] is True


@pytest.mark.asyncio
async def test_executable_attachments_are_flagged_and_never_written_to_disk(harness: Harness) -> None:
    marker = b"MARKER-attachment-bytes-must-stay-in-memory-0123456789"
    eml = make_email(attachments=[
        ("invoice.pdf.exe", "application/octet-stream", marker),
        ("update.JS", "application/javascript", b"// harmless"),
        ("report.pdf", "application/pdf", b"%PDF-1.4 harmless"),
        ("macro.docm", "application/octet-stream", b"harmless"),
    ])
    body = await harness.ok(eml)
    risky = {a["filename"]: a["risky"] for a in body["attachments"]}
    assert risky == {"invoice.pdf.exe": True, "update.JS": True, "report.pdf": False, "macro.docm": True}
    assert next(i for i in body["indicators"] if i["id"] == "executable_attachment")["count"] == 3
    exe = body["attachments"][0]
    assert exe["size"] == len(marker) and len(exe["sha256"]) == 64
    stored = sorted(p.name for p in (harness.data_dir / "email" / body["id"]).iterdir())
    assert stored == ["meta.json", "original.eml"]
    for path in harness.data_dir.rglob("*"):
        if path.is_file():
            assert marker not in path.read_bytes(), path  # base64 inside original.eml only


@pytest.mark.asyncio
@pytest.mark.parametrize("href", ["javascript:alert(document.cookie)", "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", "vbscript:msgbox(1)"])
async def test_script_and_data_links_are_dangerous_and_not_investigable(harness: Harness, href: str) -> None:
    body = await harness.ok(make_email(html=f'<a href="{href}">Open your statement</a>', text=None))
    item = body["links"][0]
    assert item["kind"] == "dangerous_uri" and not item["investigable"] and item["target"] is None
    assert "dangerous_link" in indicator_ids(body)


@pytest.mark.asyncio
@pytest.mark.parametrize("url", ["http://10.0.0.1/admin", "http://169.254.169.254/latest/meta-data/", "http://localhost/", "http://127.0.0.1:8000/"])
async def test_internal_links_are_refused(harness: Harness, url: str) -> None:
    body = await harness.ok(make_email(text=f"Open {url} now"))
    item = body["links"][0]
    assert item["kind"] == "web_url" and not item["investigable"] and item["target"] is None and item["note"].startswith("Refused")
    assert "internal_link" in indicator_ids(body)
    response = await harness.client.post("/api/scans", json={"url": url, "email_id": body["id"], "access_code": ACCESS_CODE})
    assert response.status_code == 400 and harness.runner.targets == []


# ---- explicit confirmation and the link into the pipeline


@pytest.mark.asyncio
async def test_fixture_link_is_a_test_page_and_runs_via_email_id(harness: Harness) -> None:
    html = '<a href="http://fixtures.invalid/lab-credential-harvest">https://secure.larkspur-bank.invalid/</a>'
    body = await harness.ok(make_email(html=html, subject=XSS))
    item = body["links"][0]
    assert item["kind"] == "test_page" and item["target"] == {"kind": "fixture", "value": "lab-credential-harvest"}
    assert harness.runner.targets == []
    response = await harness.client.post("/api/scans", json={"fixture": "lab-credential-harvest", "email_id": body["id"]})
    assert response.status_code == 202
    events = await harness.events(response.json()["id"])
    assert harness.runner.targets == [ScanTarget(kind="fixture", value="lab-credential-harvest")]
    sources = [e for e in events if e["type"] == "email_source"]
    assert len(sources) == 1 and sources[0]["source"] == "host" and sources[0]["seq"] == 1
    data = sources[0]["data"]
    assert data["email_id"] == body["id"] and data["sha256"] == body["sha256"] and data["subject"] == XSS
    assert data["from"] == "alerts@larkspur-bank.invalid" and data["anchor_text"] == "https://secure.larkspur-bank.invalid/"
    assert "event" not in data and not any(e["type"] == "qr_source" for e in events)


@pytest.mark.asyncio
async def test_live_link_needs_a_second_request_and_the_access_code(harness: Harness) -> None:
    body = await harness.ok(make_email(html='<a href="https://example.com/offer">Offer</a>'))
    assert harness.lookups == [] and harness.runner.targets == []
    refused = await harness.client.post("/api/scans", json={"url": "https://example.com/offer", "email_id": body["id"]})
    assert refused.status_code == 403
    response = await harness.client.post("/api/scans", json={"url": "https://example.com/offer", "email_id": body["id"], "access_code": ACCESS_CODE})
    assert response.status_code == 202
    events = await harness.events(response.json()["id"])
    assert harness.lookups == ["example.com"]
    assert events[0]["type"] == "email_source" and events[0]["seq"] == 1 and events[0]["source"] == "host"


@pytest.mark.asyncio
async def test_an_email_cannot_vouch_for_a_target_it_did_not_contain(harness: Harness) -> None:
    body = await harness.ok(make_email(html='<a href="https://example.com/offer">Offer</a>'))
    other = await harness.client.post("/api/scans", json={"url": "https://example.org/else", "email_id": body["id"], "access_code": ACCESS_CODE})
    assert other.status_code == 400 and "not found in this email" in other.json()["detail"]
    fixture = await harness.client.post("/api/scans", json={"fixture": "benign", "email_id": body["id"]})
    assert fixture.status_code == 400
    for bad in ("A" * 22, "../../etc/passwd", "short"):
        unknown = await harness.client.post("/api/scans", json={"fixture": "benign", "email_id": bad})
        assert unknown.status_code == 400
        assert (await harness.client.get(f"/api/email/{bad}")).status_code == 404
    assert harness.runner.targets == []
    again = await harness.client.get(f"/api/email/{body['id']}")
    assert again.status_code == 200 and again.json() == body


@pytest.mark.asyncio
async def test_worker_cannot_forge_email_evidence(harness: Harness) -> None:
    response = await harness.client.post("/api/scans", json={"fixture": "benign"})
    events = await harness.events(response.json()["id"])
    assert harness.runner.targets and not any(e["type"] == "email_source" for e in events)


@pytest.mark.asyncio
async def test_qr_id_and_email_id_together_are_refused(harness: Harness) -> None:
    body = await harness.ok(make_email(html='<a href="http://fixtures.invalid/benign">Notes</a>'))
    response = await harness.client.post("/api/scans", json={"fixture": "benign", "email_id": body["id"], "qr_id": "A" * 22})
    assert response.status_code == 400 and "not both" in response.json()["detail"] and harness.runner.targets == []


# ---- refusals before or at the extractor


@pytest.mark.asyncio
async def test_oversized_upload(harness: Harness) -> None:
    big = b"From: a@example.com\r\n\r\n" + b"x" * email_intake.MAX_UPLOAD_BYTES
    assert (await harness.upload(big)).status_code == 413 and harness.extractor.calls == 0


@pytest.mark.asyncio
async def test_other_content_types_are_refused(harness: Harness) -> None:
    for ctype in ("text/plain", "text/html", "image/png", "multipart/form-data", ""):
        assert (await harness.upload(make_email(), ctype)).status_code == 415
    assert (await harness.upload(make_email(), "application/octet-stream")).status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("data", [
    qr_bytes("https://example.com"),
    b"\x7fELF\x02\x01\x01" + b"\x00" * 200,
    b"MZ\x90\x00From: a@example.com\r\n",
    b"%PDF-1.7\nFrom: a@example.com\n",
    b"PK\x03\x04From: a@example.com\n",
    b"From: a@example.com\r\n\x00\x01\x02 binary",
    b"just some words with no header line at all\n" * 40,
    b"",
])
async def test_binary_or_non_email_upload_is_refused_before_extraction(harness: Harness, data: bytes) -> None:
    response = await harness.upload(data)
    assert response.status_code == 400 and "does not look like an email" in response.json()["detail"]
    assert harness.extractor.calls == 0


@pytest.mark.asyncio
async def test_header_like_text_that_is_not_an_email_is_refused_by_the_extractor(harness: Harness) -> None:
    response = await harness.upload(b"Hello: world\n\nThis is a note, not an email.\n")
    assert response.status_code == 400 and "does not look like an email" in response.json()["detail"]
    assert harness.extractor.calls == 1


@pytest.mark.asyncio
async def test_malformed_mime_is_handled(harness: Harness) -> None:
    eml = (
        b"From: a@example.com\r\nSubject: =?bogus-charset?Q?broken?=\r\nMIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="BOUND"\r\n\r\n'
        b"--BOUND\r\nContent-Type: text/plain; charset=x-not-a-charset\r\n\r\nSee https://example.com/a\r\n"
        b"--BOUND\r\nContent-Type: image/png\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"q.png\"\r\n\r\n"
        b"!!!!not base64@@@@\r\n"
        b"--BOUND\r\nContent-Type: text/html\r\n\r\n<a href='https://example.com/b'>unclosed <b><i>\r\n"
    )  # never closed
    body = await harness.ok(eml)
    assert {item["display"] for item in body["links"]} == {"https://example.com/a", "https://example.com/b"}
    assert body["attachments"][0]["filename"] == "q.png" and body["qr_payloads"] == []


def nested(depth: int) -> bytes:
    head = b"From: a@example.com\r\nSubject: nest\r\nMIME-Version: 1.0\r\n"
    open_parts, close_parts = b"", b""
    for level in range(depth):
        open_parts += b'Content-Type: multipart/mixed; boundary="b%d"\r\n\r\n--b%d\r\n' % (level, level)
        close_parts = b"\r\n--b%d--\r\n" % level + close_parts
    return head + open_parts + b"Content-Type: text/plain\r\n\r\nhttps://example.com/deep" + close_parts


def many_parts(count: int) -> bytes:
    head = b'From: a@example.com\r\nSubject: wide\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="w"\r\n\r\n'
    part = b"--w\r\nContent-Type: text/plain\r\n\r\nhttps://example.com/p%d\r\n"
    return head + b"".join(part % i for i in range(count)) + b"--w--\r\n"


UNCLOSED_ANCHORS = b"From: a@example.com\r\nContent-Type: text/html\r\n\r\n" + b"".join(b"<a href=https://example.com/%d>t " % i for i in range(15000))


@pytest.mark.parametrize("eml", [nested(40), nested(2000), many_parts(3000), UNCLOSED_ANCHORS], ids=["deep", "very-deep", "wide", "unclosed-anchors"])
@pytest.mark.asyncio
async def test_mime_bombs_are_refused_or_capped_quickly(harness: Harness, eml: bytes) -> None:
    started = time.monotonic()
    response = await harness.upload(eml)
    assert time.monotonic() - started < 15
    if response.status_code == 400:
        assert "nested too deeply" in response.json()["detail"] or "could not be read" in response.json()["detail"]
        return
    body = response.json()
    assert response.status_code == 200 and body["truncated"] is True
    assert body["parts"] <= email_intake.MAX_PARTS and len(body["links"]) <= email_intake.MAX_LINKS


@pytest.mark.asyncio
async def test_demo_samples(harness: Harness) -> None:
    phish = await harness.ok((DEMO / "1-fake-bank-alert.eml").read_bytes())
    assert indicator_ids(phish) == {"link_text_mismatch", "reply_to_differs", "auth_failed", "executable_attachment", "qr_in_email"}
    assert phish["links"][0]["target"] == {"kind": "fixture", "value": "lab-credential-harvest"}
    assert phish["qr_payloads"][0]["target"] == {"kind": "fixture", "value": "lab-indirect-injection"}
    benign = await harness.ok((DEMO / "2-benign-newsletter.eml").read_bytes())
    assert benign["indicators"] == [] and benign["links"][0]["target"] == {"kind": "fixture", "value": "benign"}


# ---- the extractor boundary


def test_extractor_container_has_no_network_mounts_or_environment() -> None:
    argv = email_intake.build_extractor_argv("ld-email-test", Settings())
    joined = " ".join(argv)
    assert argv[argv.index("--network") + 1] == "none" and "-i" in argv and "--read-only" in argv
    assert argv[argv.index("--memory") + 1] == "256m" and argv[argv.index("--cap-drop") + 1] == "ALL"
    assert argv[argv.index("--pids-limit") + 1] == "64"
    assert "link-detonator.owner=app" in argv and "no-new-privileges" in argv
    for forbidden in ("-v", "--volume", "--mount", "-e", "--env", "--env-file", "--privileged", "host"):
        assert forbidden not in argv, forbidden
    assert argv[-2:] == ["python", "/worker/email_extract.py"] and "--runtime" not in joined
    with_runtime = email_intake.build_extractor_argv("ld-email-test", Settings(runtime="runsc"))
    assert with_runtime[with_runtime.index("--runtime") + 1] == "runsc"


def good_reply(**overrides: Any) -> dict[str, Any]:
    reply = {
        "ok": True,
        "headers": {"from": "a@example.com", "from_address": "a@example.com", "from_domain": "example.com", "reply_to": "",
                    "reply_to_domain": "", "return_path": "", "to": [], "to_count": 0, "subject": "s", "date": "",
                    "message_id": "", "received_count": 0},
        "auth": {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"},
        "links": [{"url": "https://example.com/", "anchor_text": "", "source": "text", "hidden": False}],
        "links_truncated": False,
        "attachments": [{"filename": "a.txt", "content_type": "text/plain", "size": 1, "sha256": "0" * 64, "inline": False}],
        "attachments_truncated": False,
        "qr_payloads": [{"text": "https://example.com/q", "part": "attachment"}],
        "parts": 3,
        "truncated": False,
    }
    for key, value in overrides.items():
        if key.startswith("headers."):
            reply["headers"][key.split(".", 1)[1]] = value
        else:
            reply[key] = value
    return reply


def test_good_extractor_output_is_accepted() -> None:
    extracted = email_intake.parse_extractor_output(json.dumps(good_reply()).encode())
    assert extracted.links[0]["url"] == "https://example.com/" and extracted.parts == 3


LINK = {"url": "https://example.com/", "anchor_text": "", "source": "text", "hidden": False}
ATTACHMENT = {"filename": "a", "content_type": "text/plain", "size": 1, "sha256": "0" * 64, "inline": False}


@pytest.mark.parametrize("stdout", [
    b"",
    b"not json",
    b"[1, 2]",
    b'{"ok": true}',
    json.dumps(good_reply(extra="field")).encode(),
    json.dumps(good_reply(**{"headers.subject": "x" * 501})).encode(),
    json.dumps(good_reply(**{"headers.subject": 5})).encode(),
    json.dumps(good_reply(**{"headers.from_domain": "evil .example"})).encode(),
    json.dumps(good_reply(**{"headers.to": ["a"] * 6})).encode(),
    json.dumps(good_reply(**{"headers.received_count": -1})).encode(),
    json.dumps(good_reply(**{"headers.injected": "x"})).encode(),
    json.dumps(good_reply(auth={"spf": "pass", "dkim": "pass", "dmarc": "trusted"})).encode(),
    json.dumps(good_reply(auth={"spf": "pass", "dkim": "pass"})).encode(),
    json.dumps(good_reply(links=[LINK] * 2)).encode(),
    json.dumps(good_reply(links=[{**LINK, "url": f"https://example.com/{i}"} for i in range(51)])).encode(),
    json.dumps(good_reply(links=[{**LINK, "source": "worker_says_safe"}])).encode(),
    json.dumps(good_reply(links=[{**LINK, "url": "x" * 5000}])).encode(),
    json.dumps(good_reply(links=[{**LINK, "url": ""}])).encode(),
    json.dumps(good_reply(links=[{**LINK, "investigable": True}])).encode(),
    json.dumps(good_reply(links=[{**LINK, "hidden": "no"}])).encode(),
    json.dumps(good_reply(attachments=[{**ATTACHMENT, "sha256": "not-a-hash"}])).encode(),
    json.dumps(good_reply(attachments=[{**ATTACHMENT, "size": True}])).encode(),
    json.dumps(good_reply(attachments=[{**ATTACHMENT, "size": 10**9}])).encode(),
    json.dumps(good_reply(attachments=[ATTACHMENT] * 31)).encode(),
    json.dumps(good_reply(qr_payloads=[{"text": "x", "part": "p", "target": {"kind": "url"}}])).encode(),
    json.dumps(good_reply(qr_payloads=[{"text": "", "part": "p"}])).encode(),
    json.dumps(good_reply(qr_payloads=[{"text": "x", "part": "p"}] * 21)).encode(),
    json.dumps(good_reply(parts=201)).encode(),
    json.dumps(good_reply(truncated="no")).encode(),
    b"x" * (email_intake.MAX_EXTRACTOR_OUTPUT_BYTES + 1),
])
def test_hostile_extractor_output_is_rejected(stdout: bytes) -> None:
    with pytest.raises(email_intake.EmailError):
        email_intake.parse_extractor_output(stdout)


@pytest.mark.parametrize("error,expected", [("email too large", "larger than 5 MB"), ("not an email", "does not look like"),
                                            ("extraction took too long", "too long"), ("<script>", "could not be read")])
def test_extractor_errors_map_to_fixed_messages(error: str, expected: str) -> None:
    with pytest.raises(email_intake.EmailError, match=expected):
        email_intake.parse_extractor_output(json.dumps({"ok": False, "error": error}).encode())


# ---- the page, in a real browser


def test_email_panel_renders_inertly_and_fits_a_phone(browser: Any, tmp_path: Path) -> None:  # noqa: F811
    settings = Settings(data_dir=tmp_path)
    app = create_app(settings=settings, runner=FakeRunner(), email_extractor=email_intake.LocalEmailExtractor(settings))
    eml = make_email(
        subject=XSS, sender=f'"{XSS}" <alerts@larkspur-bank.invalid>', reply_to="desk@larkspur-support.invalid",
        auth="mx.example.com; spf=fail; dkim=none; dmarc=fail",
        html=(f'<a href="http://fixtures.invalid/lab-credential-harvest">https://secure.larkspur-bank.invalid/login</a>'
              f'<a href="javascript:alert(1)">{html.escape(XSS)}</a><a href="https://example.com/{"a" * 300}">long</a>'),
        attachments=[("invoice.pdf.exe", "application/octet-stream", b"harmless"), (f"{XSS}.png", "image/png", qr_bytes("http://fixtures.invalid/benign"))],
    )
    sample = tmp_path / "sample.eml"
    sample.write_bytes(eml)
    problems: list[str] = []
    with LoopbackServer(app) as base:
        page = open_page(browser, base, problems, viewport={"width": 390, "height": 844})
        page.goto(base + "/")
        anchors_before = page.locator("main a").count()
        page.locator("#email-file").set_input_files(str(sample))
        page.locator("#email-check").click()
        page.locator("#email-result").wait_for(state="visible", timeout=15_000)

        panel = page.locator("#email-result")
        assert page.evaluate("window.__pwned") is None
        assert panel.locator("a, img, script").count() == 0
        assert page.locator("main a").count() == anchors_before
        assert XSS in page.locator("#email-facts").inner_text()
        assert XSS in page.locator("#email-links").inner_text()
        assert "SPF: fail" in page.locator("#email-auth").inner_text()
        warnings = page.locator("#email-indicators").inner_text()
        assert "really goes to another" in warnings and "different domain" in warnings and "can run code" in warnings
        assert page.locator(".email-link[data-mismatch='yes']").count() == 1
        assert page.locator(".email-attachment[data-risky='yes']").count() == 1
        assert page.locator("#email-qr .qr-payload").count() == 1
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")

        # The test page, the long web link and the QR code; the javascript: link has none.
        buttons = panel.locator("button", has_text="Investigate this link")
        assert buttons.count() == 3
        buttons.first.click()
        page.wait_for_url("**/r/*")
        page.locator("#email-card").wait_for(state="visible", timeout=10_000)
        card = page.locator("#email-card-facts").inner_text()
        assert XSS in card and "alerts@larkspur-bank.invalid" in card and "fixtures.invalid/lab-credential-harvest" in card
        assert page.evaluate("window.__pwned") is None
        assert page.locator("main a").count() == 0
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    assert problems == []
