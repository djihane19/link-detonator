"""Email input adapter. A saved .eml file is one more way to submit links: it is read in
a disposable network-disabled sandbox, its links and QR codes are shown to the user with
deterministic indicators, and a link is investigated only on an explicit request through
the normal scan pipeline. Nothing here contacts anything the email contains.

The trusted process never parses the email, its HTML or its images. It counts bytes,
checks that the start looks like mail headers, stores the original as evidence, and
validates every field the extractor returns as hostile.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import secrets
import shutil
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

from app.config import PROJECT_ROOT, Settings
from app.qr import MAX_PAYLOAD_CHARS, classify
from app.sandbox import SANDBOX_LABEL, _DockerClient, decoder_runtime_args, owner_label
from app.urlpolicy import UrlPolicyError, _check_name_is_public, _parse_host, check_url_syntax, is_public_ip

MAX_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_EXTRACTOR_OUTPUT_BYTES = 2 * 1024 * 1024
EXTRACT_TIMEOUT_S = 20.0
MAX_STORED_UPLOADS = 500
EXTRACTOR_SCRIPT = "/worker/email_extract.py"
CONTENT_TYPES = frozenset({"message/rfc822", "application/octet-stream"})

# Caps the reply must respect. They match worker/email_extract.py.
MAX_LINKS = 50
MAX_ATTACHMENTS = 30
MAX_QR_PAYLOADS = 20
MAX_RECIPIENTS = 5
MAX_HEADER_CHARS = 500
MAX_ANCHOR_CHARS = 300
MAX_NAME_CHARS = 255
MAX_DOMAIN_CHARS = 253
MAX_SIZE = MAX_UPLOAD_BYTES
MAX_PARTS = 200
MAX_SUBJECT_IN_ORIGIN = 200

AUTH_TOKENS = frozenset({"pass", "fail", "softfail", "none", "neutral", "temperror", "permerror", "unknown"})
LINK_SOURCES = frozenset({"html_href", "text"})
RISKY_EXTENSIONS = frozenset({
    "exe", "scr", "js", "vbs", "bat", "cmd", "ps1", "hta", "iso", "img", "lnk", "jar", "msi", "docm", "xlsm",
})
_EMAIL_ID = re.compile(r"^[A-Za-z0-9_-]{22}$")
_HEADER_LINE = re.compile(rb"^[A-Za-z0-9-]+:", re.MULTILINE)
_CONTROL = re.compile(rb"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
# A string that reads as a link or a bare domain to a person: "www.bank.example",
# "https://bank.example/login". Used only to compare with the real destination.
_LOOKS_LIKE_HOST = re.compile(
    r"^(?:[a-z][a-z0-9+.-]*://)?((?:[a-z0-9-]+\.)+[a-z]{2,63}|\d{1,3}(?:\.\d{1,3}){3})\.?(?::\d+)?(?:[/?#]\S*)?$",
    re.IGNORECASE,
)
_BINARY_MAGIC = (b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"%PDF", b"PK\x03\x04", b"MZ", b"\x7fELF", b"RIFF", b"\x1f\x8b", b"Rar!", b"7z\xbc\xaf")

INDICATOR_TEXT = {
    "link_text_mismatch": "A link's text shows one address but it really goes to another.",
    "reply_to_differs": "Replies would go to a different domain than the sender's.",
    "auth_failed": "The email's own headers report a failed sender check (SPF, DKIM or DMARC).",
    "dangerous_link": "A link uses a type that can run code or read local data, such as javascript: or data:.",
    "internal_link": "A link points at a private or internal address. It cannot be investigated.",
    "executable_attachment": "An attachment has a file type that can run code, or hides one behind a double extension.",
    "qr_in_email": "The email contains a QR code. A QR code hides its destination until scanned.",
}


class EmailError(Exception):
    """A refusal that is safe to show the user."""


def is_valid_email_id(value: str) -> bool:
    return bool(_EMAIL_ID.fullmatch(value))


def looks_like_email(data: bytes) -> bool:
    """A cheap sanity check, not a parse: the first 1 KB must be text and contain a
    header-like line. Obvious binaries are refused before any sandbox starts."""
    head = data[:1024]
    if not head or head.startswith(_BINARY_MAGIC) or _CONTROL.search(head):
        return False
    return _HEADER_LINE.search(head) is not None


@dataclass(frozen=True)
class Extracted:
    headers: dict[str, Any]
    auth: dict[str, str]
    links: list[dict[str, Any]]
    links_truncated: bool
    attachments: list[dict[str, Any]]
    attachments_truncated: bool
    qr_payloads: list[dict[str, str]]
    parts: int
    truncated: bool


class EmailExtractor(Protocol):
    sandboxed: bool

    async def extract(self, data: bytes) -> Extracted:
        """Raises EmailError with a user-safe message."""
        ...


def _text(value: Any, limit: int) -> bool:
    return isinstance(value, str) and len(value) <= limit


def _flag(value: Any) -> bool:
    return isinstance(value, bool)


def _count(value: Any, limit: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= limit


def _exact_keys(value: Any, keys: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == keys


_HEADER_FIELDS = {
    "from": MAX_HEADER_CHARS, "from_address": MAX_HEADER_CHARS, "from_domain": MAX_DOMAIN_CHARS,
    "reply_to": MAX_HEADER_CHARS, "reply_to_domain": MAX_DOMAIN_CHARS, "return_path": MAX_HEADER_CHARS,
    "subject": MAX_HEADER_CHARS, "date": MAX_HEADER_CHARS, "message_id": MAX_HEADER_CHARS,
}
_REPLY_KEYS = {"ok", "headers", "auth", "links", "links_truncated", "attachments", "attachments_truncated", "qr_payloads", "parts", "truncated"}


def _headers_ok(headers: Any) -> bool:
    if not _exact_keys(headers, {*_HEADER_FIELDS, "to", "to_count", "received_count"}):
        return False
    return (
        all(_text(headers[k], limit) for k, limit in _HEADER_FIELDS.items())
        and isinstance(headers["to"], list) and len(headers["to"]) <= MAX_RECIPIENTS
        and all(_text(t, MAX_HEADER_CHARS) for t in headers["to"])
        and _count(headers["to_count"], 100_000) and _count(headers["received_count"], 100_000)
        and not any(c.isspace() for c in headers["from_domain"] + headers["reply_to_domain"])
    )


def _link_ok(link: Any) -> bool:
    return (
        _exact_keys(link, {"url", "anchor_text", "source", "hidden"})
        and _text(link["url"], MAX_PAYLOAD_CHARS) and bool(link["url"])
        and _text(link["anchor_text"], MAX_ANCHOR_CHARS)
        and link["source"] in LINK_SOURCES and _flag(link["hidden"])
    )


def _attachment_ok(item: Any) -> bool:
    return (
        _exact_keys(item, {"filename", "content_type", "size", "sha256", "inline"})
        and _text(item["filename"], MAX_NAME_CHARS) and _text(item["content_type"], 127)
        and _count(item["size"], MAX_SIZE) and isinstance(item["sha256"], str)
        and bool(_SHA256.fullmatch(item["sha256"])) and _flag(item["inline"])
    )


def _qr_ok(item: Any) -> bool:
    return _exact_keys(item, {"text", "part"}) and _text(item["text"], MAX_PAYLOAD_CHARS) and bool(item["text"]) and _text(item["part"], MAX_NAME_CHARS)


def parse_extractor_output(stdout: bytes) -> Extracted:
    """The extractor is treated as hostile: its whole reply is validated before use."""
    if len(stdout) > MAX_EXTRACTOR_OUTPUT_BYTES:
        raise EmailError("The email reader returned too much data.")
    try:
        reply = json.loads(stdout.decode("utf-8").strip().splitlines()[-1])
    except (ValueError, IndexError, UnicodeDecodeError, RecursionError):
        raise EmailError("The email could not be read.") from None
    if not isinstance(reply, dict):
        raise EmailError("The email could not be read.")
    if reply.get("ok") is not True:
        messages = {
            "email too large": "The email is larger than 5 MB.",
            "empty upload": "The upload was empty.",
            "not an email": "That file does not look like an email (.eml).",
            "extraction took too long": "Reading the email took too long.",
            "email nested too deeply": "The email is nested too deeply to read safely.",
        }
        raise EmailError(messages.get(reply.get("error"), "That file could not be read as an email."))
    links, attachments, qr = reply.get("links"), reply.get("attachments"), reply.get("qr_payloads")
    fields_ok = (
        set(reply) == _REPLY_KEYS
        and _headers_ok(reply["headers"])
        and _exact_keys(reply["auth"], {"spf", "dkim", "dmarc"}) and all(v in AUTH_TOKENS for v in reply["auth"].values())
        and isinstance(links, list) and len(links) <= MAX_LINKS and all(_link_ok(x) for x in links)
        and len({x["url"] for x in links}) == len(links)
        and isinstance(attachments, list) and len(attachments) <= MAX_ATTACHMENTS and all(_attachment_ok(x) for x in attachments)
        and isinstance(qr, list) and len(qr) <= MAX_QR_PAYLOADS and all(_qr_ok(x) for x in qr)
        and _count(reply["parts"], MAX_PARTS)
        and all(_flag(reply[k]) for k in ("links_truncated", "attachments_truncated", "truncated"))
    )
    if not fields_ok:
        raise EmailError("The email could not be read.")
    return Extracted(reply["headers"], reply["auth"], links, reply["links_truncated"], attachments,
                     reply["attachments_truncated"], qr, reply["parts"], reply["truncated"])


def build_extractor_argv(name: str, settings: Settings) -> list[str]:
    """The same box as the QR decoder: no network, read-only, the email only on stdin."""
    argv = [
        settings.docker_bin, "run", "-i", "--rm", "--init",
        "--name", name,
        "--label", SANDBOX_LABEL,
        "--label", owner_label(settings),
        "--network", "none",
        "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", "64",
        "--memory", "256m", "--memory-swap", "256m",
        "--cpus", "1",
        "--ulimit", "nofile=256:256",
        "--log-driver", "none",
        "--user", "pwuser",
    ]
    argv += decoder_runtime_args(settings)
    return [*argv, settings.image, "python", EXTRACTOR_SCRIPT]


class DockerEmailExtractor:
    sandboxed = True

    def __init__(self, settings: Settings, max_concurrent: int = 2) -> None:
        self._settings = settings
        self._client = _DockerClient(settings)
        self._slots = asyncio.Semaphore(max_concurrent)

    async def extract(self, data: bytes) -> Extracted:
        if self._slots.locked():
            raise EmailError("The email reader is busy. Try again in a moment.")
        async with self._slots:
            name = f"ld-email-{secrets.token_hex(8)}"
            stdout = await self._run(build_extractor_argv(name, self._settings), data, name)
        return parse_extractor_output(stdout)

    async def _run(self, argv: list[str], data: bytes, name: str) -> bytes:
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL, env=self._client.env,
            )
        except OSError:
            raise EmailError("The email reader could not start.") from None
        try:
            async with asyncio.timeout(EXTRACT_TIMEOUT_S):
                stdout, _ = await proc.communicate(input=data)
        except TimeoutError:
            raise EmailError("Reading the email took too long.") from None
        finally:
            if proc.returncode is None:
                with suppress(ProcessLookupError):
                    proc.kill()
            await self._client.command("rm", "-f", name)
        return stdout


class LocalEmailExtractor:
    """Dev only: runs the extractor script as a plain subprocess, with no sandbox."""

    sandboxed = False

    def __init__(self, settings: Settings) -> None:
        self._python = settings.python_bin
        self._script = str(PROJECT_ROOT / "worker" / "email_extract.py")

    async def extract(self, data: bytes) -> Extracted:
        proc = await asyncio.create_subprocess_exec(
            self._python, "-I", self._script, stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL, env={"PATH": os.environ.get("PATH", "")},
        )
        try:
            async with asyncio.timeout(EXTRACT_TIMEOUT_S):
                stdout, _ = await proc.communicate(input=data)
        except TimeoutError:
            with suppress(ProcessLookupError):
                proc.kill()
            raise EmailError("Reading the email took too long.") from None
        return parse_extractor_output(stdout)


def build_extractor(settings: Settings) -> EmailExtractor:
    return LocalEmailExtractor(settings) if settings.dev_local_runner else DockerEmailExtractor(settings)


# ---- indicators: facts computed from the extracted data, never a verdict


def _strip_www(host: str) -> str:
    host = host.lower().rstrip(".")
    return host[4:] if host.startswith("www.") else host


def text_host(anchor: str) -> str | None:
    """The host a person would read in a link's text, if the text looks like one."""
    match = _LOOKS_LIKE_HOST.match(anchor.strip())
    return _strip_www(match.group(1)) if match else None


def href_host(url: str) -> str | None:
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    return _strip_www(host) if host else None


def text_mismatch(anchor: str, url: str) -> bool:
    shown = text_host(anchor)
    return shown is not None and shown != href_host(url)


def same_domain(a: str, b: str) -> bool:
    a, b = a.lower().rstrip("."), b.lower().rstrip(".")
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def is_risky_name(filename: str) -> bool:
    name = filename.strip().strip(".").lower()
    parts = name.rsplit(".", 1)
    return len(parts) == 2 and parts[1].strip() in RISKY_EXTENSIONS


def is_internal(url: str) -> bool:
    """Whether the URL policy calls the host non-public, whatever else it refused the URL
    for (a port, say). Only the policy's own host checks are used."""
    try:
        check_url_syntax(url)
        return False
    except UrlPolicyError as exc:
        if exc.code in ("non_public_host", "single_label"):
            return True
    try:
        host, ip = _parse_host(urlsplit(url).hostname)
        if ip is not None:
            return not is_public_ip(ip)
        _check_name_is_public(host)
    except UrlPolicyError as exc:
        return exc.code in ("non_public_host", "single_label")
    except ValueError:
        return False
    return False


def indicators(extracted: Extracted, links: list[dict[str, Any]], qr: list[dict[str, Any]]) -> list[dict[str, Any]]:
    headers, auth = extracted.headers, extracted.auth
    found: dict[str, int] = {
        "link_text_mismatch": sum(1 for link in links if link["text_mismatch"]),
        "reply_to_differs": int(bool(headers["reply_to_domain"] and headers["from_domain"]
                                     and not same_domain(headers["reply_to_domain"], headers["from_domain"]))),
        "auth_failed": sum(1 for value in auth.values() if value in ("fail", "softfail")),
        "dangerous_link": sum(1 for item in links + qr if item["kind"] == "dangerous_uri"),
        "internal_link": sum(1 for item in links + qr if item["kind"] == "web_url" and not item["investigable"] and item["internal"]),
        "executable_attachment": sum(1 for a in extracted.attachments if is_risky_name(a["filename"])),
        "qr_in_email": len(qr),
    }
    return [{"id": key, "count": count, "text": INDICATOR_TEXT[key]} for key, count in found.items() if count]


def _classified(text: str) -> dict[str, Any]:
    result = classify(text)
    result["internal"] = result["kind"] == "web_url" and not result["investigable"] and is_internal(text.strip())
    return result


def analyse(extracted: Extracted) -> dict[str, Any]:
    links = [
        {**_classified(link["url"]), "anchor_text": link["anchor_text"], "source": link["source"], "hidden": link["hidden"],
         "text_mismatch": text_mismatch(link["anchor_text"], link["url"])}
        for link in extracted.links
    ]
    qr = [{**_classified(item["text"]), "part": item["part"]} for item in extracted.qr_payloads]
    attachments = [{**a, "risky": is_risky_name(a["filename"])} for a in extracted.attachments]
    return {"links": links, "qr_payloads": qr, "attachments": attachments, "indicators": indicators(extracted, links, qr)}


class EmailStore:
    """Evidence on disk: the original upload (never served) and the extracted, classified
    facts. Same retention and caps as QR uploads."""

    def __init__(self, settings: Settings) -> None:
        self._root = Path(settings.data_dir) / "email"
        self._retention_s = settings.retention_days * 86400

    def save(self, original: bytes, extracted: Extracted, sandboxed: bool) -> dict[str, Any]:
        self._prune()
        email_id = secrets.token_urlsafe(16)
        directory = self._root / email_id
        directory.mkdir(parents=True, mode=0o700)
        (directory / "original.eml").write_bytes(original)
        meta = {
            "id": email_id,
            "created_at": time.time(),
            "sha256": hashlib.sha256(original).hexdigest(),
            "bytes": len(original),
            "extractor": "sandbox" if sandboxed else "dev_unsandboxed",
            "headers": extracted.headers,
            "auth": extracted.auth,
            "parts": extracted.parts,
            "truncated": extracted.truncated or extracted.links_truncated or extracted.attachments_truncated,
            **analyse(extracted),
        }
        (directory / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
        return meta

    def load(self, email_id: str) -> dict[str, Any] | None:
        if not is_valid_email_id(email_id):
            return None
        try:
            return json.loads((self._root / email_id / "meta.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def _prune(self) -> None:
        if not self._root.is_dir():
            return
        entries = sorted((p for p in self._root.iterdir() if p.is_dir()), key=lambda p: p.stat().st_mtime)
        cutoff = time.time() - self._retention_s
        excess = max(0, len(entries) - MAX_STORED_UPLOADS + 1)
        for index, entry in enumerate(entries):
            if index < excess or entry.stat().st_mtime < cutoff:
                shutil.rmtree(entry, ignore_errors=True)


def _public_item(index: int, item: dict[str, Any], extra: tuple[str, ...]) -> dict[str, Any]:
    return {
        "index": index,
        **{k: item[k] for k in ("display", "kind", "scheme", "investigable", "note", *extra)},
        "target": item["target"] if item["investigable"] else None,
    }


def public_view(meta: dict[str, Any]) -> dict[str, Any]:
    """What the browser sees. The stored targets are kept server side for matching."""
    headers = meta["headers"]
    return {
        **{k: meta[k] for k in ("id", "sha256", "bytes", "extractor", "auth", "parts", "truncated", "indicators")},
        "headers": {k: headers[k] for k in ("from", "from_address", "reply_to", "return_path", "to", "to_count", "subject", "date", "message_id", "received_count")},
        "links": [_public_item(i, link, ("anchor_text", "source", "hidden", "text_mismatch")) for i, link in enumerate(meta["links"])],
        "qr_payloads": [_public_item(i, item, ("part",)) for i, item in enumerate(meta["qr_payloads"])],
        "attachments": [{k: a[k] for k in ("filename", "content_type", "size", "sha256", "inline", "risky")} for a in meta["attachments"]],
    }


def email_origin(meta: dict[str, Any] | None, kind: str, value: str) -> dict[str, Any] | None:
    """The evidence link, only if this exact target came out of that email."""
    if meta is None:
        return None
    wanted = {"kind": kind, "value": value}
    candidates = [("link", i, item) for i, item in enumerate(meta.get("links", []))]
    candidates += [("qr", i, item) for i, item in enumerate(meta.get("qr_payloads", []))]
    for found_in, index, item in candidates:
        if item.get("investigable") and item.get("target") == wanted:
            headers = meta.get("headers", {})
            return {
                "event": "email_source",
                "email_id": meta["id"],
                "sha256": meta["sha256"],
                "extractor": meta["extractor"],
                "subject": str(headers.get("subject", ""))[:MAX_SUBJECT_IN_ORIGIN],
                "from": str(headers.get("from_address") or headers.get("from", ""))[:MAX_HEADER_CHARS],
                "found_in": found_in,
                "item_index": index,
                "link_display": item["display"],
                "link_kind": item["kind"],
                "anchor_text": item.get("anchor_text", ""),
                "qr_part": item.get("part", ""),
            }
    return None
