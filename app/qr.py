"""QR input adapter. A QR code is one more way to submit a URL: it is decoded in a
disposable sandbox, shown to the user, and investigated only on an explicit request
through the normal scan pipeline. Nothing here contacts a decoded payload.

The trusted process never parses the uploaded image. It counts bytes, checks the file
signature, and stores the original as evidence. The decoder, and the preview the app
serves, both come from a network-disabled container.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import sys
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

from app.config import PROJECT_ROOT, Settings
from app.models import FIXTURE_NAMES
from app.sandbox import SANDBOX_LABEL, _DockerClient, decoder_runtime_args, owner_label
from app.urlpolicy import UrlPolicyError, check_url_syntax

logger = logging.getLogger(__name__)

MAX_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_DECODER_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_PREVIEW_BYTES = 2 * 1024 * 1024
MAX_CODES = 5
MAX_PAYLOAD_CHARS = 4096
DECODE_TIMEOUT_S = 20.0
MAX_STORED_UPLOADS = 500
DECODER_SCRIPT = "/worker/qr_decode.py"
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
FIXTURE_HOST = "fixtures.invalid"
_QR_ID = re.compile(r"^[A-Za-z0-9_-]{22}$")

# Matched on the file's first bytes only. Anything else is refused before decoding.
_SIGNATURES = {
    "png": lambda b: b.startswith(PNG_MAGIC),
    "jpeg": lambda b: b.startswith(b"\xff\xd8\xff"),
    "webp": lambda b: len(b) >= 12 and b[:4] == b"RIFF" and b[8:12] == b"WEBP",
}
CONTENT_TYPES = {"image/png": "png", "image/jpeg": "jpeg", "image/webp": "webp"}

DANGEROUS_SCHEMES = frozenset({"javascript", "data", "file", "vbscript", "blob", "about", "chrome", "intent", "jar", "view-source", "filesystem"})
PAYMENT_SCHEMES = frozenset({"bitcoin", "ethereum", "litecoin", "lightning", "upi", "paypal", "venmo", "cashapp", "solana"})
OTHER_KNOWN = {"mailto": "Email address", "tel": "Phone number", "sms": "Text message", "smsto": "Text message", "geo": "Map location", "begin": "Contact card", "mecard": "Contact card", "matmsg": "Email message"}
SHORTENERS = frozenset({"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "s.id", "qrco.de", "qr.codes"})
_SCHEME = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]{0,31}):")


class QrError(Exception):
    """A refusal that is safe to show the user."""


def sniff_format(data: bytes) -> str | None:
    for name, matches in _SIGNATURES.items():
        if matches(data):
            return name
    return None


def is_valid_qr_id(value: str) -> bool:
    return bool(_QR_ID.fullmatch(value))


def redact(text: str) -> str:
    """Hides secrets a payload carries in the clear. Wi-Fi codes include the password."""
    if text[:5].upper() == "WIFI:":
        return re.sub(r"(?i)(?<=[:;])P:(?:\\.|[^;])*", "P:[hidden]", text)
    return text


def classify(text: str) -> dict[str, Any]:
    """What a payload is, and whether the scan pipeline may receive it. No network use."""
    display = redact(text)[:MAX_PAYLOAD_CHARS]
    result: dict[str, Any] = {"display": display, "scheme": None, "investigable": False, "target": None, "note": None}
    stripped = text.strip()
    if stripped[:4] == "BCD\n" or stripped[:5] == "BCD\r\n":
        return {**result, "kind": "payment_request", "note": "A bank transfer request (EPC QR). Not a web destination; never paid or opened."}
    if stripped[:5].upper() == "WIFI:":
        return {**result, "kind": "wifi_config", "note": "Wi-Fi network details. Not a web destination. The password is hidden."}
    match = _SCHEME.match(stripped)
    if match is None:
        return {**result, "kind": "text", "note": "Plain text. Nothing to investigate, and not treated as malicious."}
    scheme = match.group(1).lower()
    result["scheme"] = scheme
    if scheme in ("http", "https"):
        return _classify_web(stripped, result)
    if scheme in DANGEROUS_SCHEMES:
        return {**result, "kind": "dangerous_uri", "note": f"A {scheme}: link can run code or read local data. It is never opened."}
    if scheme in PAYMENT_SCHEMES:
        return {**result, "kind": "payment_request", "note": "A payment request. Not a web destination; never paid or opened."}
    label = OTHER_KNOWN.get(scheme, "Another kind of link")
    return {**result, "kind": "other_uri", "note": f"{label}. Not a web destination, so it is not investigated."}


def _classify_web(url: str, result: dict[str, Any]) -> dict[str, Any]:
    parts = urlsplit(url)
    if parts.scheme == "http" and parts.hostname == FIXTURE_HOST and parts.path.strip("/") in FIXTURE_NAMES:
        name = parts.path.strip("/")
        return {**result, "kind": "test_page", "investigable": True, "target": {"kind": "fixture", "value": name},
                "note": "A built-in test page. It runs in the sandbox like any other link."}
    try:
        checked = check_url_syntax(url)
    except UrlPolicyError as exc:
        return {**result, "kind": "web_url", "note": f"Refused: {exc}"}
    note = "A web link. It is investigated only if you ask, and is checked again then."
    if checked.host in SHORTENERS:
        note = "A link shortener: the real destination is unknown until investigated."
    return {**result, "kind": "web_url", "investigable": True, "target": {"kind": "url", "value": checked.url}, "note": note}


@dataclass(frozen=True)
class Decoded:
    format: str
    width: int
    height: int
    codes_found: int
    payloads: list[str]
    truncated: bool
    preview_png: bytes


class QrDecoder(Protocol):
    sandboxed: bool

    async def decode(self, data: bytes) -> Decoded:
        """Raises QrError with a user-safe message."""
        ...


def parse_decoder_output(stdout: bytes) -> Decoded:
    """The decoder is treated as hostile: its whole reply is validated before use."""
    if len(stdout) > MAX_DECODER_OUTPUT_BYTES:
        raise QrError("The decoder returned too much data.")
    try:
        reply = json.loads(stdout.decode("utf-8").strip().splitlines()[-1])
    except (ValueError, IndexError, UnicodeDecodeError):
        raise QrError("The image could not be decoded.") from None
    if not isinstance(reply, dict):
        raise QrError("The image could not be decoded.")
    if reply.get("ok") is not True:
        error = reply.get("error")
        messages = {"image too large": "The image is too large.", "image dimensions too large": "The image is too large: at most 4096 by 4096 pixels.",
                    "not a PNG, JPEG or WebP image": "Only PNG, JPEG and WebP images are accepted.", "decoding took too long": "Decoding took too long.",
                    "empty upload": "The upload was empty."}
        raise QrError(messages.get(error, "That file is not a readable image."))
    payloads = reply.get("payloads")
    fields_ok = (
        reply.get("format") in ("png", "jpeg", "webp")
        and all(isinstance(reply.get(k), int) and 0 <= reply[k] <= 100_000 for k in ("width", "height", "codes_found"))
        and isinstance(payloads, list) and len(payloads) <= MAX_CODES
        and all(isinstance(p, str) and len(p) <= MAX_PAYLOAD_CHARS for p in payloads)
        and isinstance(reply.get("preview_png_b64"), str)
    )
    if not fields_ok:
        raise QrError("The image could not be decoded.")
    try:
        preview = base64.b64decode(reply["preview_png_b64"], validate=True)
    except (binascii.Error, ValueError):
        raise QrError("The image could not be decoded.") from None
    if not preview.startswith(PNG_MAGIC) or len(preview) > MAX_PREVIEW_BYTES:
        raise QrError("The image could not be decoded.")
    return Decoded(reply["format"], reply["width"], reply["height"], reply["codes_found"], payloads, bool(reply.get("truncated")), preview)


def build_decoder_argv(name: str, settings: Settings) -> list[str]:
    """No network at all, a smaller box than a scan, and the image only on stdin."""
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
    return [*argv, settings.image, "python", DECODER_SCRIPT]


class DockerQrDecoder:
    sandboxed = True

    def __init__(self, settings: Settings, max_concurrent: int = 2) -> None:
        self._settings = settings
        self._client = _DockerClient(settings)
        self._slots = asyncio.Semaphore(max_concurrent)

    async def decode(self, data: bytes) -> Decoded:
        if self._slots.locked():
            raise QrError("The decoder is busy. Try again in a moment.")
        async with self._slots:
            name = f"ld-qr-{secrets.token_hex(8)}"
            argv = build_decoder_argv(name, self._settings)
            stdout = await self._run(argv, data, name)
        return parse_decoder_output(stdout)

    async def _run(self, argv: list[str], data: bytes, name: str) -> bytes:
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL, env=self._client.env,
            )
        except OSError:
            raise QrError("The decoder could not start.") from None
        try:
            async with asyncio.timeout(DECODE_TIMEOUT_S):
                stdout, _ = await proc.communicate(input=data)
        except TimeoutError:
            raise QrError("Decoding took too long.") from None
        finally:
            if proc.returncode is None:
                with suppress(ProcessLookupError):
                    proc.kill()
            await self._client.command("rm", "-f", name)
        return stdout


class LocalQrDecoder:
    """Dev only: runs the decoder script as a plain subprocess, with no sandbox."""

    sandboxed = False

    def __init__(self, settings: Settings) -> None:
        self._python = settings.python_bin
        self._script = str(PROJECT_ROOT / "worker" / "qr_decode.py")

    async def decode(self, data: bytes) -> Decoded:
        proc = await asyncio.create_subprocess_exec(
            self._python, "-I", self._script, stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL, env={"PATH": os.environ.get("PATH", "")},
        )
        try:
            async with asyncio.timeout(DECODE_TIMEOUT_S):
                stdout, _ = await proc.communicate(input=data)
        except TimeoutError:
            with suppress(ProcessLookupError):
                proc.kill()
            raise QrError("Decoding took too long.") from None
        return parse_decoder_output(stdout)


def build_decoder(settings: Settings) -> QrDecoder:
    return LocalQrDecoder(settings) if settings.dev_local_runner else DockerQrDecoder(settings)


class QrStore:
    """Evidence on disk: the original upload (never served), the sandbox-drawn preview,
    and the decoded, classified payloads. Same retention as scans."""

    def __init__(self, settings: Settings) -> None:
        self._root = Path(settings.data_dir) / "qr"
        self._retention_s = settings.retention_days * 86400

    def save(self, original: bytes, decoded: Decoded, sandboxed: bool) -> dict[str, Any]:
        self._prune()
        qr_id = secrets.token_urlsafe(16)
        directory = self._root / qr_id
        directory.mkdir(parents=True, mode=0o700)
        (directory / "original.bin").write_bytes(original)
        (directory / "preview.png").write_bytes(decoded.preview_png)
        meta = {
            "id": qr_id,
            "created_at": time.time(),
            "sha256": hashlib.sha256(original).hexdigest(),
            "bytes": len(original),
            "format": decoded.format,
            "width": decoded.width,
            "height": decoded.height,
            "codes_found": decoded.codes_found,
            "truncated": decoded.truncated,
            "decoder": "sandbox" if sandboxed else "dev_unsandboxed",
            "payloads": [classify(text) for text in decoded.payloads],
            "preview_url": f"/api/qr/{qr_id}/preview.png",
        }
        (directory / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
        return meta

    def load(self, qr_id: str) -> dict[str, Any] | None:
        if not is_valid_qr_id(qr_id):
            return None
        try:
            return json.loads((self._root / qr_id / "meta.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def preview(self, qr_id: str) -> bytes | None:
        if not is_valid_qr_id(qr_id):
            return None
        try:
            data = (self._root / qr_id / "preview.png").read_bytes()
        except OSError:
            return None
        return data if data.startswith(PNG_MAGIC) else None

    def _prune(self) -> None:
        if not self._root.is_dir():
            return
        entries = sorted((p for p in self._root.iterdir() if p.is_dir()), key=lambda p: p.stat().st_mtime)
        cutoff = time.time() - self._retention_s
        excess = max(0, len(entries) - MAX_STORED_UPLOADS + 1)
        for index, entry in enumerate(entries):
            if index < excess or entry.stat().st_mtime < cutoff:
                shutil.rmtree(entry, ignore_errors=True)


def public_view(meta: dict[str, Any]) -> dict[str, Any]:
    """What the browser sees. The stored target is kept server side for matching."""
    return {
        **{k: meta[k] for k in ("id", "sha256", "format", "width", "height", "codes_found", "truncated", "decoder", "preview_url")},
        "payloads": [
            {"index": i, **{k: p[k] for k in ("display", "kind", "scheme", "investigable", "note")},
             "target": p["target"] if p["investigable"] else None}
            for i, p in enumerate(meta["payloads"])
        ],
    }
