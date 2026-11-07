"""Extracts links, QR codes and attachment facts from one untrusted email file. Runs
inside a disposable sandbox with no network: the .eml arrives on stdin, one JSON object
leaves on stdout.

It never opens, resolves or contacts anything it finds, and never writes an attachment
anywhere. Attachments are hashed in memory; images among them are read for QR codes
with the same decoder as qr_decode.py.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import importlib.util
import json
import re
import signal
import sys
from html.parser import HTMLParser
from pathlib import Path

MAX_INPUT_BYTES = 5 * 1024 * 1024
MAX_PARTS = 200
MAX_DEPTH = 10
MAX_LINKS = 50
MAX_ATTACHMENTS = 30
MAX_TEXT_BYTES = 500 * 1024
MAX_IMAGES = 10
MAX_QR_PAYLOADS = 20
MAX_URL_CHARS = 4096
MAX_ANCHOR_CHARS = 300
MAX_HEADER_CHARS = 500
MAX_NAME_CHARS = 255
MAX_RECIPIENTS = 5
TIME_LIMIT_S = 10
AUTH_TOKENS = frozenset({"pass", "fail", "softfail", "none", "neutral", "temperror", "permerror"})
IMAGE_TYPES = {"image/png", "image/jpeg", "image/webp"}
# Only the first bytes decide whether an attachment is handed to the QR decoder.
IMAGE_MAGIC = (b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff")
_AUTH = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([A-Za-z]+)", re.IGNORECASE)
_RECEIVED_SPF = re.compile(r"^\s*([A-Za-z]+)")
_TEXT_URL = re.compile(
    r"(?:\b(?:https?|ftp|file)://|\b(?:javascript|data|vbscript|mailto|tel|sms|bitcoin):)[^\s<>\"'`]+",
    re.IGNORECASE,
)
_TRAILING = ".,;:!?)]}'\""
_SPACE = re.compile(r"\s+")


def reply(**data: object) -> None:
    sys.stdout.write(json.dumps(data, ensure_ascii=True) + "\n")
    sys.stdout.flush()


def fail(reason: str) -> None:
    reply(ok=False, error=reason)
    sys.exit(0)


def on_timeout(_signum: int, _frame: object) -> None:
    fail("extraction took too long")


def load_qr_decoder() -> object:
    """qr_decode.py sits next to this file. Loaded by path because `python -I` does not
    put the script's directory on sys.path."""
    path = Path(__file__).resolve().parent / "qr_decode.py"
    spec = importlib.util.spec_from_file_location("qr_decode", path)
    if spec is None or spec.loader is None:
        raise ImportError("qr_decode.py not found")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def clean(value: object, limit: int) -> str:
    return _SPACE.sub(" ", str(value or "")).strip()[:limit]


def trim_url(url: str) -> str:
    """Drops sentence punctuation after a URL in prose. A closing bracket stays when the
    URL opened one, as in javascript:alert(1)."""
    while url and url[-1] in _TRAILING:
        closer = url[-1]
        opener = {")": "(", "]": "[", "}": "{"}.get(closer)
        if opener and url.count(opener) >= url.count(closer):
            break
        url = url[:-1]
    return url


class LinkParser(HTMLParser):
    """Collects a/area hrefs with their visible text, and data: images. Never fetches."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str, bool]] = []
        self.data_images: list[str] = []
        self._open: list[tuple[str, list[str], bool]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name.lower(): value or "" for name, value in attrs}
        if tag == "img" and values.get("src", "").strip().lower().startswith("data:image/"):
            if len(self.data_images) < MAX_IMAGES:
                self.data_images.append(values["src"].strip())
        if tag not in ("a", "area") or "href" not in values:
            return
        style = values.get("style", "").replace(" ", "").lower()
        hidden = "hidden" in values or any(rule in style for rule in ("display:none", "visibility:hidden", "font-size:0", "opacity:0"))
        href = values["href"].strip()
        if tag == "area":
            self.links.append((href, values.get("alt", ""), hidden))
        else:
            # Anchors do not nest in HTML; a new one ends the last. This also keeps a
            # page of unclosed anchors from costing quadratic time.
            self._flush()
            self._open.append((href, [], hidden))

    def handle_data(self, data: str) -> None:
        for _href, text, _hidden in self._open:
            if sum(len(t) for t in text) < MAX_ANCHOR_CHARS * 2:
                text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a":
            self._flush()

    def _flush(self) -> None:
        while self._open:
            href, text, hidden = self._open.pop()
            self.links.append((href, "".join(text), hidden))

    def close(self) -> None:
        super().close()
        self._flush()


class Extraction:
    def __init__(self, qr: object) -> None:
        self.qr = qr
        self.links: dict[str, dict[str, object]] = {}
        self.links_truncated = False
        self.attachments: list[dict[str, object]] = []
        self.attachments_truncated = False
        self.qr_payloads: list[dict[str, str]] = []
        self.qr_seen: set[str] = set()
        self.images_read = 0
        self.parts = 0
        self.truncated = False
        self.text_budget = MAX_TEXT_BYTES

    def add_link(self, url: str, anchor: str, source: str, hidden: bool = False) -> None:
        url = url.strip()
        if not url or url.startswith("#"):
            return
        if len(url) > MAX_URL_CHARS:
            self.links_truncated = True
            return
        if url in self.links:
            # The same link in the HTML and the plain-text version: keep the HTML one,
            # because its anchor text is what the reader sees.
            if source == "html_href" and self.links[url]["source"] == "text":
                self.links[url] = {"url": url, "anchor_text": clean(anchor, MAX_ANCHOR_CHARS), "source": source, "hidden": hidden}
            return
        if len(self.links) >= MAX_LINKS:
            self.links_truncated = True
            return
        self.links[url] = {"url": url, "anchor_text": clean(anchor, MAX_ANCHOR_CHARS), "source": source, "hidden": hidden}

    def read_qr(self, data: bytes, label: str) -> None:
        if not data.startswith(IMAGE_MAGIC) and not (data[:4] == b"RIFF" and data[8:12] == b"WEBP"):
            return
        if self.images_read >= MAX_IMAGES:
            self.truncated = True
            return
        self.images_read += 1
        try:
            result = self.qr.decode_image(data, preview=False)
        except self.qr.DecodeError:
            return
        for text in result["payloads"]:
            if text in self.qr_seen:
                continue
            if len(self.qr_payloads) >= MAX_QR_PAYLOADS:
                self.truncated = True
                return
            self.qr_seen.add(text)
            self.qr_payloads.append({"text": text, "part": clean(label, MAX_NAME_CHARS)})

    def take_text(self, text: str) -> str:
        encoded = text.encode("utf-8", "replace")
        if len(encoded) > self.text_budget:
            self.truncated = True
            encoded = encoded[: self.text_budget]
        self.text_budget -= len(encoded)
        return encoded.decode("utf-8", "ignore")

    def walk(self, part: object, depth: int) -> None:
        if self.parts >= MAX_PARTS or depth > MAX_DEPTH:
            self.truncated = True
            return
        self.parts += 1
        if part.is_multipart():
            children = part.get_payload()
            for child in children if isinstance(children, list) else []:
                self.walk(child, depth + 1)
            return
        self.leaf(part)

    def leaf(self, part: object) -> None:
        ctype = part.get_content_type()
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        if ctype in ("text/plain", "text/html") and disposition != "attachment" and not filename:
            self.body_text(part, ctype)
            return
        try:
            data = part.get_payload(decode=True) or b""
        except Exception:
            data = b""
        if not isinstance(data, bytes):
            data = b""
        name = clean(filename, MAX_NAME_CHARS)
        inline = disposition == "inline" or part.get("Content-ID") is not None
        if len(self.attachments) < MAX_ATTACHMENTS:
            self.attachments.append({
                "filename": name,
                "content_type": clean(ctype, 127),
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "inline": inline,
            })
        else:
            self.attachments_truncated = True
        label = f"{'inline image' if inline else 'attachment'} {name}".strip() if name else ("inline image" if inline else "attachment")
        if ctype in IMAGE_TYPES or data[:12].startswith(IMAGE_MAGIC) or data[8:12] == b"WEBP":
            self.read_qr(data, label)

    def body_text(self, part: object, ctype: str) -> None:
        try:
            text = part.get_content()
        except Exception:
            raw = part.get_payload(decode=True)
            text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else ""
        if not isinstance(text, str) or self.text_budget <= 0:
            if self.text_budget <= 0:
                self.truncated = True
            return
        text = self.take_text(text)
        if ctype == "text/html":
            parser = LinkParser()
            try:
                parser.feed(text)
                parser.close()
            except Exception:
                pass
            for href, anchor, hidden in parser.links:
                self.add_link(href, anchor, "html_href", hidden)
            for index, src in enumerate(parser.data_images, 1):
                self.read_data_image(src, index)
        else:
            for match in _TEXT_URL.finditer(text):
                self.add_link(trim_url(match.group(0)), "", "text")

    def read_data_image(self, src: str, index: int) -> None:
        head, _, body = src.partition(",")
        if ";base64" not in head.lower() or len(body) > MAX_INPUT_BYTES * 2:
            return
        try:
            data = base64.b64decode(body, validate=False)
        except (binascii.Error, ValueError):
            return
        self.read_qr(data, f"embedded image {index}")


def header(message: object, name: str) -> str:
    try:
        value = message.get(name)
    except Exception:
        return ""
    return clean(value, MAX_HEADER_CHARS) if value is not None else ""


def first_address(message: object, name: str) -> tuple[str, str]:
    """The first address in a header, and its domain in lower case. Display names are
    not trusted, so only the address part is used."""
    try:
        value = message.get(name)
        addresses = getattr(value, "addresses", ()) if value is not None else ()
    except Exception:
        return "", ""
    for address in addresses:
        domain = clean(getattr(address, "domain", ""), 253).lower().rstrip(".")
        spec = clean(getattr(address, "addr_spec", ""), MAX_HEADER_CHARS)
        if spec:
            return spec, domain
    return "", ""


def recipients(message: object) -> tuple[list[str], int]:
    try:
        value = message.get("To")
        addresses = list(getattr(value, "addresses", ())) if value is not None else []
    except Exception:
        return [], 0
    shown = [clean(a.addr_spec, MAX_HEADER_CHARS) for a in addresses[:MAX_RECIPIENTS]]
    return [s for s in shown if s], len(addresses)


def auth_results(message: object) -> dict[str, str]:
    """Tokens as the headers claim them. Nothing here is verified; a sender can write
    these headers too, unless the receiving server replaced them."""
    found: dict[str, str] = {}
    try:
        values = [str(v) for v in message.get_all("Authentication-Results") or []]
        spf_headers = [str(v) for v in message.get_all("Received-SPF") or []]
    except Exception:
        values, spf_headers = [], []
    for value in values:
        for method, result in _AUTH.findall(value):
            found.setdefault(method.lower(), result.lower())
    if "spf" not in found and spf_headers:
        match = _RECEIVED_SPF.match(spf_headers[0])
        if match:
            found["spf"] = match.group(1).lower()
    return {key: (found[key] if found.get(key) in AUTH_TOKENS else "unknown") for key in ("spf", "dkim", "dmarc")}


def extract(data: bytes) -> dict[str, object]:
    from email import policy
    from email.parser import BytesParser

    try:
        message = BytesParser(policy=policy.default).parsebytes(data)
    except RecursionError:
        fail("email nested too deeply")
    except Exception:
        fail("not a readable email")

    known = ("From", "To", "Subject", "Date", "Message-ID", "Received", "Return-Path", "MIME-Version")
    if not any(name in message for name in known):
        fail("not an email")

    qr = load_qr_decoder()
    work = Extraction(qr)
    try:
        work.walk(message, 0)
    except RecursionError:
        fail("email nested too deeply")

    from_address, from_domain = first_address(message, "From")
    reply_to, reply_to_domain = first_address(message, "Reply-To")
    to, to_count = recipients(message)
    try:
        received = len(message.get_all("Received") or [])
    except Exception:
        received = 0
    return {
        "headers": {
            "from": header(message, "From"),
            "from_address": from_address,
            "from_domain": from_domain,
            "reply_to": reply_to,
            "reply_to_domain": reply_to_domain,
            "return_path": header(message, "Return-Path"),
            "to": to,
            "to_count": to_count,
            "subject": header(message, "Subject"),
            "date": header(message, "Date"),
            "message_id": header(message, "Message-ID"),
            "received_count": received,
        },
        "auth": auth_results(message),
        "links": list(work.links.values()),
        "links_truncated": work.links_truncated,
        "attachments": work.attachments,
        "attachments_truncated": work.attachments_truncated,
        "qr_payloads": work.qr_payloads,
        "parts": work.parts,
        "truncated": work.truncated,
    }


def main() -> None:
    signal.signal(signal.SIGALRM, on_timeout)
    signal.alarm(TIME_LIMIT_S)

    data = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(data) > MAX_INPUT_BYTES:
        fail("email too large")
    if not data:
        fail("empty upload")
    try:
        result = extract(data)
    except RecursionError:
        fail("email nested too deeply")
    except Exception:
        fail("not a readable email")
    reply(ok=True, **result)


if __name__ == "__main__":
    main()
