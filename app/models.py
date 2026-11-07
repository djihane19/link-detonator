"""Event envelope, API models and validation of hostile worker output.

Anything the worker prints is attacker-influenced. `decode_worker_line` is the
only way worker bytes become event data: it accepts known types only, keeps only
declared fields and truncates every string. Envelope fields a worker may claim
(`v`, `seq`, `ts`, `source`) are never read.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    ValidationError,
    model_validator,
)

ENVELOPE_VERSION = 1

FIXTURE_NAMES: tuple[str, ...] = (
    "benign",
    "phish-login",
    "hostile-injection",
    "hostile-download",
    "hostile-ssrf",
    "hostile-freeze",
    "hostile-memory",
    "hostile-gauntlet",
    "lab-direct-injection",
    "lab-indirect-injection",
    "lab-credential-harvest",
    "lab-local-file",
    "lab-internal-service",
    "lab-unauthorized-nav",
    "lab-malicious-redirect",
    "lab-suspicious-download",
    "lab-prompt-disclosure",
    "lab-benign-article",
    "lab-benign-contact",
)

HOST_EVENT_TYPES: frozenset[str] = frozenset(
    {
        "sandbox_created",
        "secret_audit",
        "deadline_killed",
        "output_limit_killed",
        "output_dropped",
        "sandbox_exit",
        "sandbox_removed",
        "scan_error",
        "scan_finished",
        "verdict",
        "qr_source",
        "email_source",
    }
)

EventSource = Literal["worker", "host"]
RowStatus = Literal["contained", "observed", "not_observed", "clear", "failed", "not_applicable"]

MAX_SUBMITTED_URL_CHARS = 2048

# String caps. A truncated value is kept; only an invalid shape drops the event.
MAX_URL_CHARS = 4096
MAX_SHORT_CHARS = 64
MAX_TEXT_CHARS = 4096
MAX_VISIBLE_TEXT_CHARS = 20_000
MAX_CONCEALED_ITEMS = 500
MAX_FORM_FIELDS = 200

# The worker enforces these too. The host re-enforces them because it cannot trust it.
WORKER_EVENT_CAPS: dict[str, int] = {"request": 500, "screenshot": 25, "response": 200}

_JPEG_MAGIC = b"\xff\xd8\xff"
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean_text(value: str, max_chars: int) -> str:
    """Truncates text and makes it safe to store and serialize.

    JSON escapes can produce lone surrogates, which would raise later when the
    string is encoded for persistence or SSE, so they are replaced here.
    """
    truncated = value[:max_chars]
    encodable = truncated.encode("utf-8", "replace").decode("utf-8")
    return _CONTROL_CHARS.sub("", encodable)


def _text_cap(max_chars: int) -> BeforeValidator:
    def clean(value: object) -> object:
        return clean_text(value, max_chars) if isinstance(value, str) else value

    return BeforeValidator(clean)


def _list_cap(max_items: int) -> BeforeValidator:
    def cap(value: object) -> object:
        return value[:max_items] if isinstance(value, list) else value

    return BeforeValidator(cap)


UrlText = Annotated[str, _text_cap(MAX_URL_CHARS)]
ShortText = Annotated[str, _text_cap(MAX_SHORT_CHARS)]
Text = Annotated[str, _text_cap(MAX_TEXT_CHARS)]


def _validate_jpeg_b64(value: object) -> object:
    if not isinstance(value, str):
        return value
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("not valid base64") from exc
    if not decoded.startswith(_JPEG_MAGIC):
        raise ValueError("not a JPEG")
    return value


class _WorkerData(BaseModel):
    # strict: "200" is not a status and true is not a number.
    # extra=ignore: anything undeclared, including spoofed envelope fields, vanishes.
    model_config = ConfigDict(strict=True, extra="ignore")


class WorkerStartedData(_WorkerData):
    url: UrlText
    mode: Literal["live", "fixture"]
    offline: bool


class NavigationData(_WorkerData):
    url: UrlText
    status: Annotated[int, Field(ge=0, le=999)] | None
    redirected_from: UrlText | None


class ResponseData(_WorkerData):
    """An answer from a non-public destination, judged by URL or by the connected address."""

    url: UrlText
    status: Annotated[int, Field(ge=0, le=999)]
    peer_ip: ShortText | None


class ScreenshotData(_WorkerData):
    label: ShortText
    mime: Literal["image/jpeg"]
    b64: Annotated[str, BeforeValidator(_validate_jpeg_b64)]


class RequestData(_WorkerData):
    url: UrlText
    method: ShortText
    resource_type: ShortText


class RequestFailedData(_WorkerData):
    url: UrlText
    error: Text
    resource_type: ShortText
    blocked_locally: bool


class DownloadAttemptData(_WorkerData):
    url: UrlText
    suggested_filename: Text


class DialogData(_WorkerData):
    dialog_type: ShortText
    message: Text


class PopupData(_WorkerData):
    url: UrlText


class FormData(_WorkerData):
    action: UrlText
    method: ShortText
    has_password: bool
    field_names: Annotated[list[Text], _list_cap(MAX_FORM_FIELDS)]


class ConcealedItem(_WorkerData):
    source: Literal[
        "hidden_css",
        "offscreen",
        "tiny_text",
        "same_color",
        "comment",
        "meta",
        "aria_label",
        "alt",
    ]
    text: Text
    selector: Text


class TextLayersData(_WorkerData):
    visible_text: Annotated[str, _text_cap(MAX_VISIBLE_TEXT_CHARS)]
    concealed: Annotated[list[ConcealedItem], _list_cap(MAX_CONCEALED_ITEMS)]


class PageUnresponsiveData(_WorkerData):
    operation: ShortText
    timeout_ms: Annotated[int, Field(ge=0, le=3_600_000)]


class PageCrashData(_WorkerData):
    pass


def _clean_omitted(value: object) -> dict[str, int]:
    """Keeps only positive counts for known event types, so a hostile map stays bounded."""
    if not isinstance(value, dict):
        return {}
    return {
        key: count
        for key, count in value.items()
        if key in WORKER_EVENT_MODELS and type(count) is int and count > 0
    }


class WorkerFinishedData(_WorkerData):
    status: Literal["ok", "error", "partial"]
    error: Text | None
    # What the worker's own caps held back: "cap 500, then count".
    omitted: Annotated[dict[str, int], BeforeValidator(_clean_omitted)] = Field(default_factory=dict)
    # The worker stopped recording requests during a flood, so `omitted` is a lower bound.
    tracking_shed: bool = False
    # The worker's own time limit ended the scan, not the page finishing.
    deadline_reached: bool = False


WORKER_EVENT_MODELS: dict[str, type[_WorkerData]] = {
    "worker_started": WorkerStartedData,
    "navigation": NavigationData,
    "response": ResponseData,
    "screenshot": ScreenshotData,
    "request": RequestData,
    "request_failed": RequestFailedData,
    "download_attempt": DownloadAttemptData,
    "dialog": DialogData,
    "popup": PopupData,
    "form": FormData,
    "text_layers": TextLayersData,
    "page_unresponsive": PageUnresponsiveData,
    "page_crash": PageCrashData,
    "worker_finished": WorkerFinishedData,
}


def validate_worker_event(event_type: str, data: object) -> dict[str, Any] | None:
    """Returns clean data for a known worker event, or None to drop it."""
    model = WORKER_EVENT_MODELS.get(event_type)
    if model is None or not isinstance(data, dict):
        return None
    try:
        # exclude_unset: optional fields the worker did not send stay absent.
        return model.model_validate(data).model_dump(exclude_unset=True)
    except (ValidationError, ValueError, UnicodeError):
        return None


def _reject_constant(name: str) -> None:
    raise ValueError(f"non-finite JSON constant {name}")


def decode_worker_line(line: bytes) -> tuple[str, dict[str, Any]] | None:
    """Parses one line of worker stdout. Returns (type, data), or None to drop it."""
    try:
        # Decoding first stops json.loads from auto-detecting UTF-16 or UTF-32.
        parsed = json.loads(line.decode("utf-8"), parse_constant=_reject_constant)
    # RecursionError: deeply nested input such as '[[[[...' is a cheap way to raise it.
    except (ValueError, RecursionError):
        return None
    if not isinstance(parsed, dict):
        return None
    event_type = parsed.get("type")
    if not isinstance(event_type, str):
        return None
    data = validate_worker_event(event_type, parsed.get("data", {}))
    if data is None:
        return None
    return event_type, data


class EventEnvelope(BaseModel):
    """One stored event. `seq`, `ts` and `source` are always assigned by the host."""

    v: Literal[1] = ENVELOPE_VERSION
    seq: int
    ts: float
    source: EventSource
    type: str
    data: dict[str, Any] = Field(default_factory=dict)


class ScanTarget(BaseModel):
    """What a scan opens. A URL here must already have passed app.urlpolicy."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: Literal["url", "fixture"]
    value: str

    @model_validator(mode="after")
    def _check_value(self) -> ScanTarget:
        if self.kind == "fixture":
            if self.value not in FIXTURE_NAMES:
                raise ValueError("unknown fixture")
        elif not _looks_like_submitted_url(self.value):
            raise ValueError("not an http or https URL")
        return self


def _looks_like_submitted_url(value: str) -> bool:
    # The value becomes a worker argv entry, so it must not be able to pose as a flag.
    return (
        len(value) <= MAX_SUBMITTED_URL_CHARS
        and value.startswith(("http://", "https://"))
        and not any(char.isspace() or char < " " or char == "\x7f" for char in value)
    )


class ScanRequest(BaseModel):
    """Body of POST /api/scans: exactly one of `url` or `fixture`."""

    model_config = ConfigDict(extra="forbid")

    url: str | None = None
    fixture: str | None = None
    access_code: str | None = None
    # Set when the target was decoded from a QR upload; links the scan to that evidence.
    qr_id: str | None = None
    # Set when the target was a link or QR code found in an email upload.
    email_id: str | None = None

    @model_validator(mode="after")
    def _exactly_one(self) -> ScanRequest:
        if (self.url is None) == (self.fixture is None):
            raise ValueError("provide exactly one of url or fixture")
        return self


class ScanAccepted(BaseModel):
    id: str
    report_url: str


class BlastRadiusRow(BaseModel):
    id: str
    label: str
    status: RowStatus
    detail: str
    evidence_seqs: list[int]
    # "host", "worker", "both", or None when the row has no evidence.
    source: str | None


class ScanSnapshot(BaseModel):
    """Body of GET /api/scans/{id}."""

    id: str
    status: str
    target: ScanTarget
    events: list[dict[str, Any]]
    blast_radius: list[BlastRadiusRow]
    verdict: dict[str, Any] | None = None
