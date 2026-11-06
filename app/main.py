"""FastAPI orchestrator: routes, security headers and static pages."""

from __future__ import annotations

import asyncio
import hmac
import ipaddress
import json
import logging
from collections import Counter
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.config import PROJECT_ROOT, Settings
from app.agent.engine import build_engine
from app.models import FIXTURE_NAMES, ScanAccepted, ScanRequest, ScanTarget
from app.ratelimit import DAY_S, RateDecision, SlidingWindowLimiter, client_key
from app.sandbox import SandboxRunner, build_runner, is_loopback_host
from app.scans import (
    QueueFullError,
    ReadersBusyError,
    ScanManager,
    StreamBatch,
    is_valid_scan_id,
    parse_last_event_id,
    parse_seq,
)
from app.urlpolicy import Resolver, ResolverBusy, UrlPolicyError, validate_url
from app.verdict import VerdictEngine

logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).resolve().parent / "static"

CONTENT_SECURITY_POLICY = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)
SECURITY_HEADERS: tuple[tuple[bytes, bytes], ...] = (
    (b"content-security-policy", CONTENT_SECURITY_POLICY.encode()),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
)

MAX_BODY_BYTES = 16 * 1024
# Refused URLs do not use up scan quota, so a typo is not punished. They still cost a
# DNS lookup, so attempts have their own, wider limit.
ATTEMPT_LIMIT_FACTOR = 6
MAX_OPEN_STREAMS = 256
MAX_LOOKUPS_PER_CLIENT = 2
READ_HOUR_FACTOR = 30
GLOBAL_BUDGET_KEY = "global"
RUNNER_MARKER = 'data-runner="unknown"'

FIXTURE_CATALOG: dict[str, dict[str, str]] = {
    "lab-direct-injection": {
        "title": "Lab: direct injection",
        "description": "Benchmark page. Larkspur rate update.",
    },
    "lab-indirect-injection": {
        "title": "Lab: indirect injection",
        "description": "Benchmark page. Larkspur customer reviews.",
    },
    "lab-credential-harvest": {
        "title": "Lab: credential harvest",
        "description": "Benchmark page. Larkspur Bank sign in.",
    },
    "lab-local-file": {
        "title": "Lab: local file",
        "description": "Benchmark page. Larkspur support tool.",
    },
    "lab-internal-service": {
        "title": "Lab: internal service",
        "description": "Benchmark page. Larkspur status.",
    },
    "lab-unauthorized-nav": {
        "title": "Lab: unauthorized nav",
        "description": "Benchmark page. Larkspur offers.",
    },
    "lab-malicious-redirect": {
        "title": "Lab: malicious redirect",
        "description": "Benchmark page. Larkspur Bank sign in.",
    },
    "lab-suspicious-download": {
        "title": "Lab: suspicious download",
        "description": "Benchmark page. Larkspur security update.",
    },
    "lab-prompt-disclosure": {
        "title": "Lab: prompt disclosure",
        "description": "Benchmark page. Larkspur help.",
    },
    "lab-benign-article": {
        "title": "Lab: benign article",
        "description": "Benchmark page. Understanding prompt injection.",
    },
    "lab-benign-contact": {
        "title": "Lab: benign contact",
        "description": "Benchmark page. Larkspur contact us.",
    },
    "benign": {
        "title": "Benign control",
        "description": "An ordinary page. Shows what a quiet scan looks like.",
    },
    "phish-login": {
        "title": "Phish login",
        "description": "A redirect, then a fake login page for a fictional bank.",
    },
    "hostile-injection": {
        "title": "Hidden instructions",
        "description": "Instructions concealed from people in every place a page can hide text.",
    },
    "hostile-download": {
        "title": "Forced download",
        "description": "Tries to push a harmless text file at the browser.",
    },
    "hostile-ssrf": {
        "title": "Private network run",
        "description": "Tries to reach cloud metadata, private ranges and loopback.",
    },
    "hostile-freeze": {
        "title": "Frozen tab",
        "description": "Locks the page in an endless loop after a short delay.",
    },
    "hostile-memory": {
        "title": "Memory balloon",
        "description": "Allocates memory in a bounded loop to press against the limit.",
    },
    "hostile-gauntlet": {
        "title": "The Gauntlet",
        "description": "Most hostile tricks on one page. The memory limit has its own test charge.",
    },
}


class SecurityHeadersMiddleware:
    """Pure ASGI, so SSE is not buffered.

    Unhandled exceptions are answered here too: Starlette's own 500 response is
    produced outside user middleware and would otherwise lack these headers.
    """

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        started = False
        no_store = _is_private_path(scope.get("path", ""))

        async def send_with_headers(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                message["headers"] = _with_security_headers(message.get("headers", []), no_store)
            await send(message)

        try:
            await self._app(scope, receive, send_with_headers)
        except Exception:
            logger.exception("unhandled error serving a request")
            if started:
                raise
            await _send_plain_500(send_with_headers)


def _is_private_path(path: str) -> bool:
    return path.startswith(("/api/", "/r/"))


def _with_security_headers(
    headers: list[tuple[bytes, bytes]], no_store: bool
) -> list[tuple[bytes, bytes]]:
    names = {name.lower() for name, _ in headers}
    merged = list(headers) + [item for item in SECURITY_HEADERS if item[0] not in names]
    if no_store and b"cache-control" not in names:
        merged.append((b"cache-control", b"no-store"))
    return merged


async def _send_plain_500(send: Send) -> None:
    body = b'{"detail":"Internal server error."}'
    await send(
        {
            "type": "http.response.start",
            "status": 500,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


def create_app(
    settings: Settings | None = None,
    runner: SandboxRunner | None = None,
    resolver: Resolver | None = None,
    verdict_engine: VerdictEngine | None = None,
) -> FastAPI:
    active_settings = settings or Settings.from_env()
    active_runner = runner or build_runner(active_settings)
    engine = verdict_engine or build_engine(active_runner, active_settings.data_dir)
    manager = ScanManager(active_settings, active_runner, engine)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        await manager.start()
        try:
            yield
        finally:
            await manager.stop()

    # The stock docs pages load from a CDN, which the CSP forbids, so they stay off.
    app = FastAPI(
        title="Link Detonator",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        redirect_slashes=False,
        lifespan=lifespan,
    )
    app.add_middleware(SecurityHeadersMiddleware)
    app.state.manager = manager
    app.state.settings = active_settings

    dev_runner = not active_runner.isolated
    _register_api(app, manager, active_settings, resolver, dev_runner)
    _register_pages(app, manager, dev_runner)
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app


class _CountedStream(StreamingResponse):
    """Gives its stream slot back however the response ends, including before it starts."""

    def __init__(self, content: AsyncIterator[str], release: Callable[[], None], **kwargs: Any) -> None:
        super().__init__(content, **kwargs)
        self._release = release

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            self._release()


def _refusal(status: int, detail: str, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse({"detail": detail}, status_code=status, headers=headers)


def _arrived_on_loopback(request: Request) -> bool:
    """LD_BIND_HOST is only a claim; this is the address the connection really reached.

    A name is not a socket address (an in-process test client), so only IPs are judged.
    """
    server = request.scope.get("server")
    host = server[0] if server else ""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return True
    return is_loopback_host(host)


def _rate_limited(decision: RateDecision) -> JSONResponse:
    return _refusal(
        429,
        "Too many scans from this client. Try again shortly.",
        {"Retry-After": str(max(decision.retry_after_s, 1))},
    )


def _budget_spent(decision: RateDecision) -> JSONResponse:
    return _refusal(
        429,
        "This deployment has used its scan budget for now. Try again later.",
        {"Retry-After": str(max(decision.retry_after_s, 1))},
    )


def _code_matches(supplied: str, expected: str) -> bool:
    return hmac.compare_digest(supplied.encode("utf-8", "replace"), expected.encode("utf-8", "replace"))


def _live_scan_refusal(settings: Settings, has_code: bool) -> str | None:
    """Why a live URL may not be scanned here. Live scans run a stranger's JavaScript from
    this VM's address, so they stay off until the operator chooses who may start them."""
    if not settings.live_scans_enabled:
        return "Live URL scans are switched off on this deployment. Test charges still work."
    if settings.live_access_code() is None:
        return "Live URL scans are not enabled on this deployment. Test charges still work."
    if not has_code:
        return "Live URL scans need an access code. Test charges do not."
    return None


async def _read_limited_body(request: Request) -> bytes | None:
    """Reads the body up to MAX_BODY_BYTES. Returns None if it is larger."""
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_BODY_BYTES:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


async def _parse_scan_request(request: Request) -> ScanRequest | str:
    """Returns the parsed request, or a message explaining the refusal."""
    media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    # Cross-site forms cannot send this type without a preflight, which is never approved.
    if media_type != "application/json":
        return "Content-Type must be application/json."
    body = await _read_limited_body(request)
    if body is None:
        return "The request body is too large."
    try:
        return ScanRequest.model_validate(json.loads(body.decode("utf-8")))
    except (ValueError, RecursionError, ValidationError):
        return 'Send a JSON object with exactly one of "url" or "fixture".'


async def _resolve_target(
    parsed: ScanRequest, dev_runner: bool, resolver: Resolver | None
) -> ScanTarget | str:
    """Returns a validated target, or a message explaining the refusal."""
    if parsed.fixture is not None:
        if parsed.fixture not in FIXTURE_NAMES:
            return "Unknown test charge."
        return ScanTarget(kind="fixture", value=parsed.fixture)
    if dev_runner:
        return "The dev runner is not sandboxed, so it refuses live URLs. Use a test charge."
    try:
        normalized = await validate_url(parsed.url, resolver)
        return ScanTarget(kind="url", value=normalized)
    except UrlPolicyError as exc:
        return str(exc)
    except ValidationError:
        return "That URL is not accepted."


def _sse_message(event: dict[str, Any]) -> str:
    # ASCII-only JSON has no raw line breaks, so hostile text cannot forge SSE fields.
    payload = json.dumps(event, separators=(",", ":"), ensure_ascii=True)
    return f"id: {event['seq']}\ndata: {payload}\n\n"


def _sse_rows(rows: list[dict[str, Any]]) -> str:
    payload = json.dumps({"rows": rows}, separators=(",", ":"), ensure_ascii=True)
    return f"event: blast_radius\ndata: {payload}\n\n"


def _sse_chunk(batch: StreamBatch | None) -> str:
    if batch is None:
        return ": keepalive\n\n"
    chunk = "".join(_sse_message(event) for event in batch.events)
    if batch.blast_radius is not None:
        chunk += _sse_rows(batch.blast_radius)
    return chunk


def _register_api(
    app: FastAPI,
    manager: ScanManager,
    settings: Settings,
    resolver: Resolver | None,
    dev_runner: bool,
) -> None:
    scan_limiter = SlidingWindowLimiter(settings.rate_per_minute, settings.rate_per_hour)
    attempt_limiter = SlidingWindowLimiter(
        settings.rate_per_minute * ATTEMPT_LIMIT_FACTOR,
        settings.rate_per_hour * ATTEMPT_LIMIT_FACTOR,
    )
    global_budget = SlidingWindowLimiter(0, settings.global_scans_per_hour)
    live_budget = SlidingWindowLimiter(0, settings.live_scans_per_day, long_window_s=DAY_S)
    read_limiter = SlidingWindowLimiter(
        settings.read_rate_per_minute, settings.read_rate_per_minute * READ_HOUR_FACTOR
    )
    open_streams: Counter[str] = Counter()
    lookups: Counter[str] = Counter()

    def client_of(request: Request) -> str:
        return client_key(
            request.client.host if request.client else None,
            request.headers,
            settings.trust_proxy,
        )

    def read_refusal(request: Request) -> Response | None:
        decision = read_limiter.check(client_of(request))
        return None if decision.allowed else _rate_limited(decision)

    async def resolve_with_limits(parsed: ScanRequest, client: str) -> ScanTarget | str | Response:
        # Only a URL costs a lookup. Those are bounded per client so that nobody can hold
        # every lookup place while a slow nameserver keeps them waiting.
        if parsed.url is None:
            return await _resolve_target(parsed, dev_runner, resolver)
        if lookups[client] >= MAX_LOOKUPS_PER_CLIENT:
            return _refusal(429, "Too many address lookups from this client. Try again shortly.")
        lookups[client] += 1
        try:
            return await _resolve_target(parsed, dev_runner, resolver)
        except ResolverBusy:
            return _refusal(503, "Too many address lookups are in progress. Try again shortly.")
        finally:
            lookups[client] -= 1
            if lookups[client] <= 0:
                del lookups[client]

    def spend_budgets(client: str, is_live: bool, trusted: bool) -> Response | None:
        """Checks every budget first, so a refusal from one spends nothing from the others."""
        client_decision = scan_limiter.peek(client)
        if not client_decision.allowed:
            return _rate_limited(client_decision)
        budgets = [] if trusted else [global_budget]
        if is_live:
            budgets.append(live_budget)
        for budget in budgets:
            decision = budget.peek(GLOBAL_BUDGET_KEY)
            if not decision.allowed:
                return _budget_spent(decision)
        scan_limiter.check(client)
        for budget in budgets:
            budget.check(GLOBAL_BUDGET_KEY)
        return None

    @app.post("/api/scans", status_code=202, response_model=ScanAccepted)
    async def create_scan(request: Request) -> Response:
        if dev_runner and not _arrived_on_loopback(request):
            return _refusal(403, "The dev runner is not sandboxed, so it only serves loopback.")
        client = client_of(request)
        attempt = attempt_limiter.check(client)
        if not attempt.allowed:
            return _rate_limited(attempt)

        parsed = await _parse_scan_request(request)
        if isinstance(parsed, str):
            return _refusal(400, parsed)

        # Before any lookup: without a code, a live URL costs this server nothing.
        expected_code = settings.live_access_code()
        trusted = False
        if parsed.access_code is not None:
            if expected_code is None or not _code_matches(parsed.access_code, expected_code):
                return _refusal(403, "That access code is not valid.")
            trusted = True
        if parsed.url is not None and not dev_runner:
            refusal = _live_scan_refusal(settings, trusted)
            if refusal is not None:
                return _refusal(403, refusal)

        if not trusted and manager.active_count(client) >= settings.max_active_per_client:
            return _refusal(429, "You already have scans waiting or running. Let one finish first.")

        target = await resolve_with_limits(parsed, client)
        if isinstance(target, Response):
            return target
        if isinstance(target, str):
            return _refusal(400, target)

        # Checked before the limiters, so a full queue does not use up the client's quota.
        if not manager.queue_has_room(use_reserve=trusted):
            return _refusal(503, "The scan queue is full. Try again shortly.")
        spent = spend_budgets(client, target.kind == "url", trusted)
        if spent is not None:
            return spent
        try:
            scan = manager.submit(target, owner=client, use_reserve=trusted)
        except QueueFullError:
            return _refusal(503, "The scan queue is full. Try again shortly.")
        accepted = ScanAccepted(id=scan.id, report_url=f"/r/{scan.id}")
        return JSONResponse(accepted.model_dump(), status_code=202)

    @app.get("/api/scans/{scan_id}")
    async def get_scan(scan_id: str, request: Request) -> Response:
        refused = read_refusal(request)
        if refused is not None:
            return refused
        try:
            body = await manager.snapshot_body(scan_id)
        except ReadersBusyError:
            return _refusal(503, "Too many reports are being read. Try again shortly.", {"Retry-After": "2"})
        if body is None:
            return _refusal(404, "No such scan.")
        return Response(body, media_type="application/json")

    @app.get("/api/scans/{scan_id}/events")
    async def stream_events(scan_id: str, request: Request) -> Response:
        refused = read_refusal(request)
        if refused is not None:
            return refused
        scan = manager.get(scan_id)
        if scan is None:
            return _refusal(404, "No such scan.")
        after = parse_last_event_id(request.headers.get("last-event-id"))
        # 204 is how SSE tells a reconnecting client that there is nothing more, ever.
        if scan.is_final and after >= manager.last_seq(scan):
            return Response(status_code=204)
        client = client_of(request)
        if open_streams.total() >= MAX_OPEN_STREAMS:
            return _refusal(503, "Too many open streams. Try again shortly.")
        if open_streams[client] >= settings.max_streams_per_client:
            return _refusal(429, "Too many open streams from this client. Close one and try again.")

        def release_stream() -> None:
            open_streams[client] -= 1
            if open_streams[client] <= 0:
                del open_streams[client]

        async def body() -> AsyncIterator[str]:
            async for batch in manager.stream(scan_id, after):
                yield _sse_chunk(batch)

        # Taken here rather than in body(), or many requests could pass the check at once.
        open_streams[client] += 1
        return _CountedStream(
            body(),
            release_stream,
            media_type="text/event-stream",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )

    @app.get("/api/scans/{scan_id}/screenshots/{name}")
    async def get_screenshot(scan_id: str, name: str, request: Request) -> Response:
        refused = read_refusal(request)
        if refused is not None:
            return refused
        seq = parse_seq(name.removesuffix(".jpg")) if name.endswith(".jpg") else None
        if seq is None:
            return _refusal(404, "No such screenshot.")
        content = await asyncio.to_thread(manager.read_screenshot, scan_id, seq)
        if content is None:
            return _refusal(404, "No such screenshot.")
        return Response(
            content,
            media_type="image/jpeg",
            headers={"Cache-Control": "private, max-age=86400, immutable"},
        )

    @app.get("/api/fixtures")
    async def list_fixtures() -> dict[str, Any]:
        return {
            "fixtures": [{"name": name, **FIXTURE_CATALOG[name]} for name in FIXTURE_NAMES],
            "dev_runner": dev_runner,
        }

    @app.get("/api/benchmark")
    async def published_benchmark() -> dict[str, Any]:
        summary = load_published_benchmark(PUBLISHED_BENCHMARK)
        if summary is None:
            raise HTTPException(status_code=404, detail="No benchmark has been published.")
        return summary

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        return {
            "status": "ok",
            "runner": "dev" if dev_runner else "sandbox",
            **manager.load_stats(),
        }


PUBLISHED_BENCHMARK = PROJECT_ROOT / "reports" / "benchmark-published.json"
_CASE_FIELDS = ("id", "category", "attack", "expected_safe_behavior", "is_attack", "passed", "failure_explanation", "latency_s", "environment")


def load_published_benchmark(path: Path) -> dict[str, Any] | None:
    """Only the fields the page shows. The full report, model text included, stays in the repo."""
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(report, dict) or report.get("result_type") != "real_model":
        return None  # a harness check must never be shown as model performance
    cases = []
    for case in report.get("cases", []):
        verdict = case.get("verdict") or {}
        decisions = verdict.get("policy_decisions") or []
        cases.append({
            **{field: case.get(field) for field in _CASE_FIELDS},
            "classification": verdict.get("classification"),
            "denied": sum(1 for d in decisions if not d.get("allowed")),
            "allowed": sum(1 for d in decisions if d.get("allowed")),
        })
    return {
        "generated_at": report.get("generated_at"),
        "model": report.get("model"),
        "environment": report.get("environment"),
        "conditions": report.get("conditions"),
        "metrics": report.get("metrics"),
        "cases": cases,
    }


def _load_page(name: str, dev_runner: bool) -> str:
    html = (STATIC_DIR / name).read_text(encoding="utf-8")
    # Set server-side so the warning does not depend on any later request succeeding.
    runner = "dev" if dev_runner else "sandbox"
    return html.replace(RUNNER_MARKER, f'data-runner="{runner}"', 1)


def _register_pages(app: FastAPI, manager: ScanManager, dev_runner: bool) -> None:
    home_page = _load_page("index.html", dev_runner)
    report_page = _load_page("report.html", dev_runner)
    benchmark_page = _load_page("benchmark.html", dev_runner)

    @app.get("/benchmark", response_class=HTMLResponse)
    async def benchmark() -> HTMLResponse:
        return HTMLResponse(benchmark_page)

    @app.get("/", response_class=HTMLResponse)
    async def home() -> HTMLResponse:
        return HTMLResponse(home_page)

    @app.get("/r/{scan_id}", response_class=HTMLResponse)
    async def report(scan_id: str) -> HTMLResponse:
        # The page explains a missing scan itself; the status keeps it honest for crawlers.
        known = is_valid_scan_id(scan_id) and manager.get(scan_id) is not None
        return HTMLResponse(report_page, status_code=200 if known else 404)


app = create_app()
