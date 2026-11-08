"""Job manager: queue, concurrency, persistence and live event fan-out.

Layout on disk, under `<data_dir>/scans/<id>/`:
  meta.json       scan facts, replaced atomically
  events.ndjson   the envelope log, one event per line, never holding screenshot b64
  <seq>.jpg       decoded screenshots, named only from the host-assigned integer seq

Active scans keep their events in memory so subscribers read from a shared list
instead of per-client queues: a slow client costs a cursor, not a growing buffer.
Finished scans are read back from disk on demand.
"""

from __future__ import annotations

import asyncio
import hashlib
import base64
import binascii
import json
import logging
import os
import re
import secrets
import shutil
import time
from collections import Counter, OrderedDict
from collections.abc import AsyncIterator, Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from app.blast_radius import compute_blast_radius
from app.config import Settings
from app.models import ENVELOPE_VERSION, HOST_EVENT_TYPES, WORKER_EVENT_CAPS, ScanTarget
from app.sandbox import SandboxRunner
from app.receipt import build_receipt
from app.verdict import PendingVerdictEngine, VerdictEngine

logger = logging.getLogger(__name__)

STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_INTERRUPTED = "interrupted"
FINAL_STATUSES = frozenset({"ok", "partial", "error", STATUS_INTERRUPTED})
WORKER_FINAL_STATUSES = frozenset({"ok", "partial", "error"})

RUNNER_DEV = "dev"
RUNNER_SANDBOX = "sandbox"

# secrets.token_urlsafe(16) is exactly 22 URL-safe characters.
SCAN_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{22}")
SEQ_PATTERN = re.compile(r"[1-9][0-9]{0,8}")

JPEG_MAGIC = b"\xff\xd8\xff"
META_FILE = "meta.json"
EVENTS_FILE = "events.ndjson"
SECONDS_PER_DAY = 86_400.0
MIB = 1024 * 1024
RETENTION_SWEEP_S = 3600.0
HEARTBEAT_S = 15.0
# Bursts coalesce into one batch, which also bounds how often rows are recomputed.
STREAM_COALESCE_S = 0.05
# Reading a finished scan parses its whole log, which a hostile page can make large, so
# only this many run at once. A finished scan never changes, so its body is kept.
MAX_CONCURRENT_LOG_READS = 4
SNAPSHOT_CACHE_BYTES = 64 * MIB

# Written only by the manager, so a runner bug or a hostile line cannot end a scan early.
MANAGER_ONLY_TYPES = frozenset({"scan_finished", "verdict", "qr_source", "email_source"})


class QueueFullError(Exception):
    """The waiting queue is at capacity."""


class ReadersBusyError(Exception):
    """Too many finished-scan logs are being read right now. Try again shortly."""


@dataclass
class Scan:
    id: str
    target: ScanTarget
    runner: str
    created_at: float
    status: str = STATUS_QUEUED
    started_at: float | None = None
    finished_at: float | None = None
    next_seq: int = 1
    screenshots: int = 0
    worker_events: int = 0
    # Who submitted it, for the per-client cap. In memory only: never stored or served.
    owner: str | None = None
    # Where the target came from, such as a decoded QR image. Recorded as the first event.
    origin: dict[str, Any] | None = None
    # None once finished: the log on disk is then the only copy.
    events: list[dict[str, Any]] | None = None
    changed: asyncio.Event = field(default_factory=asyncio.Event)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    @property
    def is_final(self) -> bool:
        return self.status in FINAL_STATUSES

    def wake_subscribers(self) -> None:
        previous, self.changed = self.changed, asyncio.Event()
        previous.set()


@dataclass(frozen=True)
class StreamBatch:
    events: list[dict[str, Any]]
    blast_radius: list[dict[str, Any]] | None


def is_valid_scan_id(value: str) -> bool:
    return SCAN_ID_PATTERN.fullmatch(value) is not None


def parse_seq(value: str) -> int | None:
    """Strict positive-integer parse, so a path segment can only ever name an integer file."""
    return int(value) if SEQ_PATTERN.fullmatch(value) else None


def parse_last_event_id(value: str | None) -> int:
    """Client-controlled header: anything malformed means replay from the start."""
    if value is None:
        return 0
    parsed = parse_seq(value.strip())
    return parsed if parsed is not None else 0


def final_status(events: list[Mapping[str, Any]]) -> str:
    """Summarises a finished run. Host facts outrank whatever the worker claimed."""
    worker_claim: str | None = None
    has_worker_events = False
    host_problem = False
    host_error = False
    for event in events:
        kind, data = event["type"], event.get("data", {})
        if event.get("source") == "worker":
            has_worker_events = True
            if kind == "worker_finished":
                worker_claim = data.get("status")
        elif kind == "scan_error":
            host_error = True
        elif kind in ("deadline_killed", "output_limit_killed"):
            host_problem = True
        elif kind == "sandbox_exit" and (data.get("exit_code") != 0 or data.get("oom_killed")):
            host_problem = True
        elif kind == "sandbox_removed" and data.get("verified") is not True:
            host_problem = True

    if host_error:
        return "error"
    if worker_claim not in WORKER_FINAL_STATUSES:
        return "partial" if has_worker_events else "error"
    if worker_claim == "ok" and host_problem:
        return "partial"
    return str(worker_claim)


class ScanManager:
    def __init__(
        self,
        settings: Settings,
        runner: SandboxRunner,
        verdict_engine: VerdictEngine | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._settings = settings
        self._runner = runner
        self._verdict_engine = verdict_engine or PendingVerdictEngine()
        self._clock = clock
        self._root = Path(settings.data_dir) / "scans"
        self._scans: dict[str, Scan] = {}
        # The extra places are only for submissions that may use the reserve.
        self._queue: asyncio.Queue[Scan] = asyncio.Queue(
            maxsize=settings.queue_size + settings.reserved_queue_slots
        )
        self._active_by_owner: Counter[str] = Counter()
        self._prune_lock = asyncio.Lock()
        self._read_slots = asyncio.Semaphore(MAX_CONCURRENT_LOG_READS)
        self._snapshot_cache: OrderedDict[str, bytes] = OrderedDict()
        self._snapshot_cache_size = 0
        self._tasks: list[asyncio.Task[None]] = []
        self._running = 0
        self._runner_label = RUNNER_SANDBOX if runner.isolated else RUNNER_DEV

    # ---- lifecycle

    async def start(self) -> None:
        self._root.mkdir(parents=True, exist_ok=True)
        await self._load_existing()
        await self.prune()
        await self._run_reaper()
        self._tasks = [
            asyncio.create_task(self._work_loop(), name=f"scan-worker-{index}")
            for index in range(self._settings.concurrency)
        ]
        self._tasks.append(asyncio.create_task(self._retention_loop(), name="scan-retention"))

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks = []
        for scan in list(self._scans.values()):
            if scan.status == STATUS_QUEUED:
                await self._mark_interrupted(scan, "The orchestrator stopped before this scan ran.")

    async def _run_reaper(self) -> None:
        try:
            await self._runner.reap()
        except Exception:
            logger.exception("startup reaper failed")

    # ---- submission and reads

    def queue_has_room(self, use_reserve: bool = False) -> bool:
        limit = self._settings.queue_size
        if use_reserve:
            limit += self._settings.reserved_queue_slots
        return self._queue.qsize() < limit

    def active_count(self, owner: str) -> int:
        """Scans this client has queued or running."""
        return self._active_by_owner[owner]

    def submit(
        self, target: ScanTarget, owner: str | None = None, use_reserve: bool = False, origin: dict[str, Any] | None = None
    ) -> Scan:
        if not self.queue_has_room(use_reserve):
            raise QueueFullError
        scan = Scan(
            id=secrets.token_urlsafe(16),
            target=target,
            runner=self._runner_label,
            created_at=self._clock(),
            owner=owner,
            origin=origin,
            events=[],
        )
        self._scan_dir(scan.id).mkdir(parents=True)
        self._write_meta(scan)
        self._scans[scan.id] = scan
        self._queue.put_nowait(scan)
        if owner is not None:
            self._active_by_owner[owner] += 1
        return scan

    def get(self, scan_id: str) -> Scan | None:
        if not is_valid_scan_id(scan_id):
            return None
        return self._scans.get(scan_id)

    def load_stats(self) -> dict[str, int]:
        return {"queued": self._queue.qsize(), "running": self._running}

    async def receipt(self, scan_id: str) -> dict[str, Any] | None:
        """A hash-chained receipt of a finished scan's recorded events and screenshots."""
        scan = self.get(scan_id)
        if scan is None or not scan.is_final:
            return None
        events = await self._events_of(scan)
        record = {"scan_id": scan.id, "target": scan.target.model_dump(), "runner": scan.runner,
                  "created_at": scan.created_at, "status": scan.status}
        directory = self._scan_dir(scan.id)

        def screenshot_hashes() -> list[dict[str, Any]]:
            found = []
            for event in events:
                if event.get("type") == "screenshot" and (event.get("data") or {}).get("image_url"):
                    try:
                        content = (directory / f"{int(event['seq'])}.jpg").read_bytes()
                    except (OSError, ValueError):
                        continue
                    found.append({"seq": int(event["seq"]), "sha256": hashlib.sha256(content).hexdigest()})
            return found

        artifacts = await asyncio.to_thread(screenshot_hashes)
        return build_receipt(record, events, artifacts)

    async def snapshot(self, scan_id: str) -> dict[str, Any] | None:
        scan = self.get(scan_id)
        if scan is None:
            return None
        return self._build_snapshot(scan, await self._events_of(scan))

    async def snapshot_body(self, scan_id: str) -> bytes | None:
        """The snapshot as JSON. Raises ReadersBusyError rather than queue up log reads."""
        scan = self.get(scan_id)
        if scan is None:
            return None
        if not scan.is_final:
            return _encode_json(self._build_snapshot(scan, list(scan.events or [])))
        cached = self._snapshot_cache.get(scan.id)
        if cached is not None:
            self._snapshot_cache.move_to_end(scan.id)
            return cached
        if self._read_slots.locked():
            raise ReadersBusyError
        async with self._read_slots:
            body = await asyncio.to_thread(self._render_final_snapshot, scan)
        self._cache_snapshot(scan, body)
        return body

    def _render_final_snapshot(self, scan: Scan) -> bytes:
        return _encode_json(self._build_snapshot(scan, self._read_events(scan.id)))

    def _build_snapshot(self, scan: Scan, events: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "id": scan.id,
            "status": scan.status,
            "target": scan.target.model_dump(),
            "runner": scan.runner,
            "created_at": scan.created_at,
            "started_at": scan.started_at,
            "finished_at": scan.finished_at,
            "report_url": f"/r/{scan.id}",
            "events": events,
            "blast_radius": compute_blast_radius(events),
            "verdict": _latest_verdict(events),
        }

    def _cache_snapshot(self, scan: Scan, body: bytes) -> None:
        # Pruned while it was being read: caching it would keep a deleted report alive.
        if len(body) > SNAPSHOT_CACHE_BYTES or scan.id not in self._scans or scan.id in self._snapshot_cache:
            return
        self._snapshot_cache[scan.id] = body
        self._snapshot_cache_size += len(body)
        while self._snapshot_cache_size > SNAPSHOT_CACHE_BYTES:
            _, evicted = self._snapshot_cache.popitem(last=False)
            self._snapshot_cache_size -= len(evicted)

    def _forget_snapshot(self, scan_id: str) -> None:
        cached = self._snapshot_cache.pop(scan_id, None)
        if cached is not None:
            self._snapshot_cache_size -= len(cached)

    def last_seq(self, scan: Scan) -> int:
        return scan.next_seq - 1

    async def stream(self, scan_id: str, after_seq: int) -> AsyncIterator[StreamBatch | None]:
        """Yields events after `after_seq`, then ends once scan_finished has been delivered.

        A None item is a heartbeat: nothing new, but the connection should be kept alive.
        """
        scan = self.get(scan_id)
        if scan is None:
            return
        cursor = after_seq
        last_rows: list[dict[str, Any]] | None = None
        while True:
            # Both taken before the read: an event landing in between still wakes the wait
            # below, and a scan seen final here has its whole log on disk.
            changed = scan.changed
            was_final = scan.is_final
            events = await self._events_of(scan)
            fresh = [event for event in events if event["seq"] > cursor]
            if fresh:
                cursor = fresh[-1]["seq"]
                rows = compute_blast_radius(events)
                yield StreamBatch(fresh, rows if rows != last_rows else None)
                last_rows = rows
            if was_final:
                return
            try:
                async with asyncio.timeout(HEARTBEAT_S):
                    await changed.wait()
            except TimeoutError:
                yield None
                continue
            await asyncio.sleep(STREAM_COALESCE_S)

    def read_screenshot(self, scan_id: str, seq: int) -> bytes | None:
        """Returns validated JPEG bytes. Blocking; call it off the event loop."""
        scan = self.get(scan_id)
        if scan is None or seq < 1:
            return None
        path = self._scan_dir(scan.id) / f"{seq}.jpg"
        limit = self._settings.max_line_bytes
        try:
            # O_NOFOLLOW: a planted symlink must not be able to serve another file.
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            return None
        with os.fdopen(descriptor, "rb") as handle:
            content = handle.read(limit + 1)
        if len(content) > limit or not content.startswith(JPEG_MAGIC):
            return None
        return content

    # ---- running scans

    async def _work_loop(self) -> None:
        while True:
            scan = await self._queue.get()
            try:
                await self._execute(scan)
            except Exception:
                # One broken scan must not take a worker slot down with it.
                logger.exception("scan %s failed outside the runner", scan.id)
                await self._seal(scan, "error")
            finally:
                self._queue.task_done()

    async def _execute(self, scan: Scan) -> None:
        scan.status = STATUS_RUNNING
        scan.started_at = self._clock()
        self._write_meta(scan)
        scan.wake_subscribers()
        self._running += 1

        async def emit(event_type: str, data: dict[str, Any], source: str = "worker") -> None:
            await self._emit(scan, event_type, data, source)

        if scan.origin is not None:
            # The origin names its own event; a QR origin has none and stays qr_source.
            data = {k: v for k, v in scan.origin.items() if k != "event"}
            event_type = "email_source" if scan.origin.get("event") == "email_source" else "qr_source"
            async with scan.lock:
                self._append(scan, event_type, data, "host")

        try:
            await self._runner.run(scan.id, scan.target, emit)
        except asyncio.CancelledError:
            await self._mark_interrupted(scan, "The orchestrator stopped during this scan.")
            raise
        except Exception:
            # Details go to the log: exception text can carry paths and hostile strings.
            logger.exception("runner failed for scan %s", scan.id)
            await self._emit(scan, "scan_error", {"message": "The scan runner failed."}, "host")
        finally:
            self._running -= 1
        await self._conclude(scan)
        await self.prune()

    async def _conclude(self, scan: Scan) -> None:
        events = scan.events if scan.events is not None else []
        await self._record_verdict(scan, events)
        await self._seal(scan, final_status(events))

    async def _record_verdict(self, scan: Scan, events: list[dict[str, Any]]) -> None:
        try:
            verdict = await self._verdict_engine.evaluate(scan.id, events)
        except Exception:
            logger.exception("verdict engine failed for scan %s", scan.id)
            verdict = {"status": "pending"}
        async with scan.lock:
            self._append(scan, "verdict", verdict, "host")

    async def _seal(self, scan: Scan, status: str) -> None:
        """Writes scan_finished and drops the in-memory log. Nothing is accepted afterwards."""
        async with scan.lock:
            if scan.is_final:
                return
            self._append(scan, "scan_finished", {"status": status}, "host")
            scan.status = status
            scan.finished_at = self._clock()
            self._write_meta(scan)
            scan.events = None
            if scan.owner is not None:
                self._active_by_owner[scan.owner] -= 1
                if self._active_by_owner[scan.owner] <= 0:
                    del self._active_by_owner[scan.owner]
        scan.wake_subscribers()

    async def _mark_interrupted(self, scan: Scan, message: str) -> None:
        async with scan.lock:
            if scan.is_final:
                return
            self._append(scan, "scan_error", {"message": message}, "host")
        await self._seal(scan, STATUS_INTERRUPTED)

    async def _emit(self, scan: Scan, event_type: str, data: dict[str, Any], source: str) -> None:
        if event_type in MANAGER_ONLY_TYPES or not isinstance(data, dict):
            return
        # A source other than "host" gets the lower-trust label, and may not assert host facts.
        trusted_source = "host" if source == "host" else "worker"
        if trusted_source == "worker" and event_type in HOST_EVENT_TYPES:
            logger.warning("dropped host event type claimed by worker on scan %s", scan.id)
            return
        async with scan.lock:
            if scan.is_final or not self._admit_worker_event(scan, trusted_source):
                return
            seq = scan.next_seq
            if event_type == "screenshot":
                data = await self._store_screenshot(scan, seq, data)
            self._append(scan, event_type, data, trusted_source)
        scan.wake_subscribers()

    def _admit_worker_event(self, scan: Scan, source: str) -> bool:
        """Second line of defence behind the runner's cap. Host events always get through."""
        if source != "worker":
            return True
        if scan.worker_events >= self._settings.max_events:
            return False
        scan.worker_events += 1
        return True

    def _append(self, scan: Scan, event_type: str, data: dict[str, Any], source: str) -> None:
        """Assigns seq and ts, then persists. Callers hold scan.lock."""
        event = {
            "v": ENVELOPE_VERSION,
            "seq": scan.next_seq,
            "ts": self._clock(),
            "source": source,
            "type": event_type,
            "data": data,
        }
        scan.next_seq += 1
        if scan.events is not None:
            scan.events.append(event)
        self._write_event(scan.id, event)

    async def _store_screenshot(
        self, scan: Scan, seq: int, data: dict[str, Any]
    ) -> dict[str, Any]:
        """Moves the image out of the event. A rejected frame stays recorded, with no image."""
        stored = {key: value for key, value in data.items() if key not in ("b64", "image_url")}
        stored["mime"] = "image/jpeg"
        stored["image_url"] = None
        if scan.screenshots >= WORKER_EVENT_CAPS["screenshot"]:
            return stored
        content = _decode_jpeg(data.get("b64"))
        if content is None:
            return stored
        path = self._scan_dir(scan.id) / f"{seq}.jpg"
        try:
            await asyncio.to_thread(path.write_bytes, content)
        except OSError:
            logger.exception("could not store a screenshot for scan %s", scan.id)
            return stored
        scan.screenshots += 1
        stored["image_url"] = f"/api/scans/{scan.id}/screenshots/{seq}.jpg"
        return stored

    # ---- persistence

    def _scan_dir(self, scan_id: str) -> Path:
        if not is_valid_scan_id(scan_id):
            raise ValueError("invalid scan id")
        return self._root / scan_id

    def _write_meta(self, scan: Scan) -> None:
        meta = {
            "id": scan.id,
            "target": scan.target.model_dump(),
            "runner": scan.runner,
            "status": scan.status,
            "created_at": scan.created_at,
            "started_at": scan.started_at,
            "finished_at": scan.finished_at,
            "next_seq": scan.next_seq,
        }
        directory = self._scan_dir(scan.id)
        temporary = directory / f"{META_FILE}.tmp"
        try:
            temporary.write_text(json.dumps(meta), encoding="utf-8")
            temporary.replace(directory / META_FILE)
        except OSError:
            logger.exception("could not write meta for scan %s", scan.id)

    def _write_event(self, scan_id: str, event: dict[str, Any]) -> None:
        # Opened per event so each line reaches the OS at once and survives a crash.
        line = json.dumps(event, separators=(",", ":"), ensure_ascii=True) + "\n"
        try:
            with open(self._scan_dir(scan_id) / EVENTS_FILE, "a", encoding="utf-8") as handle:
                handle.write(line)
        except OSError:
            logger.exception("could not persist an event for scan %s", scan_id)

    async def _events_of(self, scan: Scan) -> list[dict[str, Any]]:
        if scan.events is not None:
            return list(scan.events)
        async with self._read_slots:
            return await asyncio.to_thread(self._read_events, scan.id)

    def _read_events(self, scan_id: str) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        try:
            with open(self._scan_dir(scan_id) / EVENTS_FILE, encoding="utf-8") as handle:
                for line in handle:
                    event = _parse_event_line(line)
                    if event is not None:
                        events.append(event)
        except FileNotFoundError:
            return []
        except (OSError, UnicodeError):
            logger.exception("could not read events for scan %s", scan_id)
        return events

    async def _load_existing(self) -> None:
        for entry in await asyncio.to_thread(_list_scan_dirs, self._root):
            scan = self._load_scan(entry)
            if scan is None:
                continue
            self._scans[scan.id] = scan
            if not scan.is_final:
                await self._recover_interrupted(scan)
            elif scan.next_seq <= 1:
                # Written before meta.json carried this. The log is the only other record.
                await self._restore_next_seq(scan)

    def _load_scan(self, directory: Path) -> Scan | None:
        try:
            meta = json.loads((directory / META_FILE).read_text(encoding="utf-8"))
            return Scan(
                id=directory.name,
                target=ScanTarget.model_validate(meta["target"]),
                runner=str(meta.get("runner", RUNNER_SANDBOX)),
                created_at=float(meta["created_at"]),
                status=str(meta["status"]),
                started_at=meta.get("started_at"),
                finished_at=meta.get("finished_at"),
                next_seq=int(meta.get("next_seq", 1)),
            )
        except (OSError, ValueError, KeyError, TypeError, ValidationError):
            logger.warning("ignored unreadable scan directory %s", directory.name)
            return None

    async def _restore_next_seq(self, scan: Scan) -> None:
        events = await asyncio.to_thread(self._read_events, scan.id)
        scan.next_seq = max((event["seq"] for event in events), default=0) + 1

    async def _recover_interrupted(self, scan: Scan) -> None:
        events = await asyncio.to_thread(self._read_events, scan.id)
        scan.next_seq = max((event["seq"] for event in events), default=0) + 1
        scan.events = events
        await self._mark_interrupted(scan, "The orchestrator restarted during this scan.")

    # ---- retention

    async def _retention_loop(self) -> None:
        while True:
            await asyncio.sleep(RETENTION_SWEEP_S)
            try:
                await self.prune()
            except Exception:
                # One bad sweep must not end retention for the life of the process.
                logger.exception("retention sweep failed")

    async def prune(self) -> None:
        """Removes expired scans, then the oldest finished ones until under the disk cap."""
        # Serialized: two scan slots can finish together, and both would remove the same scan.
        async with self._prune_lock:
            await self._prune_once()

    async def _prune_once(self) -> None:
        finished = sorted(
            (scan for scan in self._scans.values() if scan.is_final),
            key=lambda scan: scan.finished_at or scan.created_at,
        )
        cutoff = self._clock() - self._settings.retention_days * SECONDS_PER_DAY
        expired = [scan for scan in finished if (scan.finished_at or scan.created_at) < cutoff]
        await self._remove(expired)

        remaining = [scan for scan in finished if scan not in expired]
        cap = self._settings.disk_cap_mb * MIB
        usage = await asyncio.to_thread(_directory_size, self._root)
        for scan in remaining:
            if usage <= cap:
                break
            usage -= await asyncio.to_thread(_directory_size, self._scan_dir(scan.id))
            await self._remove([scan])

    async def _remove(self, scans: list[Scan]) -> None:
        for scan in scans:
            self._scans.pop(scan.id, None)
            self._forget_snapshot(scan.id)
            await asyncio.to_thread(shutil.rmtree, self._scan_dir(scan.id), True)


def _encode_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _decode_jpeg(value: object) -> bytes | None:
    if not isinstance(value, str):
        return None
    try:
        content = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    return content if content.startswith(JPEG_MAGIC) else None


def _latest_verdict(events: list[dict[str, Any]]) -> dict[str, Any]:
    for event in reversed(events):
        if event["type"] == "verdict":
            return event["data"]
    return {"status": "pending"}


def _parse_event_line(line: str) -> dict[str, Any] | None:
    """A crash can leave a torn last line, so an unparsable line is skipped, not fatal."""
    try:
        event = json.loads(line)
    except ValueError:
        return None
    if not isinstance(event, dict) or not isinstance(event.get("seq"), int):
        return None
    if not isinstance(event.get("type"), str) or not isinstance(event.get("data"), dict):
        return None
    return event


def _list_scan_dirs(root: Path) -> list[Path]:
    return [
        entry
        for entry in root.iterdir()
        if is_valid_scan_id(entry.name) and entry.is_dir() and not entry.is_symlink()
    ]


def _directory_size(directory: Path) -> int:
    total = 0
    for current, _, names in os.walk(directory):
        for name in names:
            try:
                total += os.lstat(os.path.join(current, name)).st_size
            except OSError:
                continue
    return total
