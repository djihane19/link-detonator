"""Job manager: queue, concurrency, persistence, retention and event fan-out."""

from __future__ import annotations

import asyncio
import base64
import json
import os
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio

from app.config import Settings
from app.models import ScanTarget
from app.scans import (
    QueueFullError,
    ScanManager,
    StreamBatch,
    final_status,
    is_valid_scan_id,
    parse_last_event_id,
    parse_seq,
)

JPEG = b"\xff\xd8\xff\xe0" + b"fake-jpeg-body"
FIXTURE = ScanTarget(kind="fixture", value="benign")

Script = Callable[[str, ScanTarget, Any], Awaitable[None]]


class FakeRunner:
    """Runs a test-supplied script in place of a sandbox."""

    isolated = True

    def __init__(self, script: Script | None = None) -> None:
        self.script = script
        self.reaped = 0

    async def reap(self) -> int:
        self.reaped += 1
        return 0

    async def run(self, scan_id: str, target: ScanTarget, emit: Any) -> None:
        if self.script is not None:
            await self.script(scan_id, target, emit)


def make_settings(tmp_path: Path, **overrides: Any) -> Settings:
    return Settings(data_dir=tmp_path, **overrides)


@pytest_asyncio.fixture
async def started(tmp_path: Path) -> AsyncIterator[Callable[..., Awaitable[ScanManager]]]:
    managers: list[ScanManager] = []

    async def start(runner: FakeRunner, **overrides: Any) -> ScanManager:
        manager = ScanManager(make_settings(tmp_path, **overrides), runner)
        await manager.start()
        managers.append(manager)
        return manager

    yield start
    for manager in managers:
        await manager.stop()


async def wait_final(manager: ScanManager, scan_id: str) -> dict[str, Any]:
    async with asyncio.timeout(5):
        while True:
            scan = manager.get(scan_id)
            assert scan is not None
            if scan.is_final:
                snapshot = await manager.snapshot(scan_id)
                assert snapshot is not None
                return snapshot
            await asyncio.sleep(0.005)


def event_types(snapshot: dict[str, Any]) -> list[str]:
    return [event["type"] for event in snapshot["events"]]


def log_lines(tmp_path: Path, scan_id: str) -> list[dict[str, Any]]:
    text = (tmp_path / "scans" / scan_id / "events.ndjson").read_text()
    return [json.loads(line) for line in text.splitlines()]


async def script_ok(_: str, __: ScanTarget, emit: Any) -> None:
    await emit("worker_started", {"url": "http://fixtures.invalid/benign", "mode": "fixture", "offline": True}, "worker")
    await emit("worker_finished", {"status": "ok", "error": None}, "worker")


@pytest.mark.asyncio
async def test_host_assigns_envelope_and_scan_finishes(started: Any, tmp_path: Path) -> None:
    manager = await started(FakeRunner(script_ok))
    scan = manager.submit(FIXTURE)
    assert is_valid_scan_id(scan.id)

    snapshot = await wait_final(manager, scan.id)

    assert snapshot["status"] == "ok"
    assert event_types(snapshot) == ["worker_started", "worker_finished", "verdict", "scan_finished"]
    assert [event["seq"] for event in snapshot["events"]] == [1, 2, 3, 4]
    assert all(event["v"] == 1 for event in snapshot["events"])
    assert [event["source"] for event in snapshot["events"]] == ["worker", "worker", "host", "host"]
    assert snapshot["events"][-1]["data"] == {"status": "ok"}
    assert snapshot["verdict"] == {"status": "pending"}
    assert len(snapshot["blast_radius"]) == 8
    assert log_lines(tmp_path, scan.id) == snapshot["events"]


@pytest.mark.asyncio
async def test_worker_cannot_assert_host_facts_or_end_the_scan(started: Any) -> None:
    async def script(_: str, __: ScanTarget, emit: Any) -> None:
        await emit("sandbox_removed", {"verified": True}, "worker")
        await emit("scan_finished", {"status": "ok"}, "worker")
        await emit("scan_finished", {"status": "ok"}, "host")
        await emit("verdict", {"status": "safe"}, "host")
        await emit("worker_finished", {"status": "partial", "error": None}, "worker")

    manager = await started(FakeRunner(script))
    snapshot = await wait_final(manager, manager.submit(FIXTURE).id)

    assert event_types(snapshot) == ["worker_finished", "verdict", "scan_finished"]
    assert snapshot["verdict"] == {"status": "pending"}
    assert snapshot["status"] == "partial"


@pytest.mark.asyncio
async def test_unknown_source_gets_the_lower_trust_label(started: Any) -> None:
    async def script(_: str, __: ScanTarget, emit: Any) -> None:
        await emit("dialog", {"dialog_type": "alert", "message": "x"}, "root")

    manager = await started(FakeRunner(script))
    snapshot = await wait_final(manager, manager.submit(FIXTURE).id)
    assert snapshot["events"][0]["source"] == "worker"


@pytest.mark.asyncio
async def test_screenshot_is_decoded_and_b64_never_persisted(started: Any, tmp_path: Path) -> None:
    b64 = base64.b64encode(JPEG).decode()

    async def script(_: str, __: ScanTarget, emit: Any) -> None:
        await emit("screenshot", {"label": "load", "mime": "image/jpeg", "b64": b64, "image_url": "https://evil.example/x"}, "worker")

    manager = await started(FakeRunner(script))
    scan = manager.submit(FIXTURE)
    snapshot = await wait_final(manager, scan.id)

    shot = snapshot["events"][0]
    assert "b64" not in shot["data"]
    assert shot["data"]["image_url"] == f"/api/scans/{scan.id}/screenshots/1.jpg"
    assert (tmp_path / "scans" / scan.id / "1.jpg").read_bytes() == JPEG
    assert b64 not in (tmp_path / "scans" / scan.id / "events.ndjson").read_text()
    assert manager.read_screenshot(scan.id, 1) == JPEG


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad_b64",
    ["not base64 !!!", base64.b64encode(b"<svg onload=alert(1)>").decode(), None],
)
async def test_non_jpeg_screenshot_is_recorded_without_an_image(
    started: Any, tmp_path: Path, bad_b64: str | None
) -> None:
    async def script(_: str, __: ScanTarget, emit: Any) -> None:
        await emit("screenshot", {"label": "bad", "mime": "image/jpeg", "b64": bad_b64}, "worker")

    manager = await started(FakeRunner(script))
    scan = manager.submit(FIXTURE)
    snapshot = await wait_final(manager, scan.id)

    assert snapshot["events"][0]["data"]["image_url"] is None
    assert not (tmp_path / "scans" / scan.id / "1.jpg").exists()


@pytest.mark.asyncio
async def test_screenshot_cap_is_enforced_by_the_host(started: Any, tmp_path: Path) -> None:
    b64 = base64.b64encode(JPEG).decode()

    async def script(_: str, __: ScanTarget, emit: Any) -> None:
        for _index in range(30):
            await emit("screenshot", {"label": "x", "mime": "image/jpeg", "b64": b64}, "worker")

    manager = await started(FakeRunner(script))
    scan = manager.submit(FIXTURE)
    await wait_final(manager, scan.id)
    assert len(list((tmp_path / "scans" / scan.id).glob("*.jpg"))) == 25


@pytest.mark.asyncio
async def test_worker_event_cap_still_lets_host_events_through(started: Any) -> None:
    async def script(_: str, __: ScanTarget, emit: Any) -> None:
        for _index in range(10):
            await emit("popup", {"url": "http://a.example/"}, "worker")
        await emit("sandbox_removed", {"verified": True}, "host")

    manager = await started(FakeRunner(script), max_events=3)
    snapshot = await wait_final(manager, manager.submit(FIXTURE).id)
    assert event_types(snapshot).count("popup") == 3
    assert "sandbox_removed" in event_types(snapshot)


@pytest.mark.asyncio
async def test_runner_exception_becomes_a_generic_scan_error(started: Any) -> None:
    async def script(_: str, __: ScanTarget, emit: Any) -> None:
        raise RuntimeError("/secret/path/leak")

    manager = await started(FakeRunner(script))
    snapshot = await wait_final(manager, manager.submit(FIXTURE).id)

    assert snapshot["status"] == "error"
    assert "/secret/path/leak" not in json.dumps(snapshot)
    assert event_types(snapshot) == ["scan_error", "verdict", "scan_finished"]


@pytest.mark.asyncio
async def test_a_failing_scan_does_not_stop_later_scans(started: Any) -> None:
    calls = {"count": 0}

    async def script(scan_id: str, target: ScanTarget, emit: Any) -> None:
        calls["count"] += 1
        if calls["count"] == 1:
            raise RuntimeError("boom")
        await script_ok(scan_id, target, emit)

    manager = await started(FakeRunner(script), concurrency=1)
    first = manager.submit(FIXTURE)
    second = manager.submit(FIXTURE)
    assert (await wait_final(manager, first.id))["status"] == "error"
    assert (await wait_final(manager, second.id))["status"] == "ok"


@pytest.mark.asyncio
async def test_verdict_engine_failure_stays_pending(tmp_path: Path) -> None:
    class BrokenEngine:
        async def evaluate(self, scan_id: str, events: Any) -> dict[str, Any]:
            raise RuntimeError("boom")

    manager = ScanManager(make_settings(tmp_path), FakeRunner(script_ok), BrokenEngine())
    await manager.start()
    try:
        snapshot = await wait_final(manager, manager.submit(FIXTURE).id)
    finally:
        await manager.stop()
    assert snapshot["verdict"] == {"status": "pending"}
    assert snapshot["status"] == "ok"


@pytest.mark.asyncio
async def test_concurrency_cap_and_queue_limit(started: Any) -> None:
    release = asyncio.Event()
    active = {"now": 0, "peak": 0}

    async def script(_: str, __: ScanTarget, emit: Any) -> None:
        active["now"] += 1
        active["peak"] = max(active["peak"], active["now"])
        await release.wait()
        active["now"] -= 1

    manager = await started(FakeRunner(script), concurrency=2, queue_size=3)
    scans = [manager.submit(FIXTURE) for _ in range(2)]
    async with asyncio.timeout(5):
        while manager.load_stats()["running"] < 2:
            await asyncio.sleep(0.005)

    scans += [manager.submit(FIXTURE) for _ in range(3)]
    assert manager.load_stats() == {"queued": 3, "running": 2}
    assert not manager.queue_has_room()
    with pytest.raises(QueueFullError):
        manager.submit(FIXTURE)
    assert scans[-1].status == "queued"

    release.set()
    for scan in scans:
        await wait_final(manager, scan.id)
    assert active["peak"] == 2


@pytest.mark.asyncio
async def test_startup_runs_the_reaper(started: Any) -> None:
    runner = FakeRunner()
    await started(runner)
    assert runner.reaped == 1


@pytest.mark.asyncio
async def test_reaper_failure_does_not_stop_startup(started: Any) -> None:
    class BadReaper(FakeRunner):
        async def reap(self) -> int:
            raise OSError("no docker")

    manager = await started(BadReaper(script_ok))
    assert (await wait_final(manager, manager.submit(FIXTURE).id))["status"] == "ok"


async def collect(manager: ScanManager, scan_id: str, after: int = 0) -> list[StreamBatch]:
    batches: list[StreamBatch] = []
    async with asyncio.timeout(5):
        async for batch in manager.stream(scan_id, after):
            if batch is not None:
                batches.append(batch)
    return batches


def flat_seqs(batches: list[StreamBatch]) -> list[int]:
    return [event["seq"] for batch in batches for event in batch.events]


@pytest.mark.asyncio
async def test_live_stream_delivers_in_order_and_ends_after_scan_finished(started: Any) -> None:
    gate = asyncio.Event()

    async def script(_: str, __: ScanTarget, emit: Any) -> None:
        await emit("popup", {"url": "http://a.example/"}, "worker")
        await gate.wait()
        await emit("popup", {"url": "http://b.example/"}, "worker")

    manager = await started(FakeRunner(script))
    scan = manager.submit(FIXTURE)
    consumer = asyncio.create_task(collect(manager, scan.id))
    await asyncio.sleep(0.05)
    assert not consumer.done()
    gate.set()

    batches = await consumer
    assert flat_seqs(batches) == [1, 2, 3, 4]
    assert batches[-1].events[-1]["type"] == "scan_finished"
    assert batches[0].blast_radius is not None


@pytest.mark.asyncio
async def test_idle_stream_sends_heartbeats(started: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.scans.HEARTBEAT_S", 0.01)
    gate = asyncio.Event()

    async def script(_: str, __: ScanTarget, emit: Any) -> None:
        await gate.wait()

    manager = await started(FakeRunner(script))
    scan = manager.submit(FIXTURE)
    stream = manager.stream(scan.id, 0)
    async with asyncio.timeout(5):
        assert await anext(stream) is None
    gate.set()
    await wait_final(manager, scan.id)
    await stream.aclose()


@pytest.mark.asyncio
async def test_two_subscribers_each_get_everything(started: Any) -> None:
    gate = asyncio.Event()

    async def script(_: str, __: ScanTarget, emit: Any) -> None:
        await gate.wait()
        for _index in range(20):
            await emit("popup", {"url": "http://a.example/"}, "worker")

    manager = await started(FakeRunner(script))
    scan = manager.submit(FIXTURE)
    consumers = [asyncio.create_task(collect(manager, scan.id)) for _ in range(2)]
    await asyncio.sleep(0.01)
    gate.set()
    results = await asyncio.gather(*consumers)
    assert flat_seqs(results[0]) == flat_seqs(results[1]) == list(range(1, 23))


@pytest.mark.asyncio
async def test_replay_honours_cursor_after_finish(started: Any) -> None:
    manager = await started(FakeRunner(script_ok))
    scan = manager.submit(FIXTURE)
    await wait_final(manager, scan.id)

    assert flat_seqs(await collect(manager, scan.id)) == [1, 2, 3, 4]
    assert flat_seqs(await collect(manager, scan.id, after=2)) == [3, 4]
    assert flat_seqs(await collect(manager, scan.id, after=4)) == []


@pytest.mark.asyncio
async def test_stream_of_a_pruned_scan_ends(started: Any) -> None:
    manager = await started(FakeRunner(script_ok))
    scan = manager.submit(FIXTURE)
    await wait_final(manager, scan.id)
    stream = manager.stream(scan.id, 0)
    await manager._remove([scan])
    async with asyncio.timeout(5):
        assert [item async for item in stream] == []


@pytest.mark.asyncio
async def test_reload_keeps_finished_scans_and_interrupts_unfinished_ones(tmp_path: Path) -> None:
    gate = asyncio.Event()

    async def script(_: str, target: ScanTarget, emit: Any) -> None:
        await emit("popup", {"url": "http://a.example/"}, "worker")
        if target.value == "hostile-freeze":
            await gate.wait()

    first = ScanManager(make_settings(tmp_path, concurrency=1), FakeRunner(script))
    await first.start()
    finished = first.submit(FIXTURE)
    await wait_final(first, finished.id)
    running = first.submit(ScanTarget(kind="fixture", value="hostile-freeze"))
    queued = first.submit(FIXTURE)
    async with asyncio.timeout(5):
        while running.status != "running" or running.next_seq < 2:
            await asyncio.sleep(0.005)
    # Abandoned rather than stopped, which is what a hard crash leaves on disk.
    for task in first._tasks:
        task.cancel()
    await asyncio.gather(*first._tasks, return_exceptions=True)
    for scan_id, status in ((running.id, "running"), (queued.id, "queued")):
        meta_path = tmp_path / "scans" / scan_id / "meta.json"
        meta = json.loads(meta_path.read_text())
        meta["status"], meta["finished_at"] = status, None
        meta_path.write_text(json.dumps(meta))
        log_path = tmp_path / "scans" / scan_id / "events.ndjson"
        if not log_path.exists():
            continue
        kept = [line for line in log_path.read_text().splitlines() if json.loads(line)["source"] == "worker"]
        log_path.write_text("".join(f"{line}\n" for line in kept))

    second = ScanManager(make_settings(tmp_path, concurrency=1), FakeRunner(script))
    await second.start()
    try:
        kept_snapshot = await second.snapshot(finished.id)
        assert kept_snapshot is not None and kept_snapshot["status"] == "partial"

        interrupted = await second.snapshot(running.id)
        assert interrupted is not None and interrupted["status"] == "interrupted"
        assert event_types(interrupted) == ["popup", "scan_error", "scan_finished"]
        assert [event["seq"] for event in interrupted["events"]] == [1, 2, 3]
        assert interrupted["events"][-1]["data"] == {"status": "interrupted"}

        never_ran = await second.snapshot(queued.id)
        assert never_ran is not None and never_ran["status"] == "interrupted"

        assert flat_seqs(await collect(second, running.id)) == [1, 2, 3]
    finally:
        await second.stop()


@pytest.mark.asyncio
async def test_graceful_stop_interrupts_running_and_queued(tmp_path: Path) -> None:
    async def script(_: str, __: ScanTarget, emit: Any) -> None:
        await asyncio.Event().wait()

    manager = ScanManager(make_settings(tmp_path, concurrency=1), FakeRunner(script))
    await manager.start()
    running = manager.submit(FIXTURE)
    queued = manager.submit(FIXTURE)
    async with asyncio.timeout(5):
        while running.status != "running":
            await asyncio.sleep(0.005)
    await manager.stop()
    assert running.status == "interrupted"
    assert queued.status == "interrupted"
    assert log_lines(tmp_path, running.id)[-1]["type"] == "scan_finished"


@pytest.mark.asyncio
async def test_reload_tolerates_bad_directories_and_torn_lines(tmp_path: Path) -> None:
    first = ScanManager(make_settings(tmp_path), FakeRunner(script_ok))
    await first.start()
    scan = first.submit(FIXTURE)
    await wait_final(first, scan.id)
    await first.stop()

    scans_dir = tmp_path / "scans"
    (scans_dir / "not-a-valid-id").mkdir()
    bad_meta = scans_dir / ("B" * 22)
    bad_meta.mkdir()
    (bad_meta / "meta.json").write_text("{torn")
    with open(scans_dir / scan.id / "events.ndjson", "a") as handle:
        handle.write('{"torn": ')

    second = ScanManager(make_settings(tmp_path), FakeRunner())
    await second.start()
    try:
        assert second.get("B" * 22) is None
        snapshot = await second.snapshot(scan.id)
        assert snapshot is not None and len(snapshot["events"]) == 4
    finally:
        await second.stop()


@pytest.mark.asyncio
async def test_retention_removes_expired_scans(tmp_path: Path) -> None:
    clock = {"now": 1_000_000.0}
    settings = make_settings(tmp_path, retention_days=1)
    manager = ScanManager(settings, FakeRunner(script_ok), clock=lambda: clock["now"])
    await manager.start()
    try:
        old = manager.submit(FIXTURE)
        await wait_final(manager, old.id)
        clock["now"] += 86_401
        fresh = manager.submit(FIXTURE)
        await wait_final(manager, fresh.id)
        await manager.prune()
        assert manager.get(old.id) is None
        assert not (tmp_path / "scans" / old.id).exists()
        assert manager.get(fresh.id) is not None
    finally:
        await manager.stop()


@pytest.mark.asyncio
async def test_disk_cap_removes_oldest_finished_first_and_never_active(tmp_path: Path) -> None:
    clock = {"now": 1_000_000.0}
    gate = asyncio.Event()

    async def script(_: str, target: ScanTarget, emit: Any) -> None:
        if target.value == "hostile-freeze":
            await gate.wait()

    manager = ScanManager(make_settings(tmp_path, disk_cap_mb=1), FakeRunner(script), clock=lambda: clock["now"])
    await manager.start()
    try:
        active = manager.submit(ScanTarget(kind="fixture", value="hostile-freeze"))
        async with asyncio.timeout(5):
            while active.status != "running":
                await asyncio.sleep(0.005)
        (tmp_path / "scans" / active.id / "ballast").write_bytes(b"x" * 400_000)

        older = manager.submit(FIXTURE)
        await wait_final(manager, older.id)
        (tmp_path / "scans" / older.id / "ballast").write_bytes(b"x" * 500_000)
        clock["now"] += 10
        newer = manager.submit(FIXTURE)
        await wait_final(manager, newer.id)
        (tmp_path / "scans" / newer.id / "ballast").write_bytes(b"x" * 500_000)

        await manager.prune()
        assert manager.get(older.id) is None
        assert manager.get(newer.id) is not None
        assert manager.get(active.id) is not None
    finally:
        gate.set()
        await manager.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_id", ["../../etc", "..", "", "a/b", "A" * 21, "A" * 23, "A" * 21 + "/"])
async def test_bad_ids_never_resolve(started: Any, bad_id: str) -> None:
    manager = await started(FakeRunner())
    assert manager.get(bad_id) is None
    assert await manager.snapshot(bad_id) is None
    assert manager.read_screenshot(bad_id, 1) is None


@pytest.mark.asyncio
async def test_screenshot_read_revalidates_and_refuses_symlinks(started: Any, tmp_path: Path) -> None:
    manager = await started(FakeRunner(script_ok))
    scan = manager.submit(FIXTURE)
    await wait_final(manager, scan.id)
    directory = tmp_path / "scans" / scan.id

    (directory / "5.jpg").write_bytes(b"<html>not a jpeg</html>")
    assert manager.read_screenshot(scan.id, 5) is None

    secret = tmp_path / "secret.jpg"
    secret.write_bytes(JPEG)
    os.symlink(secret, directory / "6.jpg")
    assert manager.read_screenshot(scan.id, 6) is None

    assert manager.read_screenshot(scan.id, 0) is None
    assert manager.read_screenshot(scan.id, 99) is None


@pytest.mark.parametrize("value", ["../1", "1/../2", "-1", "0", "01", "1.0", "", " 1", "1\n", "٣", "9" * 10, "9" * 5000])
def test_parse_seq_accepts_only_plain_positive_integers(value: str) -> None:
    assert parse_seq(value) is None


def test_parse_seq_accepts_a_normal_number() -> None:
    assert parse_seq("42") == 42


@pytest.mark.parametrize(
    ("header", "expected"),
    [(None, 0), ("", 0), ("7", 7), (" 7 ", 7), ("abc", 0), ("-3", 0), ("9" * 5000, 0)],
)
def test_parse_last_event_id(header: str | None, expected: int) -> None:
    assert parse_last_event_id(header) == expected


def _event(kind: str, source: str, **data: Any) -> dict[str, Any]:
    return {"type": kind, "source": source, "data": data}


@pytest.mark.parametrize(
    ("events", "expected"),
    [
        ([], "error"),
        ([_event("popup", "worker")], "partial"),
        ([_event("worker_finished", "worker", status="ok")], "ok"),
        ([_event("worker_finished", "worker", status="nonsense")], "partial"),
        ([_event("worker_finished", "worker", status="ok"), _event("deadline_killed", "host")], "partial"),
        ([_event("worker_finished", "worker", status="ok"), _event("sandbox_exit", "host", exit_code=137, oom_killed=None)], "partial"),
        ([_event("worker_finished", "worker", status="ok"), _event("sandbox_exit", "host", exit_code=0, oom_killed=False)], "ok"),
        ([_event("worker_finished", "worker", status="ok"), _event("scan_error", "host", message="x")], "error"),
        ([_event("worker_finished", "worker", status="ok"), _event("sandbox_removed", "host", verified=False)], "partial"),
        # A worker cannot talk its way out of a host fact, or forge one.
        ([_event("scan_error", "worker", message="x"), _event("worker_finished", "worker", status="error")], "error"),
    ],
)
def test_final_status(events: list[dict[str, Any]], expected: str) -> None:
    assert final_status(events) == expected
