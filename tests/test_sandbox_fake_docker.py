"""DockerRunner and LocalFixtureRunner against real subprocesses.

tests/fake_docker.py stands in for the docker CLI. These tests prove what the runner
does given a client's behaviour; they do not prove anything about Docker itself.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import stat
import sys
import textwrap
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from app.blast_radius import compute_blast_radius
from app.config import SECRET_CANARY_ENV, Settings
from app.models import ScanTarget
from app.sandbox import (
    REASON_EVENTS,
    REASON_LINE,
    REASON_TOTAL,
    DockerRunner,
    LocalFixtureRunner,
)

pytestmark = pytest.mark.asyncio

FIXTURE = ScanTarget(kind="fixture", value="benign")
SCAN_ID = "scan_id-1"
NAME = f"ld-{SCAN_ID}"
TEST_TIMEOUT_S = 60
# Long enough for the stub to start and be inspected even on a loaded machine. Tests that
# assert on anything past the audit use this; a shorter deadline makes them racy.
AUDITED_DEADLINE_S = 4.0


async def run_scan(fake_docker: Any, event_log: Any, **overrides: Any) -> None:
    runner = DockerRunner(fake_docker.settings(**overrides))
    await asyncio.wait_for(runner.run(SCAN_ID, FIXTURE, event_log), TEST_TIMEOUT_S)


def assert_cleaned_up(fake_docker: Any) -> None:
    """rm -f ran, an inspect came after it, and the stub agrees the container is gone."""
    commands = fake_docker.commands()
    last_rm = len(commands) - 1 - commands[::-1].index("rm")
    assert "inspect" in commands[last_rm + 1 :]
    assert fake_docker.call_for("rm")["argv"] == ["rm", "-f", NAME]
    assert not fake_docker.container_exists(NAME)


def rows(event_log: Any) -> dict[str, dict[str, Any]]:
    return {row["id"]: row for row in compute_blast_radius(event_log.events)}


# --- Normal stream ---------------------------------------------------------------


async def test_normal_stream_full_lifecycle(fake_docker: Any, event_log: Any) -> None:
    await run_scan(fake_docker, event_log)

    assert event_log.types() == [
        "sandbox_created",
        "secret_audit",
        "worker_started",
        "navigation",
        "request",
        "screenshot",
        "text_layers",
        "worker_finished",
        "sandbox_exit",
        "sandbox_removed",
    ]
    assert event_log.types("worker") == event_log.types()[2:8]
    assert event_log.only("sandbox_created") == {
        "name": NAME,
        "image": "ld-test-image:1",
        "runtime": "runc",
        "policy": event_log.only("sandbox_created")["policy"],
    }
    assert event_log.only("sandbox_created")["policy"]["network"] == "ld-sandbox"
    assert event_log.only("sandbox_exit") == {"exit_code": 0, "oom_killed": False}
    assert event_log.only("sandbox_removed") == {"verified": True}
    assert_cleaned_up(fake_docker)


async def test_runner_executes_the_built_argv(fake_docker: Any, event_log: Any) -> None:
    await run_scan(fake_docker, event_log)
    argv = fake_docker.call_for("run")["argv"]
    assert argv[:4] == ["run", "--rm", "--init", "--name"]
    assert argv[-7:] == [
        "ld-test-image:1", "python", "/worker/worker.py", "--fixture", "benign", "--deadline", "15",
    ]  # fmt: skip
    assert "--offline" not in argv


async def test_url_target_is_passed_to_the_worker(fake_docker: Any, event_log: Any) -> None:
    runner = DockerRunner(fake_docker.settings())
    target = ScanTarget(kind="url", value="https://example.com/")
    await asyncio.wait_for(runner.run(SCAN_ID, target, event_log), TEST_TIMEOUT_S)
    assert fake_docker.call_for("run")["argv"][-4:-2] == ["--url", "https://example.com/"]


async def test_host_secrets_never_reach_the_docker_client(
    fake_docker: Any, event_log: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("VULTR_API_KEY", "host-secret-value")
    monkeypatch.setenv("LD_ANYTHING", "x")
    await run_scan(fake_docker, event_log)
    for call in fake_docker.calls():
        assert "VULTR_API_KEY" not in call["env_keys"]
        assert "LD_ANYTHING" not in call["env_keys"]
    assert all("-e" not in call["argv"] and "--env" not in call["argv"] for call in fake_docker.calls())


# --- Hard caps -------------------------------------------------------------------


async def test_oversized_line_kills_at_the_real_8_mib_cap(fake_docker: Any, event_log: Any) -> None:
    fake_docker.configure(scenario="oversized_line")
    await run_scan(fake_docker, event_log)

    assert event_log.only("output_limit_killed") == {"reason": REASON_LINE, "kill_confirmed": True}
    assert "worker_started" in event_log.types("worker"), "evidence before the breach survives"
    assert "page_crash" not in event_log.types(), "nothing after the breach is read"
    assert "kill" in fake_docker.commands()
    assert event_log.only("sandbox_exit")["exit_code"] == 137
    assert event_log.only("sandbox_removed") == {"verified": True}
    assert_cleaned_up(fake_docker)
    assert rows(event_log)["limits"]["status"] == "contained"


async def test_total_output_flood_kills_at_the_real_64_mib_cap(fake_docker: Any, event_log: Any) -> None:
    fake_docker.configure(scenario="flood")
    await run_scan(fake_docker, event_log)

    assert event_log.only("output_limit_killed") == {"reason": REASON_TOTAL, "kill_confirmed": True}
    # Every line before the cap was an unknown type: dropped and counted, not stored.
    assert event_log.only("output_dropped")["count"] >= 60
    assert "unknown_flood" not in event_log.types()
    assert "page_crash" not in event_log.types()
    assert "kill" in fake_docker.commands()
    assert_cleaned_up(fake_docker)


async def test_event_count_kills_at_the_real_5000_cap(fake_docker: Any, event_log: Any) -> None:
    fake_docker.configure(scenario="event_flood")
    await run_scan(fake_docker, event_log)

    # The client may already have exited by the time the last buffered line is read, in
    # which case there was nothing left to kill and no kill to confirm.
    assert event_log.only("output_limit_killed")["reason"] == REASON_EVENTS
    assert len(event_log.types("worker")) == 5000
    assert "worker_finished" not in event_log.types()
    assert_cleaned_up(fake_docker)


async def test_junk_lines_cannot_dodge_the_event_cap(fake_docker: Any, event_log: Any) -> None:
    fake_docker.configure(scenario="junk_line_flood")
    await run_scan(fake_docker, event_log)
    assert event_log.only("output_limit_killed")["reason"] == REASON_EVENTS
    assert event_log.only("output_dropped") == {"count": 5000}
    assert event_log.types("worker") == []


async def test_stderr_flood_counts_against_the_total_cap(fake_docker: Any, event_log: Any) -> None:
    fake_docker.configure(scenario="stderr_flood")
    await run_scan(fake_docker, event_log)
    assert event_log.only("output_limit_killed") == {"reason": REASON_TOTAL, "kill_confirmed": True}
    assert "kill" in fake_docker.commands()
    assert_cleaned_up(fake_docker)


async def test_per_type_caps_drop_and_count(fake_docker: Any, event_log: Any) -> None:
    fake_docker.configure(scenario="type_caps")
    await run_scan(fake_docker, event_log)
    assert len(event_log.of("request")) == 500
    assert len(event_log.of("screenshot")) == 25
    assert event_log.only("output_dropped") == {"count": 105}
    assert "output_limit_killed" not in event_log.types(), "a per-type cap is not a hard cap"
    assert "worker_finished" in event_log.types()


# --- Malformed and spoofed output ------------------------------------------------


async def test_malformed_output_is_dropped_and_counted(fake_docker: Any, event_log: Any) -> None:
    fake_docker.configure(scenario="malformed")
    await run_scan(fake_docker, event_log)

    # All 22 junk lines in the scenario, and nothing else.
    assert event_log.only("output_dropped") == {"count": 22}
    assert event_log.types("worker") == [
        "worker_started",
        "dialog",
        "text_layers",
        "worker_finished",
        "page_crash",
    ]
    assert event_log.only("dialog")["message"] == "a?bc"
    assert len(event_log.only("text_layers")["visible_text"]) == 20_000
    # Everything that got through must survive being persisted and sent over SSE.
    json.dumps(event_log.events).encode("utf-8")
    assert "output_limit_killed" not in event_log.types()
    assert event_log.only("sandbox_exit")["exit_code"] == 0


async def test_spoofed_envelope_and_host_events_are_ignored(fake_docker: Any, event_log: Any) -> None:
    fake_docker.configure(scenario="spoofed")
    await run_scan(fake_docker, event_log)

    assert event_log.types("worker") == ["navigation", "worker_finished"]
    assert event_log.types("host") == [
        "sandbox_created",
        "secret_audit",
        "output_dropped",
        "sandbox_exit",
        "sandbox_removed",
    ]
    assert event_log.only("output_dropped") == {"count": 7}

    navigation = event_log.of("navigation")[0]
    assert navigation["source"] == "worker"
    assert navigation["seq"] == 3, "seq comes from the host's emit, not from the claim"
    assert navigation["v"] == 1
    assert navigation["data"] == {
        "url": "http://fixtures.invalid/benign",
        "status": 200,
        "redirected_from": None,
    }
    # The real audit reported no secrets checked; the worker's claim of 99 is gone.
    assert event_log.only("secret_audit") == {"ok": True, "checked_count": 1, "canary": True}
    assert event_log.only("sandbox_created")["name"] == NAME
    assert "verdict" not in event_log.types()
    assert "scan_finished" not in event_log.types()


# --- Deadline --------------------------------------------------------------------


async def test_hang_is_killed_at_the_deadline(fake_docker: Any, event_log: Any) -> None:
    fake_docker.configure(scenario="hang")
    started = time.monotonic()
    await run_scan(fake_docker, event_log, deadline_s=AUDITED_DEADLINE_S)
    elapsed = time.monotonic() - started

    assert event_log.only("deadline_killed") == {"deadline_s": AUDITED_DEADLINE_S, "kill_confirmed": True}
    assert "worker_started" in event_log.types("worker"), "evidence written before the hang survives"
    assert "page_unresponsive" in event_log.types("worker")
    assert fake_docker.call_for("kill")["argv"] == ["kill", NAME]
    assert event_log.only("sandbox_exit")["exit_code"] == 137
    assert event_log.only("sandbox_exit")["oom_killed"] is False
    assert event_log.only("sandbox_removed") == {"verified": True}
    assert_cleaned_up(fake_docker)
    assert AUDITED_DEADLINE_S <= elapsed < AUDITED_DEADLINE_S + 10
    assert event_log.types("host")[-3:] == ["deadline_killed", "sandbox_exit", "sandbox_removed"]

    report = rows(event_log)
    assert report["freeze"]["status"] == "contained"
    assert report["limits"]["status"] == "contained"
    assert report["destroyed"]["status"] == "contained"


async def test_closing_stdout_does_not_escape_the_deadline(fake_docker: Any, event_log: Any) -> None:
    fake_docker.configure(scenario="close_stdout_then_hang")
    await run_scan(fake_docker, event_log, deadline_s=1.0)
    assert event_log.only("deadline_killed") == {"deadline_s": 1.0, "kill_confirmed": True}
    assert_cleaned_up(fake_docker)


async def test_client_is_force_killed_when_docker_kill_does_nothing(fake_docker: Any, event_log: Any) -> None:
    fake_docker.configure(scenario="hang", kill_ignored=True)
    started = time.monotonic()
    await run_scan(fake_docker, event_log, deadline_s=AUDITED_DEADLINE_S)

    assert event_log.only("deadline_killed") == {"deadline_s": AUDITED_DEADLINE_S, "kill_confirmed": False}
    assert rows(event_log)["freeze"]["status"] == "observed"
    assert rows(event_log)["limits"]["status"] == "observed"
    assert event_log.only("sandbox_exit")["exit_code"] == -signal.SIGKILL
    assert time.monotonic() - started < AUDITED_DEADLINE_S + 15
    assert_cleaned_up(fake_docker)


async def test_deadline_covers_a_container_that_never_appears(fake_docker: Any, event_log: Any) -> None:
    # docker run hangs before the container exists, as a slow image pull would.
    fake_docker.configure(scenario="hang", inspect_down=True)
    await run_scan(fake_docker, event_log, deadline_s=0.5)

    assert event_log.only("deadline_killed") == {"deadline_s": 0.5, "kill_confirmed": False}
    assert "sandbox_created" not in event_log.types()
    assert "secret_audit" not in event_log.types()
    assert "worker_started" not in event_log.types(), "unaudited output is never read"
    assert event_log.only("sandbox_removed") == {"verified": False}


# --- Secret audit ----------------------------------------------------------------


SECRET = "top-secret-value-1234"


async def test_secret_in_env_fails_the_audit_and_kills_unread(
    fake_docker: Any, event_log: Any, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("LD_T_SECRET", SECRET)
    monkeypatch.setenv("LD_T_OTHER", "other-value")
    fake_docker.configure(scenario="hang", env=["PATH=/usr/bin", f"LEAKED={SECRET}"])

    with caplog.at_level(logging.DEBUG):
        await run_scan(fake_docker, event_log, secret_env_names=("LD_T_SECRET", "LD_T_OTHER"))

    assert event_log.only("secret_audit") == {"ok": False, "checked_count": 3, "canary": True}
    assert "kill" in fake_docker.commands()
    assert event_log.types("worker") == [], "no output from a failed sandbox is read"
    assert "audit" in event_log.only("scan_error")["message"]
    assert event_log.only("sandbox_removed") == {"verified": True}
    assert_cleaned_up(fake_docker)

    assert SECRET not in json.dumps(event_log.events)
    assert SECRET not in caplog.text
    assert "other-value" not in json.dumps(event_log.events)
    assert rows(event_log)["secrets"]["status"] == "failed"
    assert SECRET not in json.dumps(compute_blast_radius(event_log.events))


async def test_clean_env_passes_the_audit(
    fake_docker: Any, event_log: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LD_T_SECRET", SECRET)
    fake_docker.configure(env=["PATH=/usr/bin", "LANG=C"])
    await run_scan(fake_docker, event_log, secret_env_names=("LD_T_SECRET", "LD_T_UNSET"))

    assert event_log.only("secret_audit") == {"ok": True, "checked_count": 2, "canary": True}
    assert "kill" not in fake_docker.commands()
    assert "worker_finished" in event_log.types()
    assert rows(event_log)["secrets"]["status"] == "clear"


async def test_unreadable_env_fails_the_audit(
    fake_docker: Any, event_log: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LD_T_SECRET", SECRET)
    fake_docker.configure(scenario="hang", inspect_no_config=True)
    await run_scan(fake_docker, event_log, secret_env_names=("LD_T_SECRET",))
    assert event_log.only("secret_audit") == {"ok": False, "checked_count": 2, "canary": True}
    assert event_log.types("worker") == []
    assert "kill" in fake_docker.commands()


# --- Removal ---------------------------------------------------------------------


async def test_removal_failure_is_reported_not_hidden(fake_docker: Any, event_log: Any) -> None:
    fake_docker.configure(rm_fails=True)
    await run_scan(fake_docker, event_log)

    assert event_log.only("sandbox_removed") == {"verified": False}
    assert fake_docker.commands().count("rm") == 5, "removal is retried before giving up"
    assert fake_docker.container_exists(NAME)
    assert rows(event_log)["destroyed"]["status"] == "failed"


async def test_rm_losing_the_race_with_auto_remove_is_retried(fake_docker: Any, event_log: Any) -> None:
    fake_docker.configure(scenario="hang", rm_race_attempts=2)
    await run_scan(fake_docker, event_log, deadline_s=0.5)
    assert event_log.only("sandbox_removed") == {"verified": True}
    assert_cleaned_up(fake_docker)


async def test_daemon_outage_is_not_mistaken_for_removal(fake_docker: Any, event_log: Any) -> None:
    # The container is gone from the stub's view, but inspect cannot say so.
    fake_docker.configure(inspect_down=True, run_fails=True)
    await run_scan(fake_docker, event_log)
    assert event_log.only("sandbox_removed") == {"verified": False}
    assert rows(event_log)["destroyed"]["status"] == "failed"


async def test_garbage_inspect_is_not_mistaken_for_removal(fake_docker: Any, event_log: Any) -> None:
    fake_docker.configure(scenario="hang", inspect_garbage=True, rm_fails=True)
    await run_scan(fake_docker, event_log, deadline_s=0.5)
    assert event_log.only("sandbox_removed") == {"verified": False}
    assert fake_docker.container_exists(NAME)


async def test_successful_rm_alone_does_not_verify_removal(fake_docker: Any, event_log: Any) -> None:
    # rm -f exits 0 here, but inspect cannot confirm the result, so it stays unverified.
    fake_docker.configure(scenario="hang", inspect_down=True)
    await run_scan(fake_docker, event_log, deadline_s=0.5)
    assert fake_docker.commands().count("rm") == 5
    assert not fake_docker.container_exists(NAME)
    assert event_log.only("sandbox_removed") == {"verified": False}


# --- Start failures --------------------------------------------------------------


async def test_docker_run_failure_is_an_error_with_no_sandbox_claims(
    fake_docker: Any, event_log: Any, caplog: pytest.LogCaptureFixture
) -> None:
    fake_docker.configure(run_fails=True)
    await run_scan(fake_docker, event_log)

    assert "125" in event_log.only("scan_error")["message"]
    # Stderr goes to the operator's log and never into the public event stream.
    assert "fake start failure" in caplog.text
    assert "fake start failure" not in json.dumps(event_log.events)
    assert "sandbox_created" not in event_log.types()
    assert "secret_audit" not in event_log.types()
    assert "sandbox_exit" not in event_log.types()
    assert fake_docker.commands().count("rm") == 1
    assert event_log.only("sandbox_removed") == {"verified": True}
    report = rows(event_log)
    assert report["destroyed"]["status"] == "not_observed"
    assert report["secrets"]["status"] == "not_observed"


async def test_missing_docker_binary(tmp_path: Path, event_log: Any) -> None:
    settings = Settings(docker_bin=str(tmp_path / "no-such-docker"), secret_env_names=())
    await asyncio.wait_for(DockerRunner(settings).run(SCAN_ID, FIXTURE, event_log), TEST_TIMEOUT_S)

    assert "could not be started" in event_log.only("scan_error")["message"]
    assert event_log.only("sandbox_removed") == {"verified": False}
    assert "sandbox_created" not in event_log.types()
    assert rows(event_log)["destroyed"]["status"] == "failed"


async def test_exit_before_audit_is_an_error_even_with_exit_code_zero(fake_docker: Any, event_log: Any) -> None:
    fake_docker.configure(never_visible=True, exit_code=0)
    await run_scan(fake_docker, event_log)
    assert "before its audit" in event_log.only("scan_error")["message"]
    assert "sandbox_created" not in event_log.types()
    assert "secret_audit" not in event_log.types()
    assert event_log.types("worker") == []


# --- OOM -------------------------------------------------------------------------


async def test_oom_event_is_reported(fake_docker: Any, event_log: Any) -> None:
    fake_docker.configure(oom=True, exit_code=137)
    await run_scan(fake_docker, event_log)
    assert event_log.only("sandbox_exit") == {"exit_code": 137, "oom_killed": True}
    assert rows(event_log)["memory"]["status"] == "contained"


async def test_oom_status_is_unknown_when_the_watcher_died(fake_docker: Any, event_log: Any) -> None:
    fake_docker.configure(events_fail=True, exit_code=137)
    await run_scan(fake_docker, event_log)
    assert event_log.only("sandbox_exit") == {"exit_code": 137, "oom_killed": None}
    assert rows(event_log)["memory"]["status"] == "observed"


async def test_oom_watcher_filters_on_this_container(fake_docker: Any, event_log: Any) -> None:
    await run_scan(fake_docker, event_log)
    argv = fake_docker.call_for("events")["argv"]
    assert f"container={NAME}" in argv
    assert "event=oom" in argv


# --- Failure and cancellation paths ----------------------------------------------


async def test_cancellation_still_removes_the_container(fake_docker: Any, event_log: Any) -> None:
    fake_docker.configure(scenario="hang")
    runner = DockerRunner(fake_docker.settings())
    task = asyncio.create_task(runner.run(SCAN_ID, FIXTURE, event_log))
    while "worker_started" not in event_log.types():
        await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, TEST_TIMEOUT_S)

    assert "kill" in fake_docker.commands()
    assert_cleaned_up(fake_docker)
    assert event_log.only("sandbox_removed") == {"verified": True}


async def test_failing_emit_still_removes_the_container(fake_docker: Any, event_log: Any) -> None:
    fake_docker.configure(scenario="hang")

    async def emit(event_type: str, data: dict[str, Any], source: str) -> None:
        if event_type == "worker_started":
            raise RuntimeError("disk full")
        await event_log(event_type, data, source)

    runner = DockerRunner(fake_docker.settings())
    with pytest.raises(RuntimeError, match="disk full"):
        await asyncio.wait_for(runner.run(SCAN_ID, FIXTURE, emit), TEST_TIMEOUT_S)

    assert "kill" in fake_docker.commands()
    assert_cleaned_up(fake_docker)
    assert event_log.only("sandbox_removed") == {"verified": True}


async def test_emit_that_always_fails_cannot_stop_cleanup(fake_docker: Any) -> None:
    fake_docker.configure(scenario="hang")

    async def emit(_type: str, _data: dict[str, Any], _source: str) -> None:
        raise RuntimeError("store is gone")

    runner = DockerRunner(fake_docker.settings())
    with pytest.raises(RuntimeError, match="store is gone"):
        await asyncio.wait_for(runner.run(SCAN_ID, FIXTURE, emit), TEST_TIMEOUT_S)
    assert_cleaned_up(fake_docker)


async def test_second_cancellation_cannot_interrupt_cleanup(fake_docker: Any, event_log: Any) -> None:
    fake_docker.configure(scenario="hang")
    runner = DockerRunner(fake_docker.settings())
    task = asyncio.create_task(runner.run(SCAN_ID, FIXTURE, event_log))
    while "worker_started" not in event_log.types():
        await asyncio.sleep(0.05)
    task.cancel()
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, TEST_TIMEOUT_S)

    # The caller is gone, but cleanup keeps going in the background and still finishes.
    for _ in range(200):
        if "sandbox_removed" in event_log.types():
            break
        await asyncio.sleep(0.05)
    assert event_log.only("sandbox_removed") == {"verified": True}
    assert not fake_docker.container_exists(NAME)


@pytest.mark.parametrize(
    "config",
    [
        {"scenario": "normal"},
        {"scenario": "hang"},
        {"scenario": "hang", "kill_ignored": True},
        {"scenario": "oversized_line"},
        {"scenario": "stderr_flood"},
    ],
)
async def test_no_docker_process_outlives_the_scan(
    fake_docker: Any, event_log: Any, config: dict[str, Any]
) -> None:
    fake_docker.configure(**config)
    await run_scan(fake_docker, event_log, deadline_s=AUDITED_DEADLINE_S)
    pids = [call["pid"] for call in fake_docker.calls()]
    assert {"run", "events", "rm", "inspect"} <= set(fake_docker.commands())
    assert [pid for pid in pids if _process_alive(pid)] == []


# --- Reaper ----------------------------------------------------------------------


async def test_reaper_removes_only_labelled_containers(fake_docker: Any) -> None:
    labelled_id = "a" * 64
    other_labelled_id = "b" * 64
    mine = ["link-detonator=1", "link-detonator.owner=app"]
    fake_docker.add_container("ld-old-1", labelled_id, mine)
    fake_docker.add_container("ld-old-2", other_labelled_id, mine)
    fake_docker.add_container("someone-elses", "c" * 64, ["other=1"])
    fake_docker.add_container("ld-benchmark", "d" * 64, ["link-detonator=1", "link-detonator.owner=benchmark"])

    removed = await DockerRunner(fake_docker.settings()).reap()

    assert removed == 2
    assert fake_docker.container_exists("ld-benchmark")
    assert not fake_docker.container_exists("ld-old-1")
    assert not fake_docker.container_exists("ld-old-2")
    assert fake_docker.container_exists("someone-elses")
    assert fake_docker.call_for("ps")["argv"] == ["ps", "-aq", "--filter", "label=link-detonator=1", "--filter", "label=link-detonator.owner=app"]


async def test_reaper_with_nothing_to_do(fake_docker: Any) -> None:
    assert await DockerRunner(fake_docker.settings()).reap() == 0
    assert "rm" not in fake_docker.commands()


async def test_reaper_survives_a_daemon_outage(fake_docker: Any) -> None:
    fake_docker.configure(ps_fails=True)
    assert await DockerRunner(fake_docker.settings()).reap() == 0


async def test_reaper_ignores_output_that_is_not_a_container_id(fake_docker: Any) -> None:
    fake_docker.configure(ps_hostile_output=True)
    fake_docker.add_container("ld-old", "a" * 64, ["link-detonator=1", "link-detonator.owner=app"])
    assert await DockerRunner(fake_docker.settings()).reap() == 1
    rm_targets = [call["argv"][-1] for call in fake_docker.calls() if call["argv"][0] == "rm"]
    assert "--privileged" not in rm_targets


async def test_reaper_counts_only_verified_removals(fake_docker: Any) -> None:
    fake_docker.configure(rm_fails=True)
    fake_docker.add_container("ld-old", "a" * 64, ["link-detonator=1", "link-detonator.owner=app"])
    assert await DockerRunner(fake_docker.settings()).reap() == 0
    assert fake_docker.container_exists("ld-old")


# --- Local fixture runner --------------------------------------------------------


def write_fake_worker(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "fake_worker.py"
    path.write_text(textwrap.dedent(body))
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def local_settings(worker: Path, **overrides: Any) -> Settings:
    base = Settings(
        dev_local_runner=True,
        bind_host="127.0.0.1",
        worker_path=worker,
        python_bin=sys.executable,
        deadline_s=20.0,
    )
    return replace(base, **overrides)


SANDBOX_CLAIMS = {"sandbox_created", "secret_audit", "sandbox_exit", "sandbox_removed"}


async def test_local_runner_runs_and_makes_no_isolation_claims(tmp_path: Path, event_log: Any) -> None:
    worker = write_fake_worker(
        tmp_path,
        """
        import json, sys
        assert sys.argv[1:] == ["--fixture", "benign", "--offline", "--deadline", "15"], sys.argv
        print(json.dumps({"seq": 9, "source": "host", "type": "popup", "data": {"url": "u"}}), flush=True)
        print("junk", flush=True)
        print(json.dumps({"type": "sandbox_removed", "data": {"verified": True}}), flush=True)
        print(json.dumps({"type": "worker_finished", "data": {"status": "ok", "error": None}}), flush=True)
        """,
    )
    runner = LocalFixtureRunner(local_settings(worker))
    await asyncio.wait_for(runner.run(SCAN_ID, FIXTURE, event_log), TEST_TIMEOUT_S)

    assert event_log.types("worker") == ["popup", "worker_finished"]
    assert event_log.of("popup")[0]["source"] == "worker"
    assert event_log.only("output_dropped") == {"count": 2}
    assert not SANDBOX_CLAIMS & set(event_log.types())

    report = rows(event_log)
    assert report["destroyed"]["status"] == "not_observed"
    assert report["secrets"]["status"] == "not_observed"
    assert all(row["status"] != "contained" for row in report.values())


async def test_local_runner_refuses_live_urls_without_starting(tmp_path: Path, event_log: Any) -> None:
    marker = tmp_path / "ran"
    worker = write_fake_worker(tmp_path, f"open({str(marker)!r}, 'w').close()")
    runner = LocalFixtureRunner(local_settings(worker))
    target = ScanTarget(kind="url", value="https://example.com/")
    await runner.run(SCAN_ID, target, event_log)

    assert "refuses live URLs" in event_log.only("scan_error")["message"]
    assert not marker.exists()


async def test_local_runner_passes_no_secrets_to_the_worker(
    tmp_path: Path, event_log: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("VULTR_API_KEY", SECRET)
    monkeypatch.setenv("LD_ANYTHING", "x")
    worker = write_fake_worker(
        tmp_path,
        """
        import json, os
        names = ",".join(sorted(os.environ))
        print(json.dumps({"type": "popup", "data": {"url": names}}), flush=True)
        """,
    )
    await asyncio.wait_for(LocalFixtureRunner(local_settings(worker)).run(SCAN_ID, FIXTURE, event_log), TEST_TIMEOUT_S)
    names = event_log.only("popup")["url"].split(",")
    assert "VULTR_API_KEY" not in names
    assert "LD_ANYTHING" not in names


async def test_local_runner_deadline_kills_the_whole_process_group(tmp_path: Path, event_log: Any) -> None:
    pid_file = tmp_path / "child.pid"
    worker = write_fake_worker(
        tmp_path,
        f"""
        import json, subprocess, sys, time
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])
        open({str(pid_file)!r}, "w").write(str(child.pid))
        print(json.dumps({{"type": "page_crash", "data": {{}}}}), flush=True)
        time.sleep(600)
        """,
    )
    runner = LocalFixtureRunner(local_settings(worker, deadline_s=AUDITED_DEADLINE_S))
    await asyncio.wait_for(runner.run(SCAN_ID, FIXTURE, event_log), TEST_TIMEOUT_S)

    assert event_log.only("deadline_killed") == {"deadline_s": AUDITED_DEADLINE_S}
    assert "page_crash" in event_log.types("worker")

    child_pid = int(pid_file.read_text())
    for _ in range(100):
        if not _process_alive(child_pid):
            break
        await asyncio.sleep(0.05)
    assert not _process_alive(child_pid), "a descendant survived the kill"
    assert rows(event_log)["freeze"]["status"] == "observed"
    assert rows(event_log)["limits"]["status"] == "observed"


def _process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


async def test_local_runner_enforces_output_caps(tmp_path: Path, event_log: Any) -> None:
    worker = write_fake_worker(
        tmp_path,
        """
        import sys, time
        sys.stdout.write("x" * 2048)
        sys.stdout.flush()
        time.sleep(600)
        """,
    )
    runner = LocalFixtureRunner(local_settings(worker, max_line_bytes=1024))
    await asyncio.wait_for(runner.run(SCAN_ID, FIXTURE, event_log), TEST_TIMEOUT_S)
    assert event_log.only("output_limit_killed") == {"reason": REASON_LINE}


async def test_local_runner_reports_a_worker_crash(tmp_path: Path, event_log: Any) -> None:
    worker = write_fake_worker(tmp_path, "import sys; sys.exit(7)")
    await asyncio.wait_for(LocalFixtureRunner(local_settings(worker)).run(SCAN_ID, FIXTURE, event_log), TEST_TIMEOUT_S)
    assert "7" in event_log.only("scan_error")["message"]


async def test_local_runner_reports_a_missing_interpreter(tmp_path: Path, event_log: Any) -> None:
    settings = local_settings(tmp_path / "worker.py", python_bin=str(tmp_path / "no-python"))
    await asyncio.wait_for(LocalFixtureRunner(settings).run(SCAN_ID, FIXTURE, event_log), TEST_TIMEOUT_S)
    assert "could not be started" in event_log.only("scan_error")["message"]


async def test_local_reap_is_a_no_op(tmp_path: Path) -> None:
    assert await LocalFixtureRunner(local_settings(tmp_path / "w.py")).reap() == 0


# --- Canary ----------------------------------------------------------------------


async def test_a_canary_that_reaches_the_container_fails_the_audit(
    fake_docker: Any, event_log: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(SECRET_CANARY_ENV, "canary-value-for-this-test")
    fake_docker.configure(scenario="hang", env=["PATH=/usr/bin", "X=canary-value-for-this-test"])
    await run_scan(fake_docker, event_log)
    assert event_log.only("secret_audit")["ok"] is False
    assert "canary-value-for-this-test" not in json.dumps(event_log.events)
