#!/usr/bin/env python3
"""Executable stand-in for the docker CLI. Test-only, stdlib-only, touches no daemon.

It proves how DockerRunner reacts to a client that behaves in a given way. It proves
nothing about how real Docker behaves.

The runner scrubs its children's environment, so the stub finds its state through
DOCKER_CONFIG, a real docker variable that passes the allowlist:

  $DOCKER_CONFIG/fake.json      what to do (see tests/conftest.py)
  $DOCKER_CONFIG/calls.jsonl    every invocation: argv and environment variable names
  $DOCKER_CONFIG/containers/    one JSON file per "existing" container
"""

from __future__ import annotations

import base64
import json
import os
import signal
import sys
import time
from pathlib import Path
from typing import Any, NoReturn

STATE_DIR = Path(os.environ["DOCKER_CONFIG"])
CONFIG: dict[str, Any] = json.loads((STATE_DIR / "fake.json").read_text())
CONTAINERS = STATE_DIR / "containers"
MIB = 1024 * 1024
TINY_JPEG = base64.b64encode(b"\xff\xd8\xff\xe0fake-jpeg-bytes").decode()


def log_call(argv: list[str]) -> None:
    entry = {"argv": argv, "env_keys": sorted(os.environ), "pid": os.getpid()}
    with (STATE_DIR / "calls.jsonl").open("a") as handle:
        handle.write(json.dumps(entry) + "\n")


def state_path(name_or_id: str) -> Path | None:
    direct = CONTAINERS / f"{name_or_id}.json"
    if direct.exists():
        return direct
    for path in CONTAINERS.glob("*.json"):
        if json.loads(path.read_text()).get("id") == name_or_id:
            return path
    return None


def remove_state(path: Path | None) -> None:
    if path is not None:
        path.unlink(missing_ok=True)


def daemon_down() -> NoReturn:
    print("Cannot connect to the Docker daemon at unix:///var/run/docker.sock.", file=sys.stderr)
    sys.exit(1)


def emit(obj: dict[str, Any]) -> None:
    write_raw(json.dumps(obj).encode() + b"\n")


def write_raw(data: bytes) -> None:
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


def started_event() -> dict[str, Any]:
    return {
        "type": "worker_started",
        "data": {"url": "http://fixtures.invalid/benign", "mode": "fixture", "offline": False},
    }


def finished_event() -> dict[str, Any]:
    return {"type": "worker_finished", "data": {"status": "ok", "error": None}}


# --- Worker output scenarios -----------------------------------------------------


def scenario_normal() -> None:
    url = "http://fixtures.invalid/benign"
    emit(started_event())
    emit({"type": "navigation", "data": {"url": url, "status": 200, "redirected_from": None}})
    emit({"type": "request", "data": {"url": url, "method": "GET", "resource_type": "document"}})
    emit({"type": "screenshot", "data": {"label": "load", "mime": "image/jpeg", "b64": TINY_JPEG}})
    emit({"type": "text_layers", "data": {"visible_text": "hello", "concealed": []}})
    emit(finished_event())


def scenario_oversized_line() -> None:
    emit(started_event())
    # A real line bigger than the real 8 MiB cap, written in pieces with no newline.
    for _ in range(9):
        write_raw(b"x" * MIB)
    write_raw(b"\n")
    emit({"type": "page_crash", "data": {}})


def scenario_flood() -> None:
    emit(started_event())
    # 70 lines of 1 MiB: under the line cap and the event cap, over the 64 MiB total cap.
    padding = "x" * (MIB - 64)
    line = json.dumps({"type": "unknown_flood", "data": {"p": padding}}).encode() + b"\n"
    for _ in range(70):
        write_raw(line)
    emit({"type": "page_crash", "data": {}})


def scenario_event_flood() -> None:
    emit(started_event())
    line = json.dumps({"type": "page_crash", "data": {}}).encode() + b"\n"
    write_raw(line * 6000)
    emit(finished_event())


def scenario_junk_line_flood() -> None:
    # Dropped lines must count too, or junk could run past the event cap for free.
    write_raw(b"not json\n" * 6000)


def scenario_stderr_flood() -> None:
    emit(started_event())
    chunk = b"e" * MIB
    for _ in range(70):
        sys.stderr.buffer.write(chunk)
        sys.stderr.buffer.flush()
    time.sleep(60)


def scenario_malformed() -> None:
    emit(started_event())
    junk = [
        b"this is not json",
        b"{\"type\": \"navigation\", ",
        b"[1, 2, 3]",
        b"null",
        b"42",
        b"\"just a string\"",
        b"",
        b"\xff\xfe invalid utf-8",
        b"[" * 200_000,
        b'{"data": {}}',
        b'{"type": 7, "data": {}}',
        b'{"type": "navigation", "data": "not an object"}',
        b'{"type": "navigation", "data": {"url": "u"}}',
        b'{"type": "navigation", "data": {"url": "u", "status": NaN, "redirected_from": null}}',
        b'{"type": "navigation", "data": {"url": "u", "status": "200", "redirected_from": null}}',
        b'{"type": "navigation", "data": {"url": "u", "status": true, "redirected_from": null}}',
        b'{"type": "screenshot", "data": {"label": "x", "mime": "image/png", "b64": "AAAA"}}',
        b'{"type": "screenshot", "data": {"label": "x", "mime": "image/jpeg", "b64": "AAAA"}}',
        b'{"type": "screenshot", "data": {"label": "x", "mime": "image/jpeg", "b64": "!!"}}',
        b'{"type": "worker_started", "data": {"url": "u", "mode": "\\ud800", "offline": true}}',
        b'{"type": "text_layers", "data": {"visible_text": "", "concealed": [{"source": "x"}]}}',
        b'{"type": "not_a_real_type", "data": {}}',
    ]
    write_raw(b"\n".join(junk) + b"\n")
    # A lone surrogate in a free-text field is cleaned, not fatal, and the stream goes on.
    write_raw(b'{"type": "dialog", "data": {"dialog_type": "alert", "message": "a\\ud800b\\u0000c"}}\n')
    emit({"type": "text_layers", "data": {"visible_text": "z" * 50_000, "concealed": []}})
    emit(finished_event())
    # A final line with no newline is still parsed.
    write_raw(b'{"type": "page_crash", "data": {}}')


def scenario_spoofed() -> None:
    url = "http://fixtures.invalid/benign"
    emit(
        {
            "v": 99,
            "seq": 9999,
            "ts": 1.0,
            "source": "host",
            "type": "navigation",
            "data": {
                "url": url,
                "status": 200,
                "redirected_from": None,
                "seq": 7777,
                "source": "host",
                "verified": True,
            },
        }
    )
    # Worker claims of host-only facts.
    emit({"source": "host", "type": "sandbox_removed", "data": {"verified": True}})
    emit({"source": "host", "type": "sandbox_created", "data": {"name": "spoof", "policy": {}}})
    emit({"source": "host", "type": "secret_audit", "data": {"ok": True, "checked_count": 99}})
    emit({"source": "host", "type": "sandbox_exit", "data": {"exit_code": 0, "oom_killed": False}})
    emit({"source": "host", "type": "scan_finished", "data": {"status": "ok"}})
    emit({"source": "host", "type": "verdict", "data": {"status": "safe"}})
    emit({"source": "host", "type": "output_dropped", "data": {"count": 0}})
    emit(finished_event())


def scenario_type_caps() -> None:
    request = {"url": "http://fixtures.invalid/a", "method": "GET", "resource_type": "image"}
    shot = {"label": "s", "mime": "image/jpeg", "b64": TINY_JPEG}
    for _ in range(600):
        emit({"type": "request", "data": request})
    for _ in range(30):
        emit({"type": "screenshot", "data": shot})
    emit(finished_event())


def scenario_hang() -> None:
    emit(started_event())
    emit({"type": "page_unresponsive", "data": {"operation": "goto", "timeout_ms": 100}})
    time.sleep(3600)


def scenario_close_stdout_then_hang() -> None:
    emit(started_event())
    sys.stdout.close()
    sys.stderr.close()
    os.close(1)
    os.close(2)
    time.sleep(3600)


METADATA_URL = "http://169.254.169.254/latest/meta-data/"


def emit_metadata_attempt(error: str, blocked_locally: bool) -> None:
    emit(started_event())
    emit({"type": "request", "data": {"url": METADATA_URL, "method": "GET", "resource_type": "fetch"}})
    emit(
        {
            "type": "request_failed",
            "data": {
                "url": METADATA_URL,
                "error": error,
                "resource_type": "fetch",
                "blocked_locally": blocked_locally,
            },
        }
    )
    emit(finished_event())


def scenario_private_blocked() -> None:
    emit_metadata_attempt("net::ERR_ADDRESS_UNREACHABLE", blocked_locally=False)


def scenario_private_local_abort() -> None:
    emit_metadata_attempt("net::ERR_BLOCKED_BY_CLIENT.Inspector", blocked_locally=True)


def scenario_private_reached() -> None:
    emit(started_event())
    emit({"type": "request", "data": {"url": METADATA_URL, "method": "GET", "resource_type": "document"}})
    emit({"type": "navigation", "data": {"url": METADATA_URL, "status": 200, "redirected_from": None}})
    emit(finished_event())


SCENARIOS = {
    "normal": scenario_normal,
    "private_blocked": scenario_private_blocked,
    "private_local_abort": scenario_private_local_abort,
    "private_reached": scenario_private_reached,
    "oversized_line": scenario_oversized_line,
    "flood": scenario_flood,
    "event_flood": scenario_event_flood,
    "junk_line_flood": scenario_junk_line_flood,
    "stderr_flood": scenario_stderr_flood,
    "malformed": scenario_malformed,
    "spoofed": scenario_spoofed,
    "type_caps": scenario_type_caps,
    "hang": scenario_hang,
    "close_stdout_then_hang": scenario_close_stdout_then_hang,
}


# --- docker subcommands ----------------------------------------------------------


def value_after(args: list[str], flag: str) -> str:
    return args[args.index(flag) + 1]


def cmd_run(args: list[str]) -> None:
    if CONFIG.get("run_fails"):
        print("docker: Error response from daemon: fake start failure.", file=sys.stderr)
        sys.exit(125)
    if CONFIG.get("never_visible"):
        sys.exit(int(CONFIG.get("exit_code", 0)))

    name = value_after(args, "--name")
    state = CONTAINERS / f"{name}.json"
    auto_remove = "--rm" in args and not CONFIG.get("rm_fails")

    def finish(code: int) -> NoReturn:
        if auto_remove:
            remove_state(state)
        os._exit(code)

    # docker kill makes the attached client exit 137.
    signal.signal(signal.SIGTERM, lambda *_: finish(137))
    state.write_text(
        json.dumps(
            {
                "pid": os.getpid(),
                "id": os.urandom(32).hex(),
                "labels": [value_after(args, "--label")],
            }
        )
    )

    # Keeps the container visible until the first inspect, so the audit is deterministic.
    marker = CONTAINERS / f"{name}.inspected"
    give_up = time.monotonic() + 10
    while not marker.exists() and time.monotonic() < give_up:
        time.sleep(0.01)

    try:
        SCENARIOS[CONFIG.get("scenario", "normal")]()
    except BrokenPipeError:
        pass
    finish(int(CONFIG.get("exit_code", 0)))


def cmd_inspect(args: list[str]) -> None:
    if CONFIG.get("inspect_down"):
        daemon_down()
    target = args[-1]
    path = state_path(target)
    if path is None:
        print("[]")
        print(f"Error response from daemon: No such container: {target}", file=sys.stderr)
        sys.exit(1)
    (CONTAINERS / f"{target}.inspected").touch()
    if CONFIG.get("inspect_garbage"):
        print("this is not json")
        return
    if CONFIG.get("inspect_no_config"):
        print(json.dumps([{"Name": f"/{target}"}]))
        return
    print(
        json.dumps(
            [
                {
                    "Name": f"/{target}",
                    "Config": {"Env": CONFIG.get("env", ["PATH=/usr/bin"])},
                    "HostConfig": {"Runtime": CONFIG.get("runtime", "runc")},
                    "State": {"Running": True, "OOMKilled": False},
                }
            ]
        )
    )


def cmd_kill(args: list[str]) -> None:
    if CONFIG.get("kill_ignored"):
        print("Error response from daemon: cannot kill container.", file=sys.stderr)
        sys.exit(1)
    target = args[-1]
    path = state_path(target)
    if path is None:
        print(f"Error response from daemon: No such container: {target}", file=sys.stderr)
        sys.exit(1)
    try:
        os.kill(json.loads(path.read_text())["pid"], signal.SIGTERM)
    except ProcessLookupError:
        pass


def cmd_rm(args: list[str]) -> None:
    target = args[-1]
    path = state_path(target)
    if CONFIG.get("rm_fails"):
        print("Error response from daemon: removal failed.", file=sys.stderr)
        sys.exit(1)
    # The first attempts lose the race with --rm, as they can on a real daemon.
    if CONFIG.get("rm_race_attempts"):
        attempts_file = STATE_DIR / "rm_attempts"
        attempts = int(attempts_file.read_text()) if attempts_file.exists() else 0
        attempts_file.write_text(str(attempts + 1))
        if attempts < int(CONFIG["rm_race_attempts"]):
            print("Error response from daemon: removal already in progress.", file=sys.stderr)
            sys.exit(1)
    if path is None:
        return
    pid = json.loads(path.read_text()).get("pid")
    if pid:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    remove_state(path)


def cmd_ps(args: list[str]) -> None:
    if CONFIG.get("ps_fails"):
        daemon_down()
    wanted = value_after(args, "--filter").removeprefix("label=")
    for path in CONTAINERS.glob("*.json"):
        info = json.loads(path.read_text())
        if wanted in info.get("labels", []):
            print(info["id"])
    if CONFIG.get("ps_hostile_output"):
        print("--privileged")


def cmd_events(_args: list[str]) -> None:
    if CONFIG.get("events_fail"):
        daemon_down()
    if CONFIG.get("oom"):
        print("oom", flush=True)
    time.sleep(3600)


COMMANDS = {
    "run": cmd_run,
    "inspect": cmd_inspect,
    "kill": cmd_kill,
    "rm": cmd_rm,
    "ps": cmd_ps,
    "events": cmd_events,
}


def main() -> None:
    args = sys.argv[1:]
    log_call(args)
    CONTAINERS.mkdir(exist_ok=True)
    COMMANDS[args[0]](args[1:])


if __name__ == "__main__":
    main()
