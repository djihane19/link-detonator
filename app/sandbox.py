"""Runs the worker and turns its output into events.

DockerRunner is the real sandbox. LocalFixtureRunner exists only so the UI can be
developed on a machine without Docker, and is not a sandbox at all.

Runners report through `emit(type, data, source)`. The caller assigns the envelope
(`seq`, `ts`), so nothing a worker prints can influence it.

Host event order for a Docker scan:
  sandbox_created, secret_audit, <worker events>,
  [deadline_killed | output_limit_killed], [output_dropped], sandbox_exit, sandbox_removed
`scan_error` may appear when something prevents that sequence. `scan_finished` and
`verdict` belong to the job manager.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import re
import secrets
import signal
from collections import Counter
from collections.abc import Awaitable, Callable, Coroutine, Iterator, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from typing import Any, Literal, Protocol, runtime_checkable

from app.config import SECRET_CANARY_ENV, Settings
from app.models import WORKER_EVENT_CAPS, ScanTarget, decode_worker_line

logger = logging.getLogger(__name__)

Emit = Callable[[str, dict[str, Any], str], Awaitable[None]]
WorkerEvent = tuple[str, dict[str, Any]]

SANDBOX_LABEL = "link-detonator=1"
SANDBOX_NETWORK = "ld-sandbox"
SANDBOX_TMPFS = "/tmp:rw,noexec,nosuid,nodev,size=256m"
SANDBOX_POLICY: dict[str, Any] = {
    "network": SANDBOX_NETWORK,
    "read_only_rootfs": True,
    "tmpfs": SANDBOX_TMPFS,
    "cap_drop": "ALL",
    "no_new_privileges": True,
    "pids_limit": 256,
    "memory": "1g",
    "memory_swap": "1g",
    "cpus": "1",
    "shm_size": "128m",
    "nofile": "1024:1024",
    "log_driver": "none",
    "user": "pwuser",
}

REASON_LINE = "line_too_long"
REASON_TOTAL = "total_output_exceeded"
REASON_EVENTS = "event_count_exceeded"

_READ_CHUNK_BYTES = 64 * 1024
_STDERR_TAIL_BYTES = 4096
_CONTAINER_POLL_S = 0.1
_KILL_DRAIN_S = 1.0
_CLIENT_EXIT_GRACE_S = 3.0
_OOM_EVENT_GRACE_S = 0.3
_REMOVAL_ATTEMPTS = 5
_REMOVAL_RETRY_DELAY_S = 0.4
# Leaves time for container start and teardown. The bounds are what worker.py accepts.
_WORKER_DEADLINE_SHARE = 0.75
_WORKER_MIN_DEADLINE_S = 5.0
_WORKER_MAX_DEADLINE_S = 300.0

# Bounded wait for a killed container to stop: 30 x 0.1 s.
KILL_CONFIRM_POLLS = 30
KILL_CONFIRM_INTERVAL_S = 0.1

_DOCKER_NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$")
_CONTAINER_ID = re.compile(r"^[0-9a-f]{12,64}$")
_NO_SUCH_CONTAINER = re.compile(r"no such (container|object)", re.IGNORECASE)

# The docker client and the local worker get an allowlisted environment. Neither
# needs host secrets, and the local worker has no container around it to stop a leak.
_DOCKER_CLIENT_ENV = (
    "PATH",
    "HOME",
    "XDG_RUNTIME_DIR",
    "DOCKER_HOST",
    "DOCKER_CONFIG",
    "DOCKER_CONTEXT",
    "DOCKER_TLS_VERIFY",
    "DOCKER_CERT_PATH",
)
_LOCAL_WORKER_ENV = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "PLAYWRIGHT_BROWSERS_PATH")


class OutputLimitExceeded(Exception):
    """The worker broke a hard output cap, so the sandbox must be killed."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class RunnerRefused(RuntimeError):
    """A runner's safety guard refused to start."""


@runtime_checkable
class SandboxRunner(Protocol):
    # False means nothing contains the worker, and the UI must say so permanently.
    isolated: bool

    async def run(self, scan_id: str, target: ScanTarget, emit: Emit) -> None:
        """Runs one scan to completion, reporting through emit(type, data, source)."""
        ...

    async def reap(self) -> int:
        """Removes sandboxes left by a previous process. Call only before any scan starts."""
        ...


def build_runner(settings: Settings) -> SandboxRunner:
    return LocalFixtureRunner(settings) if settings.dev_local_runner else DockerRunner(settings)


def owner_label(settings: Settings) -> str:
    return f"link-detonator.owner={settings.owner}"


def container_name(scan_id: str) -> str:
    name = f"ld-{scan_id}"
    if not _DOCKER_NAME.fullmatch(name):
        raise ValueError("scan id cannot form a container name")
    return name


def worker_args(target: ScanTarget) -> list[str]:
    """Worker arguments for a Docker scan. `--offline` is never used in the sandbox."""
    return ["--url", target.value] if target.kind == "url" else ["--fixture", target.value]


def worker_deadline_args(settings: Settings) -> list[str]:
    """The worker must stop before the host kills it, or worker_finished is lost."""
    share = settings.deadline_s * _WORKER_DEADLINE_SHARE
    deadline = min(max(share, _WORKER_MIN_DEADLINE_S), _WORKER_MAX_DEADLINE_S)
    return ["--deadline", f"{deadline:g}"]


def build_docker_argv(
    name: str, image: str, target_args: Sequence[str], settings: Settings
) -> list[str]:
    """The exact `docker run` command for a scan. Pure, so it can be tested without Docker."""
    if not _DOCKER_NAME.fullmatch(name):
        raise ValueError("invalid container name")
    # Values placed before the image would be read as docker flags.
    if not image or image.startswith("-"):
        raise ValueError("invalid image name")
    if settings.runtime and not _DOCKER_NAME.fullmatch(settings.runtime):
        raise ValueError("invalid runtime name")

    argv = [
        settings.docker_bin, "run", "--rm", "--init",
        "--name", name,
        "--label", SANDBOX_LABEL,
        "--label", owner_label(settings),
        "--network", SANDBOX_NETWORK,
        "--read-only",
        "--tmpfs", SANDBOX_TMPFS,
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", "256",
        "--memory", "1g",
        "--memory-swap", "1g",
        "--cpus", "1",
        "--shm-size", "128m",
        "--ulimit", "nofile=1024:1024",
        "--log-driver", "none",
        "--user", "pwuser",
    ]  # fmt: skip
    if settings.runtime:
        argv += ["--runtime", settings.runtime]
    return [*argv, image, "python", "/worker/worker.py", *target_args]


def build_local_argv(fixture: str, settings: Settings) -> list[str]:
    return [
        settings.python_bin,
        str(settings.worker_path),
        "--fixture",
        fixture,
        "--offline",
        *worker_deadline_args(settings),
    ]


def audit_container_env(inspect_info: Mapping[str, Any], secrets: Sequence[str]) -> bool:
    """True only if the container's env is readable and contains no secret value.

    Substring matching also catches a value wrapped in a longer entry.
    """
    config = inspect_info.get("Config")
    if not isinstance(config, Mapping) or "Env" not in config:
        return False
    env = config["Env"]
    if env is None:
        return True
    if not isinstance(env, list) or not all(isinstance(entry, str) for entry in env):
        return False
    return not any(secret in entry for secret in secrets for entry in env)


def is_loopback_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class WorkerStreamParser:
    """Turns hostile worker bytes into validated events, enforcing every output cap."""

    def __init__(self, settings: Settings) -> None:
        self._max_line = settings.max_line_bytes
        self._max_total = settings.max_total_bytes
        self._max_events = settings.max_events
        self._line = bytearray()
        self._total = 0
        self._lines = 0
        self._per_type: Counter[str] = Counter()
        self.dropped = 0

    def charge(self, size: int) -> None:
        """Counts bytes against the total cap. Stderr is charged here too."""
        self._total += size
        if self._total > self._max_total:
            raise OutputLimitExceeded(REASON_TOTAL)

    def feed(self, chunk: bytes) -> Iterator[WorkerEvent]:
        """Yields complete events in order. Raises at the point a hard cap is broken."""
        self.charge(len(chunk))
        start = 0
        while (newline := chunk.find(b"\n", start)) >= 0:
            self._extend_line(chunk, start, newline)
            start = newline + 1
            line = bytes(self._line)
            self._line.clear()
            event = self._accept(line)
            if event is not None:
                yield event
        self._extend_line(chunk, start, len(chunk))

    def finish(self) -> Iterator[WorkerEvent]:
        """Handles a final line with no newline, such as one cut short by a kill."""
        if self._line:
            line = bytes(self._line)
            self._line.clear()
            event = self._accept(line)
            if event is not None:
                yield event

    def _extend_line(self, chunk: bytes, start: int, end: int) -> None:
        if len(self._line) + end - start > self._max_line:
            raise OutputLimitExceeded(REASON_LINE)
        self._line += chunk[start:end]

    def _accept(self, line: bytes) -> WorkerEvent | None:
        # Dropped lines count too, or junk lines could dodge the cap.
        self._lines += 1
        if self._lines > self._max_events:
            raise OutputLimitExceeded(REASON_EVENTS)
        event = decode_worker_line(line)
        if event is None:
            self.dropped += 1
            return None
        cap = WORKER_EVENT_CAPS.get(event[0])
        if cap is not None:
            self._per_type[event[0]] += 1
            if self._per_type[event[0]] > cap:
                self.dropped += 1
                return None
        return event


class _OutputPump:
    """Reads a process's stdout and stderr concurrently so neither pipe can block it."""

    def __init__(self, proc: asyncio.subprocess.Process, settings: Settings, emit: Emit) -> None:
        self._proc = proc
        self._emit = emit
        self.parser = WorkerStreamParser(settings)
        self.stderr_tail = b""
        self._stdout_task: asyncio.Task[None] | None = None
        self._stderr_task: asyncio.Task[None] | None = asyncio.create_task(self._read_stderr())
        self._discards: list[asyncio.Task[None]] = []

    async def run(self) -> None:
        """Returns at EOF on both streams. Raises on a broken cap or a failing emit."""
        assert self._stderr_task is not None
        self._stdout_task = asyncio.create_task(self._read_stdout())
        done, _ = await asyncio.wait(
            {self._stdout_task, self._stderr_task}, return_when=asyncio.FIRST_EXCEPTION
        )
        for task in done:
            task.result()

    async def settle(self, timeout_s: float) -> None:
        """After a kill, gives already-written evidence a moment to arrive."""
        if self._stdout_task is not None:
            await asyncio.wait({self._stdout_task}, timeout=timeout_s)

    async def discard_remaining(self) -> None:
        """Stops interpreting output but keeps draining, so the process can still exit."""
        await _cancel_tasks(self._stdout_task, self._stderr_task)
        self._stdout_task = self._stderr_task = None
        if not self._discards:
            self._discards = [
                asyncio.create_task(_discard(self._proc.stdout)),
                asyncio.create_task(_discard(self._proc.stderr)),
            ]

    async def close(self) -> None:
        await _cancel_tasks(self._stdout_task, self._stderr_task, *self._discards)
        self._stdout_task = self._stderr_task = None
        self._discards = []

    async def _read_stdout(self) -> None:
        stream = self._proc.stdout
        assert stream is not None
        while chunk := await stream.read(_READ_CHUNK_BYTES):
            for event_type, data in self.parser.feed(chunk):
                await self._emit(event_type, data, "worker")
        for event_type, data in self.parser.finish():
            await self._emit(event_type, data, "worker")

    async def _read_stderr(self) -> None:
        # Never emitted: stderr carries worker-controlled text. The tail is for the log.
        stream = self._proc.stderr
        assert stream is not None
        while chunk := await stream.read(_READ_CHUNK_BYTES):
            self.parser.charge(len(chunk))
            self.stderr_tail = (self.stderr_tail + chunk)[-_STDERR_TAIL_BYTES:]


async def _discard(stream: asyncio.StreamReader | None) -> None:
    if stream is not None:
        while await stream.read(_READ_CHUNK_BYTES):
            pass


async def _cancel_tasks(*tasks: asyncio.Task[None] | None) -> None:
    live = [task for task in tasks if task is not None]
    for task in live:
        task.cancel()
    # return_exceptions also retrieves a cap breach nobody is waiting for any more.
    await asyncio.gather(*live, return_exceptions=True)


async def _wait_for_exit(proc: asyncio.subprocess.Process, timeout_s: float) -> bool:
    try:
        async with asyncio.timeout(timeout_s):
            await proc.wait()
    except TimeoutError:
        return False
    return True


def _close_transport(proc: asyncio.subprocess.Process) -> None:
    # wait() only returns once every pipe has closed, which a surviving descendant can
    # prevent. asyncio has no public way to let go of those pipes.
    transport = getattr(proc, "_transport", None)
    if transport is not None:
        transport.close()


# Cleanup outlives a cancelled caller, so its task needs a strong reference.
_cleanup_tasks: set[asyncio.Task[None]] = set()


async def _run_cleanup(cleanup: Coroutine[Any, Any, None]) -> None:
    """Runs cleanup to completion even if the caller is cancelled again meanwhile."""
    task = asyncio.create_task(cleanup)
    _cleanup_tasks.add(task)
    task.add_done_callback(_cleanup_tasks.discard)
    await asyncio.shield(task)


@dataclass(frozen=True)
class _CommandResult:
    returncode: int | None  # None: it could not start or it timed out.
    stdout: str = ""
    stderr: str = ""


@dataclass(frozen=True)
class _Inspection:
    state: Literal["exists", "missing", "unknown"]
    info: dict[str, Any] | None = None


class _DockerClient:
    """The short-lived docker commands. Each one is bounded and never raises."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._env = {k: os.environ[k] for k in _DOCKER_CLIENT_ENV if k in os.environ}

    @property
    def env(self) -> dict[str, str]:
        return self._env

    async def command(self, *args: str) -> _CommandResult:
        try:
            proc = await asyncio.create_subprocess_exec(
                self._settings.docker_bin,
                *args,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self._env,
            )
        except OSError:
            return _CommandResult(None)
        try:
            async with asyncio.timeout(self._settings.docker_command_timeout_s):
                stdout, stderr = await proc.communicate()
        except TimeoutError:
            return _CommandResult(None)
        finally:
            if proc.returncode is None:
                with suppress(ProcessLookupError):
                    proc.kill()
                _close_transport(proc)
        return _CommandResult(
            proc.returncode,
            stdout.decode("utf-8", "replace"),
            stderr.decode("utf-8", "replace"),
        )

    async def inspect(self, container: str) -> _Inspection:
        """Distinguishes "does not exist" from "could not tell", such as a daemon outage."""
        result = await self.command("inspect", "--type", "container", container)
        if result.returncode == 0:
            try:
                parsed = json.loads(result.stdout)
            except ValueError:
                return _Inspection("unknown")
            if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
                return _Inspection("exists", parsed[0])
            return _Inspection("unknown")
        if result.returncode is not None and _NO_SUCH_CONTAINER.search(result.stderr):
            return _Inspection("missing")
        return _Inspection("unknown")

    async def remove_and_verify(self, container: str) -> bool:
        """True only once inspect reports the container does not exist.

        Retries because `rm -f` can lose a race with `--rm`: the daemon then answers
        "removal already in progress" and the container is briefly still visible.
        """
        for attempt in range(_REMOVAL_ATTEMPTS):
            if attempt:
                await asyncio.sleep(_REMOVAL_RETRY_DELAY_S)
            await self.command("rm", "-f", container)
            if (await self.inspect(container)).state == "missing":
                return True
        return False


def plant_secret_canary(env: dict[str, str] | os._Environ[str] = os.environ) -> str:
    """Puts a random value in the orchestrator's environment and returns it.

    The docker client gets an allowlisted environment, so this should never reach a
    container. Looking for it means the audit really tests that on a VM with no other
    secret configured, instead of comparing against nothing.
    """
    existing = env.get(SECRET_CANARY_ENV)
    if existing:
        return existing
    value = secrets.token_hex(24)
    env[SECRET_CANARY_ENV] = value
    return value


class _OomWatcher:
    """Listens for the container's OOM event.

    `--rm` deletes the container on exit, so State.OOMKilled can no longer be read by
    the time we know it died. `docker events` is the record that outlives it.
    """

    def __init__(self, settings: Settings, client: _DockerClient, name: str) -> None:
        self._argv = [
            settings.docker_bin, "events",
            "--filter", "type=container",
            "--filter", f"container={name}",
            "--filter", "event=oom",
            "--format", "{{.Action}}",
        ]  # fmt: skip
        self._env = client.env
        self._proc: asyncio.subprocess.Process | None = None
        self._reader: asyncio.Task[None] | None = None
        self._seen = False

    async def start(self) -> None:
        try:
            self._proc = await asyncio.create_subprocess_exec(
                *self._argv,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
                env=self._env,
            )
        except OSError:
            return
        self._reader = asyncio.create_task(self._read())

    async def finish(self) -> bool | None:
        """True or False once known. None if the watcher was not listening at the end."""
        if self._proc is None or self._reader is None:
            return None
        await asyncio.wait({self._reader}, timeout=_OOM_EVENT_GRACE_S)
        listening = self._proc.returncode is None
        with suppress(ProcessLookupError):
            self._proc.kill()
        await _cancel_tasks(self._reader)
        if not await _wait_for_exit(self._proc, _CLIENT_EXIT_GRACE_S):
            _close_transport(self._proc)
        return True if self._seen else (False if listening else None)

    async def _read(self) -> None:
        assert self._proc is not None and self._proc.stdout is not None
        if (await self._proc.stdout.readline()).strip():
            self._seen = True
        else:
            await self._proc.wait()


class DockerRunner:
    """Runs each scan in a throwaway container under the exact contract policy."""

    isolated = True

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._canary = plant_secret_canary()

    async def run(self, scan_id: str, target: ScanTarget, emit: Emit) -> None:
        await _DockerScan(self._settings, scan_id, target, emit, self._canary).execute()

    async def reap(self) -> int:
        """Removes this owner's labelled containers. Must only run before any scan starts."""
        client = _DockerClient(self._settings)
        listing = await client.command(
            "ps", "-aq", "--filter", f"label={SANDBOX_LABEL}", "--filter", f"label={owner_label(self._settings)}"
        )
        if listing.returncode != 0:
            logger.warning("reaper could not list sandboxes")
            return 0
        removed = 0
        for container_id in listing.stdout.split():
            if not _CONTAINER_ID.fullmatch(container_id):
                continue
            if await client.remove_and_verify(container_id):
                removed += 1
            else:
                logger.error("reaper could not remove sandbox %s", container_id)
        return removed


class _DockerScan:
    """The state and lifecycle of one Docker scan."""

    def __init__(
        self, settings: Settings, scan_id: str, target: ScanTarget, emit: Emit, canary: str
    ) -> None:
        self._settings = settings
        self._emit = emit
        self._canary = canary
        self._name = container_name(scan_id)
        self._argv = build_docker_argv(
            self._name, settings.image, [*worker_args(target), *worker_deadline_args(settings)], settings
        )
        self._client = _DockerClient(settings)
        self._oom = _OomWatcher(settings, self._client, self._name)
        self._proc: asyncio.subprocess.Process | None = None
        self._pump: _OutputPump | None = None
        self._container_seen = False

    async def execute(self) -> None:
        try:
            await self._oom.start()
            try:
                self._proc = await asyncio.create_subprocess_exec(
                    *self._argv,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=self._client.env,
                )
            except OSError:
                logger.exception("could not start the docker client")
                await self._emit(
                    "scan_error", {"message": "The docker client could not be started."}, "host"
                )
                return
            self._pump = _OutputPump(self._proc, self._settings, self._emit)
            await self._supervise()
        finally:
            await _run_cleanup(self._cleanup())

    async def _supervise(self) -> None:
        assert self._pump is not None and self._proc is not None
        deadline = asyncio.timeout(self._settings.deadline_s)
        try:
            async with deadline:
                if await self._admit():
                    await self._pump.run()
                    await self._proc.wait()
        except OutputLimitExceeded as exc:
            kill = await self._kill()
            confirmed = await self._kill_took_effect(kill)
            await self._emit(
                "output_limit_killed", {"reason": exc.reason, "kill_confirmed": confirmed}, "host"
            )
        except TimeoutError:
            if not deadline.expired():
                raise
            kill = await self._client.command("kill", self._name)
            await self._pump.settle(_KILL_DRAIN_S)
            await self._kill()
            confirmed = await self._kill_took_effect(kill)
            await self._emit(
                "deadline_killed",
                {"deadline_s": self._settings.deadline_s, "kill_confirmed": confirmed},
                "host",
            )

    async def _kill_took_effect(self, kill: _CommandResult | None) -> bool:
        """True only if docker accepted the kill and the container is then not running.

        Without this, a report would say the host killed a sandbox it only asked to kill.
        """
        if kill is None or kill.returncode != 0:
            return False
        # docker kill returns once the signal is sent, so the state can lag for a moment.
        # Measured on the VM: a killed sandbox is gone within about 300 ms.
        for _ in range(KILL_CONFIRM_POLLS):
            inspection = await self._client.inspect(self._name)
            if inspection.state == "missing":
                return True
            state = inspection.info.get("State") if inspection.info else None
            if isinstance(state, dict) and state.get("Running") is False:
                return True
            await asyncio.sleep(KILL_CONFIRM_INTERVAL_S)
        return False

    async def _admit(self) -> bool:
        """Reports the sandbox and audits it. Worker output is read only after a clean audit."""
        info = await self._wait_for_container()
        if info is None:
            assert self._proc is not None
            await self._emit(
                "scan_error",
                {"message": f"The sandbox exited before its audit (code {self._proc.returncode})."},
                "host",
            )
            return False

        self._container_seen = True
        host_config = info.get("HostConfig")
        runtime = host_config.get("Runtime") if isinstance(host_config, dict) else None
        await self._emit(
            "sandbox_created",
            {
                "name": self._name,
                "image": self._settings.image,
                "runtime": runtime if isinstance(runtime, str) else self._settings.runtime,
                "policy": dict(SANDBOX_POLICY),
            },
            "host",
        )

        values = [*self._settings.secret_values(), self._canary]
        ok = audit_container_env(info, values)
        await self._emit(
            "secret_audit", {"ok": ok, "checked_count": len(values), "canary": True}, "host"
        )
        if not ok:
            await self._kill()
            await self._emit(
                "scan_error",
                {"message": "The secret audit failed, so the sandbox was killed unread."},
                "host",
            )
        return ok

    async def _wait_for_container(self) -> dict[str, Any] | None:
        """Polls until the container exists. None if `docker run` exited first."""
        assert self._proc is not None
        while True:
            inspection = await self._client.inspect(self._name)
            if inspection.info is not None:
                return inspection.info
            if self._proc.returncode is not None:
                return None
            await asyncio.sleep(_CONTAINER_POLL_S)

    async def _kill(self) -> _CommandResult | None:
        """Kills the container and makes sure the attached client is gone too.

        Returns the `docker kill` result, or None if the client had already exited.
        """
        proc, pump = self._proc, self._pump
        if proc is None or pump is None:
            return None
        kill = await self._client.command("kill", self._name) if proc.returncode is None else None
        await pump.discard_remaining()
        if await _wait_for_exit(proc, _CLIENT_EXIT_GRACE_S):
            return kill
        with suppress(ProcessLookupError):
            proc.kill()
        if not await _wait_for_exit(proc, _CLIENT_EXIT_GRACE_S):
            _close_transport(proc)
        return kill

    async def _cleanup(self) -> None:
        # Removal comes before any emit, so a failing event store cannot leave a live
        # hostile page behind. None of the docker steps raises.
        await self._kill()
        verified = await self._client.remove_and_verify(self._name)
        oom_killed = await self._oom.finish()
        if self._pump is not None:
            await self._pump.close()
            self._log_stderr_on_failure()

        if self._pump is not None and self._pump.parser.dropped:
            await self._emit_quietly("output_dropped", {"count": self._pump.parser.dropped})
        if self._container_seen and self._proc is not None:
            await self._emit_quietly(
                "sandbox_exit", {"exit_code": self._proc.returncode, "oom_killed": oom_killed}
            )
        await self._emit_quietly("sandbox_removed", {"verified": verified})

    def _log_stderr_on_failure(self) -> None:
        assert self._pump is not None and self._proc is not None
        if not self._container_seen and self._pump.stderr_tail:
            # Worker-controlled text in the normal case, so it is escaped and never emitted.
            logger.warning(
                "docker run for %s failed: %r", self._name, self._pump.stderr_tail[-512:]
            )

    async def _emit_quietly(self, event_type: str, data: dict[str, Any]) -> None:
        try:
            await self._emit(event_type, data, "host")
        except Exception:
            logger.exception("could not emit %s", event_type)


class LocalFixtureRunner:
    """Runs a fixture as a plain subprocess, for UI work on a machine without Docker.

    THIS IS NOT A SANDBOX. It therefore emits no event that implies isolation
    (`sandbox_created`, `secret_audit`, `sandbox_exit`, `sandbox_removed`), and the
    UI must show a permanent "DEV: NOT SANDBOXED" banner while it is in use.
    """

    isolated = False

    def __init__(self, settings: Settings) -> None:
        if not settings.dev_local_runner:
            raise RunnerRefused("The local runner requires LD_DEV_LOCAL_RUNNER=1.")
        if not is_loopback_host(settings.bind_host):
            raise RunnerRefused("The local runner refuses to start unless bound to loopback.")
        self._settings = settings

    async def reap(self) -> int:
        return 0

    async def run(self, scan_id: str, target: ScanTarget, emit: Emit) -> None:
        if target.kind != "fixture":
            await emit("scan_error", {"message": "The local runner refuses live URLs."}, "host")
            return
        env = {k: os.environ[k] for k in _LOCAL_WORKER_ENV if k in os.environ}
        try:
            proc = await asyncio.create_subprocess_exec(
                *build_local_argv(target.value, self._settings),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                # Its own process group, so Chromium dies with the worker.
                start_new_session=True,
            )
        except OSError:
            logger.exception("could not start the local worker")
            await emit("scan_error", {"message": "The local worker could not be started."}, "host")
            return

        pump = _OutputPump(proc, self._settings, emit)
        try:
            await self._supervise(proc, pump, emit)
        finally:
            await _run_cleanup(self._finish(proc, pump, emit))

    async def _supervise(
        self, proc: asyncio.subprocess.Process, pump: _OutputPump, emit: Emit
    ) -> None:
        deadline = asyncio.timeout(self._settings.deadline_s)
        try:
            async with deadline:
                await pump.run()
                await proc.wait()
        except OutputLimitExceeded as exc:
            await self._stop(proc, pump)
            await emit("output_limit_killed", {"reason": exc.reason}, "host")
        except TimeoutError:
            if not deadline.expired():
                raise
            await self._stop(proc, pump)
            await emit("deadline_killed", {"deadline_s": self._settings.deadline_s}, "host")
        else:
            if proc.returncode:
                message = f"The worker exited with code {proc.returncode}."
                await emit("scan_error", {"message": message}, "host")

    async def _stop(self, proc: asyncio.subprocess.Process, pump: _OutputPump) -> None:
        _kill_process_group(proc)
        await pump.discard_remaining()
        if not await _wait_for_exit(proc, _CLIENT_EXIT_GRACE_S):
            _close_transport(proc)

    async def _finish(
        self, proc: asyncio.subprocess.Process, pump: _OutputPump, emit: Emit
    ) -> None:
        await self._stop(proc, pump)
        await pump.close()
        if pump.parser.dropped:
            try:
                await emit("output_dropped", {"count": pump.parser.dropped}, "host")
            except Exception:
                logger.exception("could not emit output_dropped")


def _kill_process_group(proc: asyncio.subprocess.Process) -> None:
    # After the leader exits its pid stays reserved as the group id while any member
    # is alive, so this still reaches leftovers. Errors mean the group is already gone.
    with suppress(ProcessLookupError, PermissionError):
        os.killpg(proc.pid, signal.SIGKILL)
