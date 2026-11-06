"""Environment-driven settings. Every variable uses the LD_ prefix.

Secrets are never stored on Settings: it holds only the *names* of environment
variables, so repr(settings) and any accidental log of it stay clean. That includes the
live-scan access code, which is read from the environment when it is needed.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

MIB = 1024 * 1024
PROJECT_ROOT = Path(__file__).resolve().parent.parent

_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"", "0", "false", "no", "off"})

LIVE_ACCESS_CODE_ENV = "LD_LIVE_ACCESS_CODE"
# Planted by DockerRunner, so the audit has a value to look for on any VM.
SECRET_CANARY_ENV = "LD_SECRET_CANARY"

# A key added to the orchestrator's environment is audited without anyone having to
# remember LD_SECRET_ENV_NAMES. The length floor keeps a value like "1" from matching
# every container environment by accident.
_SECRET_NAME = re.compile(r"API_?KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|ACCESS_CODE", re.IGNORECASE)
_MIN_DISCOVERED_SECRET_CHARS = 8
_NOT_SECRETS = frozenset({"LD_SECRET_ENV_NAMES", SECRET_CANARY_ENV})


@dataclass(frozen=True)
class Settings:
    # Sandbox
    docker_bin: str = "docker"
    image: str = "link-detonator-worker:latest"
    runtime: str | None = None
    deadline_s: float = 60.0
    docker_command_timeout_s: float = 15.0
    secret_env_names: tuple[str, ...] = ("VULTR_API_KEY", LIVE_ACCESS_CODE_ENV)

    # Hostile-output caps
    max_line_bytes: int = 8 * MIB
    max_total_bytes: int = 64 * MIB
    max_events: int = 5000

    # Local dev runner (no sandbox, see LocalFixtureRunner)
    dev_local_runner: bool = False
    bind_host: str = "127.0.0.1"
    worker_path: Path = PROJECT_ROOT / "worker" / "worker.py"
    python_bin: str = sys.executable

    # Job manager and storage
    data_dir: Path = PROJECT_ROOT / "data"
    concurrency: int = 2
    queue_size: int = 10
    retention_days: int = 7
    disk_cap_mb: int = 2048

    # API
    rate_per_minute: int = 5
    rate_per_hour: int = 30
    trust_proxy: bool = False
    # Reads: snapshots, event streams and screenshots.
    read_rate_per_minute: int = 240
    max_streams_per_client: int = 4

    # Abuse limits, on top of the per-client ones
    live_scans_enabled: bool = True
    live_scans_per_day: int = 50
    global_scans_per_hour: int = 120
    max_active_per_client: int = 2
    # Queue places only an access-code holder can take, so a full queue cannot lock out a demo.
    reserved_queue_slots: int = 2

    def secret_values(self, env: Mapping[str, str] | None = None) -> list[str]:
        """Values to look for in a container: the named secrets, then any secret-like variable.

        Unset or blank ones are skipped.
        """
        source = os.environ if env is None else env
        named = [source[name] for name in self.secret_env_names if source.get(name, "").strip()]
        discovered = [
            value
            for name, value in source.items()
            if name not in self.secret_env_names
            and name not in _NOT_SECRETS
            and _SECRET_NAME.search(name)
            and len(value.strip()) >= _MIN_DISCOVERED_SECRET_CHARS
        ]
        return [*named, *discovered]

    def live_access_code(self, env: Mapping[str, str] | None = None) -> str | None:
        """The code live URL scans require. Without one, live URL scans stay off."""
        source = os.environ if env is None else env
        return source.get(LIVE_ACCESS_CODE_ENV, "").strip() or None

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        """Builds settings from LD_* variables. Raises ValueError on a malformed value."""
        source = os.environ if env is None else env
        defaults = cls()
        return cls(
            docker_bin=_text(source, "LD_DOCKER_BIN", defaults.docker_bin),
            image=_text(source, "LD_IMAGE", defaults.image),
            runtime=_text(source, "LD_RUNTIME", "") or None,
            deadline_s=_positive_float(source, "LD_DEADLINE_S", defaults.deadline_s),
            docker_command_timeout_s=_positive_float(
                source, "LD_DOCKER_COMMAND_TIMEOUT_S", defaults.docker_command_timeout_s
            ),
            secret_env_names=_names(source, "LD_SECRET_ENV_NAMES", defaults.secret_env_names),
            max_line_bytes=_positive_int(source, "LD_MAX_LINE_BYTES", defaults.max_line_bytes),
            max_total_bytes=_positive_int(source, "LD_MAX_TOTAL_BYTES", defaults.max_total_bytes),
            max_events=_positive_int(source, "LD_MAX_EVENTS", defaults.max_events),
            dev_local_runner=_flag(source, "LD_DEV_LOCAL_RUNNER", defaults.dev_local_runner),
            bind_host=_text(source, "LD_BIND_HOST", defaults.bind_host),
            worker_path=Path(_text(source, "LD_WORKER_PATH", str(defaults.worker_path))),
            python_bin=_text(source, "LD_PYTHON_BIN", defaults.python_bin),
            data_dir=Path(_text(source, "LD_DATA_DIR", str(defaults.data_dir))),
            concurrency=_positive_int(source, "LD_CONCURRENCY", defaults.concurrency),
            queue_size=_positive_int(source, "LD_QUEUE_SIZE", defaults.queue_size),
            retention_days=_positive_int(source, "LD_RETENTION_DAYS", defaults.retention_days),
            disk_cap_mb=_positive_int(source, "LD_DISK_CAP_MB", defaults.disk_cap_mb),
            rate_per_minute=_positive_int(source, "LD_RATE_PER_MINUTE", defaults.rate_per_minute),
            rate_per_hour=_positive_int(source, "LD_RATE_PER_HOUR", defaults.rate_per_hour),
            trust_proxy=_flag(source, "LD_TRUST_PROXY", defaults.trust_proxy),
            read_rate_per_minute=_positive_int(source, "LD_READ_RATE_PER_MINUTE", defaults.read_rate_per_minute),
            max_streams_per_client=_positive_int(source, "LD_MAX_STREAMS_PER_CLIENT", defaults.max_streams_per_client),
            live_scans_enabled=_flag(source, "LD_LIVE_SCANS_ENABLED", defaults.live_scans_enabled),
            live_scans_per_day=_positive_int(source, "LD_LIVE_SCANS_PER_DAY", defaults.live_scans_per_day),
            global_scans_per_hour=_positive_int(source, "LD_GLOBAL_SCANS_PER_HOUR", defaults.global_scans_per_hour),
            max_active_per_client=_positive_int(source, "LD_MAX_ACTIVE_PER_CLIENT", defaults.max_active_per_client),
            reserved_queue_slots=_positive_int(source, "LD_RESERVED_QUEUE_SLOTS", defaults.reserved_queue_slots),
        )


def _text(env: Mapping[str, str], name: str, default: str) -> str:
    return env.get(name, default).strip()


def _flag(env: Mapping[str, str], name: str, default: bool) -> bool:
    if name not in env:
        return default
    value = env[name].strip().lower()
    if value in _TRUE_VALUES:
        return True
    if value in _FALSE_VALUES:
        return False
    raise ValueError(f"{name} must be a boolean flag")


def _positive_int(env: Mapping[str, str], name: str, default: int) -> int:
    if name not in env:
        return default
    value = int(env[name])
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return value


def _positive_float(env: Mapping[str, str], name: str, default: float) -> float:
    if name not in env:
        return default
    value = float(env[name])
    # The second comparison rejects NaN, which is not greater than anything.
    if value <= 0 or not value > 0 or value == float("inf"):
        raise ValueError(f"{name} must be positive and finite")
    return value


def _names(env: Mapping[str, str], name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    if name not in env:
        return default
    return tuple(part.strip() for part in env[name].split(",") if part.strip())
