"""Shared test helpers. Everything is offline: no daemon, no site, no real DNS."""

from __future__ import annotations

import json
import os
import stat
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.config import _SECRET_NAME, Settings  # noqa: E402

FAKE_DOCKER = Path(__file__).resolve().parent / "fake_docker.py"


@pytest.fixture(autouse=True)
def clean_secret_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """The audit also looks for secret-like variables, so the developer's own must not count."""
    for name in list(os.environ):
        if _SECRET_NAME.search(name):
            monkeypatch.delenv(name)


class EventLog:
    """The test's `emit`. Assigns seq the way a job manager would."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    async def __call__(self, event_type: str, data: dict[str, Any], source: str) -> None:
        self.events.append(
            {
                "v": 1,
                "seq": len(self.events) + 1,
                "ts": 0.0,
                "source": source,
                "type": event_type,
                "data": data,
            }
        )

    def types(self, source: str | None = None) -> list[str]:
        return [e["type"] for e in self.events if source is None or e["source"] == source]

    def of(self, event_type: str) -> list[dict[str, Any]]:
        return [e for e in self.events if e["type"] == event_type]

    def only(self, event_type: str) -> dict[str, Any]:
        matches = self.of(event_type)
        assert len(matches) == 1, f"expected one {event_type}, got {self.types()}"
        return matches[0]["data"]


class FakeDocker:
    """Configures and reads back tests/fake_docker.py for one test."""

    def __init__(self, state_dir: Path) -> None:
        self.state_dir = state_dir

    def configure(self, **config: Any) -> None:
        (self.state_dir / "fake.json").write_text(json.dumps(config))

    def settings(self, **overrides: Any) -> Settings:
        base = Settings(
            docker_bin=str(FAKE_DOCKER),
            image="ld-test-image:1",
            secret_env_names=(),
            deadline_s=20.0,
        )
        return replace(base, **overrides)

    def calls(self) -> list[dict[str, Any]]:
        path = self.state_dir / "calls.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines()]

    def commands(self) -> list[str]:
        return [call["argv"][0] for call in self.calls()]

    def call_for(self, command: str) -> dict[str, Any]:
        return next(call for call in self.calls() if call["argv"][0] == command)

    def container_exists(self, name: str) -> bool:
        return (self.state_dir / "containers" / f"{name}.json").exists()

    def add_container(self, name: str, container_id: str, labels: list[str]) -> None:
        directory = self.state_dir / "containers"
        directory.mkdir(exist_ok=True)
        (directory / f"{name}.json").write_text(json.dumps({"id": container_id, "labels": labels}))


@pytest.fixture
def fake_docker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeDocker:
    # Keep the stub runnable however the checkout's file modes were set.
    os.chmod(FAKE_DOCKER, FAKE_DOCKER.stat().st_mode | stat.S_IXUSR)
    state_dir = tmp_path / "docker-state"
    state_dir.mkdir()
    monkeypatch.setenv("DOCKER_CONFIG", str(state_dir))
    stub = FakeDocker(state_dir)
    stub.configure()
    return stub


@pytest.fixture
def event_log() -> EventLog:
    return EventLog()
