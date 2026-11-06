"""Runs worker.py with real Chromium against every fixture, offline only.

Nothing here touches a real website: every run uses --fixture NAME --offline, so
fixture URLs are served from memory and everything else is aborted locally. Docker
is not involved, so nothing here says anything about the sandbox's isolation.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from app.models import validate_worker_event

WORKER = Path(__file__).resolve().parent.parent / "worker" / "worker.py"
FIXTURE_ORIGIN = "http://fixtures.invalid"
FOOTER = "Link Detonator test fixture"
DEADLINE_S = 30.0
# Scheduling slack on top of the deadline; the worker aims to finish inside it.
EXIT_SLACK_S = 2.0

KNOWN_EVENT_TYPES = {
    "worker_started",
    "navigation",
    "screenshot",
    "request",
    "request_failed",
    "download_attempt",
    "dialog",
    "popup",
    "form",
    "text_layers",
    "page_unresponsive",
    "page_crash",
    "worker_finished",
}
CONCEALED_SOURCES = {
    "hidden_css",
    "offscreen",
    "tiny_text",
    "same_color",
    "comment",
    "meta",
    "aria_label",
    "alt",
}
FIXTURE_DWELL_S = {
    "benign": 3.0,
    "phish-login": 3.0,
    "hostile-injection": 2.0,
    "hostile-download": 3.0,
    "hostile-ssrf": 2.0,
    "hostile-freeze": 12.0,
    "hostile-memory": 5.0,
    "hostile-gauntlet": 12.0,
}


@dataclass(frozen=True)
class Run:
    code: int
    elapsed_s: float
    events: tuple[dict[str, Any], ...]
    work_root: Path
    stderr: str

    def of_type(self, event_type: str) -> list[dict[str, Any]]:
        return [event["data"] for event in self.events if event["type"] == event_type]

    @property
    def finished(self) -> dict[str, Any]:
        return self.of_type("worker_finished")[-1]

    def all_concealed(self) -> list[dict[str, str]]:
        return [entry for layer in self.of_type("text_layers") for entry in layer["concealed"]]

    def all_visible_text(self) -> str:
        return "\n".join(layer["visible_text"] for layer in self.of_type("text_layers"))


def worker_argv(name: str, work_root: Path, *extra: str) -> list[str]:
    return [
        sys.executable,
        str(WORKER),
        "--fixture",
        name,
        "--offline",
        "--work-root",
        str(work_root),
        *extra,
    ]


def parse_events(stdout: bytes) -> tuple[dict[str, Any], ...]:
    return tuple(json.loads(line) for line in stdout.splitlines() if line.strip())


def processes_using(work_root: Path) -> list[str]:
    listing = subprocess.run(
        ["ps", "-A", "-o", "command="], capture_output=True, text=True, errors="replace", check=True
    ).stdout
    return [line for line in listing.splitlines() if str(work_root) in line]


def assert_nothing_left_behind(work_root: Path) -> None:
    assert list(work_root.iterdir()) == [], "the worker must remove its throwaway profile"
    assert processes_using(work_root) == [], "the worker must not leave Chromium running"


CREATED_WORK_ROOTS: list[Path] = []


@lru_cache(maxsize=None)
def run_fixture(name: str) -> Run:
    work_root = Path(tempfile.mkdtemp(prefix="ld-test-"))
    CREATED_WORK_ROOTS.append(work_root)
    argv = worker_argv(name, work_root, "--deadline", str(DEADLINE_S), "--dwell", str(FIXTURE_DWELL_S[name]))
    started = time.monotonic()
    completed = subprocess.run(argv, capture_output=True, timeout=DEADLINE_S + 20, check=False)
    return Run(
        code=completed.returncode,
        elapsed_s=time.monotonic() - started,
        events=parse_events(completed.stdout),
        work_root=work_root,
        stderr=completed.stderr.decode("utf-8", "replace"),
    )


@pytest.fixture(scope="module", autouse=True)
def remove_work_roots():
    yield
    for path in CREATED_WORK_ROOTS:
        shutil.rmtree(path, ignore_errors=True)


def fixture_url(path: str) -> str:
    return f"{FIXTURE_ORIGIN}{path}"


def is_fixture_url(url: str) -> bool:
    return url.startswith(f"{FIXTURE_ORIGIN}/")


@pytest.mark.parametrize("name", list(FIXTURE_DWELL_S))
class TestEveryFixture:
    def test_host_schema_accepts_every_event(self, name: str) -> None:
        for event in run_fixture(name).events:
            assert validate_worker_event(event["type"], event["data"]) is not None, event["type"]

    def test_exits_cleanly_within_its_deadline(self, name: str) -> None:
        run = run_fixture(name)
        assert run.code == 0, run.stderr
        assert run.elapsed_s < DEADLINE_S
        assert_nothing_left_behind(run.work_root)

    def test_event_stream_follows_the_contract(self, name: str) -> None:
        run = run_fixture(name)
        assert run.events[0]["type"] == "worker_started"
        assert run.events[0]["data"] == {
            "url": fixture_url(f"/{name}"),
            "mode": "fixture",
            "offline": True,
        }
        assert run.events[-1]["type"] == "worker_finished"
        assert len(run.of_type("worker_finished")) == 1
        assert run.finished["status"] in {"ok", "partial"}
        for event in run.events:
            assert set(event) <= {"type", "data", "ts"}, "seq and source belong to the host"
            assert event["type"] in KNOWN_EVENT_TYPES

    def test_shows_the_fixture_footer(self, name: str) -> None:
        assert FOOTER in run_fixture(name).all_visible_text()

    def test_screenshots_are_jpeg(self, name: str) -> None:
        shots = run_fixture(name).of_type("screenshot")
        assert shots, "every fixture stays alive long enough for one screenshot"
        for shot in shots:
            assert shot["mime"] == "image/jpeg"
            assert shot["label"]
            assert base64.b64decode(shot["b64"]).startswith(b"\xff\xd8\xff")

    def test_no_request_leaves_the_machine(self, name: str) -> None:
        run = run_fixture(name)
        failed = {failure["url"] for failure in run.of_type("request_failed")}
        for request in run.of_type("request"):
            if not is_fixture_url(request["url"]):
                assert request["url"] in failed, f"{request['url']} did not fail"
        for failure in run.of_type("request_failed"):
            if not is_fixture_url(failure["url"]):
                assert failure["blocked_locally"] is True, failure


def test_benign_raises_no_false_alarms() -> None:
    run = run_fixture("benign")
    assert run.finished == {"status": "ok", "error": None}
    assert run.all_concealed() == []
    for quiet_type in (
        "request_failed",
        "download_attempt",
        "dialog",
        "popup",
        "page_unresponsive",
        "page_crash",
    ):
        assert run.of_type(quiet_type) == [], quiet_type
    assert run.of_type("navigation") == [
        {"url": fixture_url("/benign"), "status": 200, "redirected_from": None}
    ]
    assert [form["has_password"] for form in run.of_type("form")] == [False]
    text = run.all_visible_text()
    assert "Branch hours" in text
    # Small print and below-the-fold text are ordinary content, not concealment.
    assert "fictional institution" in text
    assert "Below the fold" in text
    assert "scripts enabled" not in text, "noscript content is not rendered"


def test_phish_login_redirect_chain_and_password_form() -> None:
    run = run_fixture("phish-login")
    assert run.finished == {"status": "ok", "error": None}
    assert run.of_type("navigation") == [
        {"url": fixture_url("/phish-login"), "status": 200, "redirected_from": None},
        {
            "url": fixture_url("/phish-login/verify"),
            "status": 200,
            "redirected_from": fixture_url("/phish-login"),
        },
        {
            "url": fixture_url("/phish-login/signin"),
            "status": 200,
            "redirected_from": fixture_url("/phish-login/verify"),
        },
    ]
    assert run.of_type("form") == [
        {
            "action": fixture_url("/phish-login/collect"),
            "method": "post",
            "has_password": True,
            "field_names": ["session_ref", "username", "password"],
        }
    ]
    assert run.of_type("page_unresponsive") == [], "a redirect is not a hang"


def test_phish_login_is_observed_and_never_submitted() -> None:
    urls = [request["url"] for request in run_fixture("phish-login").of_type("request")]
    assert fixture_url("/phish-login/collect") not in urls


HOSTILE_INJECTION_CANARIES = {
    "LDC-DISPLAY-NONE": "hidden_css",
    "LDC-STYLESHEET-HIDDEN": "hidden_css",
    "LDC-VISIBILITY-HIDDEN": "hidden_css",
    "LDC-OPACITY-ZERO": "hidden_css",
    "LDC-CLIP-RECT": "hidden_css",
    "LDC-ZERO-BOX": "hidden_css",
    "LDC-OFFSCREEN-LEFT": "offscreen",
    "LDC-OFFSCREEN-INDENT": "offscreen",
    "LDC-OFFSCREEN-TRANSFORM": "offscreen",
    "LDC-TINY-ONE-PIXEL": "tiny_text",
    "LDC-TINY-ZERO": "tiny_text",
    "LDC-SAME-WHITE": "same_color",
    "LDC-SAME-DARK": "same_color",
    "LDC-SAME-TRANSPARENT": "same_color",
    "LDC-COMMENT": "comment",
    "LDC-META-DESCRIPTION": "meta",
    "LDC-META-PROPERTY": "meta",
    "LDC-ARIA-LABEL": "aria_label",
    "LDC-ALT": "alt",
    "LDC-SHADOW-OPEN": "hidden_css",
    "LDC-SHADOW-CLOSED": "tiny_text",
    "LDC-SHADOW-DECLARATIVE": "hidden_css",
    "LDC-FRAME-COMMENT": "comment",
    "LDC-FRAME-HIDDEN": "hidden_css",
    "LDC-FRAME-OWNER-HIDDEN": "hidden_css",
}


@pytest.mark.parametrize(("canary", "source"), HOSTILE_INJECTION_CANARIES.items())
def test_hostile_injection_surfaces_each_technique(canary: str, source: str) -> None:
    # The fixture's own script overrides the DOM APIs in its world and clobbers
    # names on the document and a form; these only pass if extraction is isolated.
    matching = [entry for entry in run_fixture("hostile-injection").all_concealed() if canary in entry["text"]]
    assert [entry["source"] for entry in matching] == [source]


def test_hostile_injection_covers_every_contract_source() -> None:
    assert {entry["source"] for entry in run_fixture("hostile-injection").all_concealed()} == CONCEALED_SOURCES


def test_hostile_injection_keeps_concealed_text_out_of_visible_text() -> None:
    text = run_fixture("hostile-injection").all_visible_text()
    assert "LDC-" not in text
    assert "Savings rates change" in text
    assert "A dark panel with readable text." in text


def test_hostile_injection_entries_carry_a_selector() -> None:
    entries = run_fixture("hostile-injection").all_concealed()
    by_canary = {entry["text"].split(":")[0]: entry for entry in entries}
    assert by_canary["LDC-SAME-WHITE"]["selector"].endswith("p.same-white")
    assert by_canary["LDC-SHADOW-OPEN"]["selector"] == "div#open-shadow > p"
    assert by_canary["LDC-FRAME-HIDDEN"]["selector"].startswith("frame[1] ")


def test_hostile_injection_form_survives_clobbering() -> None:
    forms = run_fixture("hostile-injection").of_type("form")
    assert forms == [
        {
            "action": fixture_url("/hostile-injection/collect"),
            "method": "post",
            "has_password": True,
            "field_names": ["action", "method", "elements", "getAttribute", "parentNode", "localName"],
        }
    ]


def test_hostile_download_is_reported_and_no_file_is_kept() -> None:
    run = run_fixture("hostile-download")
    assert run.of_type("download_attempt") == [
        {
            "url": fixture_url("/hostile-download/larkspur-statement.txt"),
            "suggested_filename": "larkspur-statement.txt",
        }
    ]
    assert_nothing_left_behind(run.work_root)


def test_hostile_ssrf_attempts_are_blocked_locally_and_labelled_so() -> None:
    run = run_fixture("hostile-ssrf")
    failures = {failure["url"]: failure for failure in run.of_type("request_failed")}
    for target in (
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data",
        "http://10.0.0.1/",
        "http://10.0.0.2/pixel.gif",
        "http://172.16.0.1/",
        "http://192.168.1.1/",
        "http://127.0.0.1:8000/",
        "http://127.0.0.1:8080/pixel.gif",
        "http://[::1]:8000/",
        "ws://127.0.0.1:8081/",
    ):
        assert failures[target]["blocked_locally"] is True, target
        assert failures[target]["error"]
    assert "answered" not in run.all_visible_text()


def test_hostile_freeze_reports_unresponsive_and_stops_early() -> None:
    run = run_fixture("hostile-freeze")
    unresponsive = run.of_type("page_unresponsive")
    assert [item["operation"] for item in unresponsive] == ["screenshot", "evaluate"]
    assert all(item["timeout_ms"] > 0 for item in unresponsive)
    assert run.finished == {"status": "partial", "error": "page unresponsive"}
    # Evidence from before the freeze survives.
    assert run.of_type("screenshot")
    assert "secure viewer" in run.all_visible_text()
    assert run.of_type("worker_finished")[-1]["error"] != "internal deadline reached"
    assert run.elapsed_s < DEADLINE_S - 5, "a frozen page must not consume the whole deadline"


def test_hostile_memory_exits_within_bounds() -> None:
    run = run_fixture("hostile-memory")
    assert run.code == 0
    assert run.elapsed_s < DEADLINE_S
    assert "Allocated" in run.all_visible_text() or "Allocation stopped" in run.all_visible_text()
    # With no container limit the bounded loop finishes; with one it may crash the page.
    assert run.finished["status"] in {"ok", "partial"}


def test_hostile_gauntlet_produces_composite_evidence() -> None:
    run = run_fixture("hostile-gauntlet")
    navigations = run.of_type("navigation")
    assert navigations[0]["url"] == fixture_url("/hostile-gauntlet")
    assert navigations[1] == {
        "url": fixture_url("/hostile-gauntlet/landing"),
        "status": 200,
        "redirected_from": fixture_url("/hostile-gauntlet"),
    }
    assert [form["has_password"] for form in run.of_type("form")] == [True]
    assert {entry["source"] for entry in run.all_concealed()} == CONCEALED_SOURCES
    assert [dialog["dialog_type"] for dialog in run.of_type("dialog")] == ["alert"]
    assert run.of_type("popup") == [{"url": fixture_url("/benign")}]
    assert [item["suggested_filename"] for item in run.of_type("download_attempt")] == ["larkspur-statement.txt"]
    failures = {failure["url"]: failure for failure in run.of_type("request_failed")}
    for target in ("http://169.254.169.254/latest/meta-data/", "http://10.0.0.1/", "http://127.0.0.1:8000/"):
        assert failures[target]["blocked_locally"] is True
    assert run.of_type("page_unresponsive")
    assert run.finished["status"] == "partial"
    assert_nothing_left_behind(run.work_root)


def wait_for_exit(process: subprocess.Popen[bytes], limit_s: float) -> float:
    started = time.monotonic()
    process.wait(timeout=limit_s)
    return time.monotonic() - started


def test_short_deadline_is_honoured(tmp_path: Path) -> None:
    deadline = 6.0
    started = time.monotonic()
    completed = subprocess.run(
        worker_argv("hostile-gauntlet", tmp_path, "--deadline", str(deadline), "--dwell", "30"),
        capture_output=True,
        timeout=deadline + 20,
        check=False,
    )
    elapsed = time.monotonic() - started
    events = parse_events(completed.stdout)
    assert completed.returncode == 0
    assert elapsed < deadline + EXIT_SLACK_S
    assert events[-1]["type"] == "worker_finished"
    assert_nothing_left_behind(tmp_path)


def test_exits_by_itself_when_nobody_reads_stdout(tmp_path: Path) -> None:
    # A full pipe blocks the event loop, so only the watchdog thread can end this.
    deadline = 6.0
    with subprocess.Popen(
        worker_argv("hostile-gauntlet", tmp_path, "--deadline", str(deadline), "--dwell", "30"),
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    ) as process:
        started = time.monotonic()
        process.wait(timeout=deadline + 20)
        elapsed = time.monotonic() - started
    assert process.returncode == 0
    assert elapsed < deadline + EXIT_SLACK_S
    assert_nothing_left_behind(tmp_path)


def test_sigterm_reports_and_leaves_nothing_behind(tmp_path: Path) -> None:
    with subprocess.Popen(
        worker_argv("hostile-freeze", tmp_path, "--deadline", "30", "--dwell", "30"),
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    ) as process:
        assert process.stdout is not None
        lines = []
        for line in process.stdout:
            lines.append(line)
            if json.loads(line)["type"] == "screenshot":
                break
        process.send_signal(signal.SIGTERM)
        lines.extend(process.stdout)
        assert wait_for_exit(process, 5.0) < 5.0
    events = parse_events(b"".join(lines))
    assert events[-1]["type"] == "worker_finished"
    assert events[-1]["data"] == {"status": "partial", "error": "terminated by signal"}
    assert_nothing_left_behind(tmp_path)


def test_closed_stdout_ends_the_worker(tmp_path: Path) -> None:
    with subprocess.Popen(
        worker_argv("hostile-gauntlet", tmp_path, "--deadline", "30", "--dwell", "30"),
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    ) as process:
        assert process.stdout is not None
        process.stdout.readline()
        process.stdout.close()
        process.stdout = None
        assert wait_for_exit(process, 25.0) < 25.0
    assert process.returncode == 1
    assert_nothing_left_behind(tmp_path)


def test_browser_launch_failure_is_reported(tmp_path: Path) -> None:
    completed = subprocess.run(
        worker_argv("benign", tmp_path, "--deadline", "20"),
        capture_output=True,
        timeout=40,
        check=False,
        env={**os.environ, "PLAYWRIGHT_BROWSERS_PATH": str(tmp_path / "no-browsers-here")},
    )
    events = parse_events(completed.stdout)
    assert completed.returncode == 1
    assert [event["type"] for event in events] == ["worker_started", "worker_finished"]
    assert events[-1]["data"]["status"] == "error"
    assert events[-1]["data"]["error"]
    assert_nothing_left_behind(tmp_path)


def test_unusable_work_root_is_reported(tmp_path: Path) -> None:
    completed = subprocess.run(
        worker_argv("benign", tmp_path / "missing"), capture_output=True, timeout=20, check=False
    )
    events = parse_events(completed.stdout)
    assert completed.returncode == 1
    assert [event["type"] for event in events] == ["worker_started", "worker_finished"]
    assert events[-1]["data"]["status"] == "error"


@pytest.mark.parametrize(
    "arguments",
    [
        ["--url", "http://fixtures.invalid/benign", "--offline"],
        ["--url", "file:///etc/passwd"],
        ["--fixture", "../../etc/passwd", "--offline"],
        ["--fixture", "benign", "--offline", "--deadline", "1"],
        ["--fixture", "benign", "--url", "http://fixtures.invalid/benign"],
    ],
)
def test_bad_arguments_are_refused_before_any_browser_starts(arguments: list[str]) -> None:
    completed = subprocess.run(
        [sys.executable, str(WORKER), *arguments], capture_output=True, timeout=20, check=False
    )
    assert completed.returncode == 2
    assert completed.stdout == b""


@lru_cache(maxsize=None)
def load_worker() -> ModuleType:
    spec = importlib.util.spec_from_file_location("link_detonator_worker", WORKER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def writer_and_output():
    read_fd, write_fd = os.pipe()
    writer = load_worker().EventWriter(fd=write_fd)

    def read_events() -> list[dict[str, Any]]:
        os.close(write_fd)
        with os.fdopen(read_fd, "rb") as pipe:
            return list(parse_events(pipe.read()))

    return writer, read_events


def test_request_events_stop_at_the_cap_and_are_counted(writer_and_output) -> None:
    writer, read_events = writer_and_output
    data = {"url": "http://fixtures.invalid/x", "method": "GET", "resource_type": "fetch"}
    cap = load_worker().EVENT_TYPE_CAPS["request"]
    accepted = [writer.emit("request", data) for _ in range(cap + 7)]
    writer.finish("ok", None)
    events = read_events()
    assert accepted.count(True) == cap
    assert sum(event["type"] == "request" for event in events) == cap
    assert events[-1]["data"]["omitted"] == {"request": 7}


def test_output_stops_short_of_the_hosts_hard_caps() -> None:
    module = load_worker()
    assert module.LINE_BYTES_CAP < 8 * 1024 * 1024
    assert module.TOTAL_BYTES_CAP < 64 * 1024 * 1024
    assert module.TOTAL_EVENTS_CAP < 5000
    # Every per-type cap together must fit inside the event budget.
    assert sum(module.EVENT_TYPE_CAPS.values()) < module.TOTAL_EVENTS_CAP


def test_hostile_strings_stay_on_one_ascii_line(writer_and_output) -> None:
    writer, read_events = writer_and_output
    message = "first\nsecond third\ud800" + "x" * 100_000
    writer.emit("dialog", {"dialog_type": "alert", "message": message})
    writer.finish("ok", None)
    events = read_events()
    assert [event["type"] for event in events] == ["dialog", "worker_finished"]
    stored = events[0]["data"]["message"]
    assert len(stored) == load_worker().STRING_CAPS["message"]
    assert stored.startswith("first\nsecond third?")
    stored.encode("utf-8")


def test_nothing_is_written_after_worker_finished(writer_and_output) -> None:
    writer, read_events = writer_and_output
    writer.finish("ok", None)
    writer.finish("error", "again")
    assert writer.emit("popup", {"url": "http://fixtures.invalid/late"}) is False
    assert [event["type"] for event in read_events()] == ["worker_finished"]


class FakeRequest:
    url = "http://169.254.169.254/latest/meta-data/"
    resource_type = "fetch"


def test_unanswered_requests_are_reported_at_scan_end(writer_and_output, tmp_path: Path) -> None:
    # A silently dropped connection is still pending when the scan ends. It must
    # be reported, and without claiming a local abort.
    writer, read_events = writer_and_output
    module = load_worker()
    config = module.Config(
        target_url=fixture_url("/hostile-ssrf"),
        mode="fixture",
        offline=False,
        deadline_s=30.0,
        dwell_s=1.0,
        work_root=tmp_path,
    )
    scan = module.Scan(config, writer, module.Deadline(30.0), tmp_path)
    scan._pending.add(FakeRequest())
    scan.flush_pending_requests()
    scan.flush_pending_requests()
    writer.finish("ok", None)
    events = read_events()
    assert events[0] == {
        "type": "request_failed",
        "ts": events[0]["ts"],
        "data": {
            "url": FakeRequest.url,
            "error": module.PENDING_REQUEST_ERROR,
            "resource_type": "fetch",
            "blocked_locally": False,
        },
    }
    assert [event["type"] for event in events] == ["request_failed", "worker_finished"]


def test_closed_shadow_root_walk_tracks_frames() -> None:
    document = {
        "children": [
            {
                "shadowRoots": [
                    {"shadowRootType": "closed", "backendNodeId": 1, "children": []},
                    {"shadowRootType": "open", "backendNodeId": 2, "children": [
                        {"shadowRoots": [{"shadowRootType": "closed", "backendNodeId": 3}]}
                    ]},
                ]
            },
            {
                "frameId": "child",
                "contentDocument": {"children": [
                    {"shadowRoots": [{"shadowRootType": "closed", "backendNodeId": 4}]}
                ]},
            },
        ]
    }
    found = load_worker().closed_shadow_roots(document, "main")
    assert sorted(found["main"]) == [1, 3]
    assert found["child"] == [4]
