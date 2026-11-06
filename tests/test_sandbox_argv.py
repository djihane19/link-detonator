"""The exact docker argv, plus the pure helpers and guards around it."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from app.config import Settings
from app.models import FIXTURE_NAMES, ScanRequest, ScanTarget, decode_worker_line
from app.sandbox import (
    SANDBOX_POLICY,
    DockerRunner,
    LocalFixtureRunner,
    RunnerRefused,
    SandboxRunner,
    audit_container_env,
    build_docker_argv,
    build_local_argv,
    build_runner,
    container_name,
    is_loopback_host,
    worker_args,
    worker_deadline_args,
)

FORBIDDEN_FLAGS = (
    "-e",
    "--env",
    "--env-file",
    "-v",
    "--volume",
    "--mount",
    "--privileged",
    "--pid",
    "--ipc",
    "--cap-add",
    "--device",
    "--volumes-from",
    "-p",
    "--publish",
    "-P",
    "-i",
    "-t",
    "--interactive",
    "--tty",
)


def exact_argv(name: str, image: str, *rest: str) -> list[str]:
    """The contract's argv, written out by hand so a code change cannot move both sides."""
    return [
        "docker", "run", "--rm", "--init", "--name", name,
        "--label", "link-detonator=1", "--network", "ld-sandbox",
        "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=256m",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "256", "--memory", "1g", "--memory-swap", "1g", "--cpus", "1",
        "--shm-size", "128m", "--ulimit", "nofile=1024:1024", "--log-driver", "none",
        "--user", "pwuser", *rest, image, "python", "/worker/worker.py",
    ]  # fmt: skip


def test_argv_is_exactly_the_contract() -> None:
    argv = build_docker_argv("ld-abc", "img:1", ["--fixture", "benign"], Settings())
    assert argv == [*exact_argv("ld-abc", "img:1"), "--fixture", "benign"]


def test_runtime_goes_before_the_image_when_set() -> None:
    argv = build_docker_argv("ld-abc", "img:1", ["--url", "https://x.example/"], Settings(runtime="runsc"))
    assert argv == [*exact_argv("ld-abc", "img:1", "--runtime", "runsc"), "--url", "https://x.example/"]


def test_no_runtime_flag_by_default() -> None:
    assert "--runtime" not in build_docker_argv("ld-abc", "img:1", [], Settings())


def test_no_forbidden_flag_and_no_host_network() -> None:
    argv = build_docker_argv("ld-abc", "img:1", [], Settings(runtime="runsc"))
    assert not set(FORBIDDEN_FLAGS) & set(argv)
    # Also the --flag=value spellings. `--pids-limit` is required, so "--pid" alone won't do.
    prefixes = ("--env", "--volume", "--mount", "--pid=", "--ipc", "--privileged", "--network=")
    assert not any(arg.startswith(prefixes) for arg in argv)
    assert "host" not in argv
    assert argv[argv.index("--network") + 1] == "ld-sandbox"


def test_docker_binary_is_configurable() -> None:
    argv = build_docker_argv("ld-abc", "img:1", [], Settings(docker_bin="/opt/fake/docker"))
    assert argv[0] == "/opt/fake/docker"


def test_target_args_cannot_become_docker_flags() -> None:
    hostile = ["--url", "https://x.example/", "--privileged", "-v", "/:/host", "--network=host"]
    argv = build_docker_argv("ld-abc", "img:1", hostile, Settings())
    image_at = argv.index("img:1")
    assert not set(FORBIDDEN_FLAGS) & set(argv[:image_at])
    assert argv[image_at + 3 :] == hostile
    assert all("--network=host" not in arg for arg in argv[:image_at])


def test_argv_builder_is_pure() -> None:
    settings = Settings()
    args = ["--fixture", "benign"]
    first = build_docker_argv("ld-abc", "img:1", args, settings)
    assert first == build_docker_argv("ld-abc", "img:1", args, settings)
    assert args == ["--fixture", "benign"]


@pytest.mark.parametrize("image", ["--privileged", "-v", ""])
def test_image_that_could_be_read_as_a_flag_is_refused(image: str) -> None:
    with pytest.raises(ValueError):
        build_docker_argv("ld-abc", image, [], Settings())


@pytest.mark.parametrize("name", ["-x", "--privileged", "ld abc", "ld/abc", ""])
def test_bad_container_name_is_refused(name: str) -> None:
    with pytest.raises(ValueError):
        build_docker_argv(name, "img:1", [], Settings())


@pytest.mark.parametrize("runtime", ["--privileged", "run sc", "a;b"])
def test_bad_runtime_is_refused(runtime: str) -> None:
    with pytest.raises(ValueError):
        build_docker_argv("ld-abc", "img:1", [], Settings(runtime=runtime))


@pytest.mark.parametrize("scan_id", ["abc", "-abc_DEF-123", "AAAA_-__"])
def test_container_name_accepts_token_urlsafe_ids(scan_id: str) -> None:
    assert container_name(scan_id) == f"ld-{scan_id}"


@pytest.mark.parametrize("scan_id", ["a b", "../x", "a/b", "a\nb", "a;b"])
def test_container_name_refuses_anything_else(scan_id: str) -> None:
    with pytest.raises(ValueError):
        container_name(scan_id)


def test_worker_args_never_use_offline_in_the_sandbox() -> None:
    assert worker_args(ScanTarget(kind="fixture", value="benign")) == ["--fixture", "benign"]
    target = ScanTarget(kind="url", value="https://example.com/")
    assert worker_args(target) == ["--url", "https://example.com/"]


def test_policy_event_matches_the_argv() -> None:
    argv = build_docker_argv("ld-abc", "img:1", [], Settings())
    flag_for = {
        "network": "--network",
        "tmpfs": "--tmpfs",
        "cap_drop": "--cap-drop",
        "pids_limit": "--pids-limit",
        "memory": "--memory",
        "memory_swap": "--memory-swap",
        "cpus": "--cpus",
        "shm_size": "--shm-size",
        "log_driver": "--log-driver",
        "user": "--user",
    }
    for key, flag in flag_for.items():
        assert str(SANDBOX_POLICY[key]) == argv[argv.index(flag) + 1], key
    assert argv[argv.index("--ulimit") + 1] == f"nofile={SANDBOX_POLICY['nofile']}"
    assert "--read-only" in argv and SANDBOX_POLICY["read_only_rootfs"] is True
    assert argv[argv.index("--security-opt") + 1] == "no-new-privileges"


# --- Secret audit (pure part) ----------------------------------------------------


@pytest.mark.parametrize(
    ("info", "secrets", "ok"),
    [
        ({"Config": {"Env": ["PATH=/usr/bin"]}}, ["s3cret"], True),
        ({"Config": {"Env": ["PATH=/usr/bin"]}}, [], True),
        ({"Config": {"Env": None}}, ["s3cret"], True),
        ({"Config": {"Env": ["KEY=s3cret"]}}, ["s3cret"], False),
        ({"Config": {"Env": ["KEY=prefix-s3cret-suffix"]}}, ["s3cret"], False),
        ({"Config": {"Env": ["A=1", "B=s3cret"]}}, ["other", "s3cret"], False),
        # Unreadable means not proven clean.
        ({}, ["s3cret"], False),
        ({"Config": None}, ["s3cret"], False),
        ({"Config": {}}, ["s3cret"], False),
        ({"Config": {"Env": "KEY=s3cret"}}, ["s3cret"], False),
        ({"Config": {"Env": [1, 2]}}, ["s3cret"], False),
    ],
)
def test_audit_container_env(info: dict, secrets: list[str], ok: bool) -> None:
    assert audit_container_env(info, secrets) is ok


def test_settings_repr_never_contains_secret_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LD_T_SECRET", "s3cret-value")
    settings = Settings(secret_env_names=("LD_T_SECRET", "LD_T_UNSET"))
    assert settings.secret_values() == ["s3cret-value"]
    assert "s3cret-value" not in repr(settings)


def test_blank_secret_is_not_compared(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LD_T_BLANK", "  ")
    assert Settings(secret_env_names=("LD_T_BLANK",)).secret_values() == []


# --- Settings --------------------------------------------------------------------


def test_settings_defaults_match_the_contract() -> None:
    settings = Settings.from_env({})
    assert settings.deadline_s == 60.0
    assert settings.max_line_bytes == 8 * 1024 * 1024
    assert settings.max_total_bytes == 64 * 1024 * 1024
    assert settings.max_events == 5000
    assert settings.concurrency == 2
    assert settings.queue_size == 10
    assert settings.rate_per_minute == 5
    assert settings.rate_per_hour == 30
    assert settings.trust_proxy is False
    assert settings.dev_local_runner is False
    assert settings.runtime is None


def test_settings_read_the_ld_prefix() -> None:
    settings = Settings.from_env(
        {
            "LD_DOCKER_BIN": "/x/docker",
            "LD_RUNTIME": "runsc",
            "LD_DEADLINE_S": "12.5",
            "LD_DEV_LOCAL_RUNNER": "1",
            "LD_TRUST_PROXY": "true",
            "LD_SECRET_ENV_NAMES": "A, B,,C",
        }
    )
    assert settings.docker_bin == "/x/docker"
    assert settings.runtime == "runsc"
    assert settings.deadline_s == 12.5
    assert settings.dev_local_runner is True
    assert settings.trust_proxy is True
    assert settings.secret_env_names == ("A", "B", "C")


@pytest.mark.parametrize(
    "env",
    [
        {"LD_DEADLINE_S": "0"},
        {"LD_DEADLINE_S": "-1"},
        {"LD_DEADLINE_S": "nan"},
        {"LD_DEADLINE_S": "inf"},
        {"LD_DEADLINE_S": "soon"},
        {"LD_MAX_EVENTS": "0"},
        {"LD_MAX_EVENTS": "many"},
        {"LD_DEV_LOCAL_RUNNER": "maybe"},
    ],
)
def test_malformed_settings_are_refused(env: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        Settings.from_env(env)


# --- Local runner guards ---------------------------------------------------------


def test_local_runner_requires_the_flag() -> None:
    with pytest.raises(RunnerRefused):
        LocalFixtureRunner(Settings(dev_local_runner=False))


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.5", "example.com", ""])
def test_local_runner_requires_loopback(host: str) -> None:
    with pytest.raises(RunnerRefused):
        LocalFixtureRunner(Settings(dev_local_runner=True, bind_host=host))


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.2", "::1", "localhost"])
def test_loopback_hosts(host: str) -> None:
    assert is_loopback_host(host)
    assert LocalFixtureRunner(Settings(dev_local_runner=True, bind_host=host)).isolated is False


def test_local_argv_is_fixture_and_offline_only() -> None:
    settings = Settings(python_bin="/py", worker_path=Settings().worker_path)
    assert build_local_argv("benign", settings) == [
        "/py",
        str(settings.worker_path),
        "--fixture",
        "benign",
        "--offline",
        "--deadline",
        "45",
    ]


@pytest.mark.parametrize(
    ("deadline_s", "expected"),
    [(60.0, "45"), (20.0, "15"), (2.0, "5"), (1000.0, "300")],
)
def test_worker_deadline_follows_the_host_deadline(deadline_s: float, expected: str) -> None:
    assert worker_deadline_args(Settings(deadline_s=deadline_s)) == ["--deadline", expected]


def test_build_runner_selects_by_flag() -> None:
    assert isinstance(build_runner(Settings()), DockerRunner)
    local = build_runner(Settings(dev_local_runner=True))
    assert isinstance(local, LocalFixtureRunner)
    assert isinstance(local, SandboxRunner)
    assert build_runner(Settings()).isolated is True
    assert local.isolated is False


def test_build_runner_refuses_flag_with_public_bind() -> None:
    with pytest.raises(RunnerRefused):
        build_runner(Settings(dev_local_runner=True, bind_host="0.0.0.0"))


# --- ScanTarget, ScanRequest and per-type validation ---------------------------------


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_known_fixtures_are_accepted(name: str) -> None:
    assert ScanTarget(kind="fixture", value=name).value == name


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        ("fixture", "nope"),
        ("fixture", "--offline"),
        ("fixture", "../benign"),
        ("url", "--privileged"),
        ("url", "ftp://x.example/"),
        ("url", "https://x.example/ --offline"),
        ("url", "https://x.example/\n--offline"),
        ("url", "https://x.example/" + "a" * 2048),
        ("other", "benign"),
    ],
)
def test_bad_targets_are_refused(kind: str, value: str) -> None:
    with pytest.raises(ValidationError):
        ScanTarget(kind=kind, value=value)  # type: ignore[arg-type]


def test_scan_target_is_frozen() -> None:
    target = ScanTarget(kind="fixture", value="benign")
    with pytest.raises(ValidationError):
        target.value = "hostile-memory"  # type: ignore[misc]


@pytest.mark.parametrize(
    "body", [{}, {"url": "https://x.example/", "fixture": "benign"}, {"extra": 1}, {"url": None}]
)
def test_scan_request_needs_exactly_one(body: dict) -> None:
    with pytest.raises(ValidationError):
        ScanRequest(**body)


@pytest.mark.parametrize("body", [{"url": "https://x.example/"}, {"fixture": "benign"}])
def test_scan_request_accepts_one(body: dict) -> None:
    assert ScanRequest(**body)


def _decode(event_type: str, data: dict) -> dict | None:
    decoded = decode_worker_line(json.dumps({"type": event_type, "data": data}).encode())
    return decoded[1] if decoded else None


@pytest.mark.parametrize(
    ("event_type", "data"),
    [
        ("worker_started", {"url": "u", "mode": "live", "offline": False}),
        ("navigation", {"url": "u", "status": None, "redirected_from": "v"}),
        ("screenshot", {"label": "l", "mime": "image/jpeg", "b64": "/9j/4A=="}),
        ("request", {"url": "u", "method": "GET", "resource_type": "image"}),
        ("request_failed", {"url": "u", "error": "e", "resource_type": "image", "blocked_locally": False}),
        ("download_attempt", {"url": "u", "suggested_filename": "f.txt"}),
        ("dialog", {"dialog_type": "alert", "message": "m"}),
        ("popup", {"url": "u"}),
        ("form", {"action": "a", "method": "post", "has_password": True, "field_names": ["x"]}),
        ("text_layers", {"visible_text": "t", "concealed": [{"source": "alt", "text": "x", "selector": "s"}]}),
        ("page_unresponsive", {"operation": "goto", "timeout_ms": 5000}),
        ("page_crash", {}),
        ("worker_finished", {"status": "partial", "error": None}),
    ],
)
def test_every_contract_worker_type_validates(event_type: str, data: dict) -> None:
    assert _decode(event_type, data) == data


@pytest.mark.parametrize(
    ("event_type", "data"),
    [
        ("worker_started", {"url": "u", "mode": "evil", "offline": False}),
        ("navigation", {"url": 5, "status": 200, "redirected_from": None}),
        ("navigation", {"url": "u", "status": 10**400, "redirected_from": None}),
        ("navigation", {"url": "u", "status": -1, "redirected_from": None}),
        ("request_failed", {"url": "u", "error": "e", "resource_type": "x", "blocked_locally": 1}),
        ("form", {"action": "a", "method": "p", "has_password": False, "field_names": "x"}),
        ("text_layers", {"visible_text": "t", "concealed": [{"source": "bad", "text": "", "selector": ""}]}),
        ("page_unresponsive", {"operation": "o", "timeout_ms": 1.5}),
        ("worker_finished", {"status": "great", "error": None}),
    ],
)
def test_wrong_shapes_are_dropped(event_type: str, data: dict) -> None:
    assert _decode(event_type, data) is None


def test_strings_are_truncated_not_rejected() -> None:
    assert len(_decode("popup", {"url": "u" * 10_000})["url"]) == 4096
    assert len(_decode("text_layers", {"visible_text": "v" * 30_000, "concealed": []})["visible_text"]) == 20_000
    assert len(_decode("dialog", {"dialog_type": "a" * 500, "message": "m"})["dialog_type"]) == 64


def test_lists_are_capped() -> None:
    form = {"action": "a", "method": "p", "has_password": False, "field_names": ["x"] * 1000}
    assert len(_decode("form", form)["field_names"]) == 200
    item = {"source": "alt", "text": "t", "selector": "s"}
    assert len(_decode("text_layers", {"visible_text": "", "concealed": [item] * 1000})["concealed"]) == 500


def test_control_chars_and_surrogates_are_cleaned_so_output_can_be_encoded() -> None:
    line = b'{"type": "popup", "data": {"url": "a\\u0000b\\u001bc\\ud800d\\ne"}}'
    data = decode_worker_line(line)
    assert data is not None
    assert data[1]["url"] == "abc?d\ne"
    data[1]["url"].encode("utf-8")
    json.dumps(data[1]).encode("utf-8")


def test_undeclared_fields_vanish() -> None:
    data = _decode("popup", {"url": "u", "seq": 1, "source": "host", "verified": True})
    assert data == {"url": "u"}


def test_utf16_is_not_autodetected() -> None:
    assert decode_worker_line('{"type": "page_crash", "data": {}}'.encode("utf-16")) is None


def test_worker_deadline_bounds_match_what_the_worker_accepts() -> None:
    source = Settings().worker_path.read_text()
    assert "MIN_DEADLINE_S = 5.0" in source
    assert "MAX_DEADLINE_S = 300.0" in source
    # The worker's standalone default is the same share of the host's default.
    assert "DEFAULT_DEADLINE_S = 45.0" in source
    assert worker_deadline_args(Settings(deadline_s=60.0)) == ["--deadline", "45"]


def test_worker_finished_keeps_a_clean_omitted_map() -> None:
    line = json.dumps(
        {
            "type": "worker_finished",
            "data": {
                "status": "ok",
                "error": None,
                "omitted": {"request": 37, "made_up": 1, "dialog": -4, "form": True, "popup": "9"},
            },
        }
    ).encode()
    assert decode_worker_line(line) == (
        "worker_finished",
        {"status": "ok", "error": None, "omitted": {"request": 37}},
    )


def test_worker_finished_survives_a_malformed_omitted_field() -> None:
    line = json.dumps(
        {"type": "worker_finished", "data": {"status": "ok", "error": None, "omitted": [1, 2]}}
    ).encode()
    assert decode_worker_line(line) == (
        "worker_finished",
        {"status": "ok", "error": None, "omitted": {}},
    )
