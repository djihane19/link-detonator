"""Browser under gVisor: the pinned resolver mount, Chromium's own sandbox, and the
defaults that keep the production argv unchanged."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

from app.config import Settings
from app.sandbox import SANDBOX_POLICY, browser_policy, build_docker_argv, resolver_mount_args

ROOT = Path(__file__).resolve().parent.parent
RESOLV = "/etc/link-detonator/sandbox-resolv.conf"


def load_worker() -> Any:
    spec = importlib.util.spec_from_file_location("ld_worker_gvisor_test", ROOT / "worker" / "worker.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


worker = load_worker()


def test_no_mount_and_no_change_by_default() -> None:
    assert resolver_mount_args(Settings()) == []
    argv = build_docker_argv("ld-abc", "img:1", ["--fixture", "benign"], Settings())
    assert "--mount" not in argv and "--chromium-sandbox" not in argv


def test_resolver_mount_is_one_read_only_file_at_resolv_conf() -> None:
    assert resolver_mount_args(Settings(sandbox_resolv_conf=RESOLV)) == [
        "--mount", f"type=bind,source={RESOLV},target=/etc/resolv.conf,readonly",
    ]  # fmt: skip


def test_resolver_mount_follows_the_runtime_and_precedes_the_image() -> None:
    argv = build_docker_argv("ld-abc", "img:1", ["--url", "https://x.example/"], Settings(runtime="runsc", sandbox_resolv_conf=RESOLV))
    image = argv.index("img:1")
    assert argv.index("--runtime") < argv.index("--mount") < image
    assert argv.count("--mount") == 1
    assert argv[argv.index("--mount") + 1].endswith(",target=/etc/resolv.conf,readonly")


@pytest.mark.parametrize(
    "path",
    [
        "relative/resolv.conf",
        "/etc/../root/.ssh/id_rsa",
        "/etc/x,target=/etc/passwd",
        "/etc/resolv.conf readonly",
        "/etc/x\n",
        "/etc/x;rm",
    ],
)
def test_bad_resolver_paths_are_refused(path: str) -> None:
    with pytest.raises(ValueError):
        resolver_mount_args(Settings(sandbox_resolv_conf=path))


def test_policy_records_resolver_and_chromium_sandbox() -> None:
    default = browser_policy(Settings())
    assert default == {**SANDBOX_POLICY, "chromium_sandbox": False, "resolver": "docker embedded"}
    hardened = browser_policy(Settings(chromium_sandbox=True, sandbox_resolv_conf=RESOLV))
    assert hardened["chromium_sandbox"] is True and hardened["resolver"] == "pinned read-only file"


def test_settings_read_the_new_variables() -> None:
    settings = Settings.from_env({"LD_RUNTIME": "runsc", "LD_SANDBOX_RESOLV_CONF": RESOLV, "LD_CHROMIUM_SANDBOX": "1"})
    assert settings.sandbox_resolv_conf == RESOLV and settings.chromium_sandbox is True
    blank = Settings.from_env({"LD_SANDBOX_RESOLV_CONF": ""})
    assert blank.sandbox_resolv_conf is None and blank.chromium_sandbox is False


@pytest.mark.parametrize("offline", [True, False])
def test_no_sandbox_flag_only_when_chromium_sandbox_is_off(offline: bool) -> None:
    assert "--no-sandbox" in worker.chromium_args(offline)
    assert "--no-sandbox" not in worker.chromium_args(offline, chromium_sandbox=True)
    # Everything else is identical: turning the sandbox on removes exactly one flag.
    assert [a for a in worker.chromium_args(offline) if a != "--no-sandbox"] == worker.chromium_args(offline, chromium_sandbox=True)


def test_worker_cli_flag() -> None:
    assert worker.parse_args(["--fixture", "benign"]).chromium_sandbox is False
    assert worker.parse_args(["--url", "https://x.example/", "--chromium-sandbox"]).chromium_sandbox is True


@pytest.mark.parametrize("runtime", ["", "runc"])
def test_chromium_sandbox_without_gvisor_is_refused_at_startup(runtime: str) -> None:
    with pytest.raises(ValueError, match="LD_RUNTIME=runsc"):
        Settings.from_env({"LD_RUNTIME": runtime, "LD_CHROMIUM_SANDBOX": "1"})
