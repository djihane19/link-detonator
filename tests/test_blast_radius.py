"""Blast Radius honesty rules. A row must never claim more than the events prove."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest

from app.blast_radius import FIREWALL_REJECT_ERRORS, MAX_EVIDENCE_SEQS, compute_blast_radius
from app.models import BlastRadiusRow

ROW_IDS = [
    "downloads",
    "private_network",
    "freeze",
    "memory",
    "concealed_text",
    "secrets",
    "limits",
    "destroyed",
]


FIREWALL_REJECT = "net::ERR_ADDRESS_UNREACHABLE"


class Scan:
    """Builds an event list with host-assigned seqs."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def add(self, source: str, event_type: str, **data: Any) -> Scan:
        self.events.append(
            {"v": 1, "seq": len(self.events) + 1, "ts": 0.0, "source": source, "type": event_type, "data": data}
        )
        return self

    def host(self, event_type: str, **data: Any) -> Scan:
        return self.add("host", event_type, **data)

    def worker(self, event_type: str, **data: Any) -> Scan:
        return self.add("worker", event_type, **data)

    def docker(self) -> Scan:
        return self.host("sandbox_created", name="ld-x", image="i", runtime="runc", policy={})

    def verified_end(self) -> Scan:
        return (
            self.worker("worker_finished", status="ok", error=None)
            .host("sandbox_exit", exit_code=0, oom_killed=False)
            .host("sandbox_removed", verified=True)
        )

    def request(self, url: str) -> Scan:
        return self.worker("request", url=url, method="GET", resource_type="fetch")

    def failed(self, url: str, error: str = FIREWALL_REJECT, local: bool = False) -> Scan:
        return self.worker("request_failed", url=url, error=error, resource_type="fetch", blocked_locally=local)

    def row(self, row_id: str) -> dict[str, Any]:
        return next(r for r in compute_blast_radius(self.events) if r["id"] == row_id)


METADATA = "http://169.254.169.254/latest/meta-data/"
RFC1918 = "http://10.0.0.1/"
LOOPBACK = "http://127.0.0.1:3000/"


# --- Shape -----------------------------------------------------------------------


def test_every_row_in_contract_order_with_contract_fields() -> None:
    rows = compute_blast_radius(Scan().docker().verified_end().events)
    assert [row["id"] for row in rows] == ROW_IDS
    for row in rows:
        assert set(row) == {"id", "label", "status", "detail", "evidence_seqs", "source"}
        BlastRadiusRow(**row)


def test_no_evidence_means_not_observed_everywhere() -> None:
    rows = compute_blast_radius([])
    assert {row["status"] for row in rows} == {"not_observed"}
    assert all(row["evidence_seqs"] == [] and row["source"] is None for row in rows)


def test_pure_does_not_mutate_or_depend_on_call_count() -> None:
    scan = Scan().docker().request(METADATA).failed(METADATA).verified_end()
    before = copy.deepcopy(scan.events)
    first = compute_blast_radius(scan.events)
    second = compute_blast_radius(scan.events)
    assert first == second
    assert scan.events == before


def test_accepts_a_generator() -> None:
    assert len(compute_blast_radius(e for e in Scan().docker().events)) == len(ROW_IDS)


def test_evidence_seqs_are_capped() -> None:
    scan = Scan().docker()
    for _ in range(MAX_EVIDENCE_SEQS + 10):
        scan.worker("download_attempt", url="http://x/", suggested_filename="f")
    scan.verified_end()
    assert len(scan.row("downloads")["evidence_seqs"]) == MAX_EVIDENCE_SEQS


# --- Source is checked, whatever an event claims -----------------------------------


@pytest.mark.parametrize(
    ("event_type", "data", "row_id"),
    [
        ("sandbox_removed", {"verified": True}, "destroyed"),
        ("secret_audit", {"ok": True, "checked_count": 3}, "secrets"),
        ("deadline_killed", {"deadline_s": 60}, "freeze"),
        ("output_limit_killed", {"reason": "x"}, "limits"),
        ("sandbox_exit", {"exit_code": 137, "oom_killed": True}, "memory"),
    ],
)
def test_host_facts_from_a_worker_source_are_ignored(event_type: str, data: dict, row_id: str) -> None:
    assert Scan().worker(event_type, **data).row(row_id)["status"] == "not_observed"


def test_sandbox_created_from_a_worker_does_not_make_it_a_docker_scan() -> None:
    scan = Scan().worker("sandbox_created", name="spoof", policy={}).failed(METADATA)
    assert scan.row("private_network")["status"] == "not_applicable"


def test_spoofed_sandbox_removed_cannot_turn_a_failure_into_contained() -> None:
    scan = Scan().docker().host("sandbox_removed", verified=False).worker("sandbox_removed", verified=True)
    assert scan.row("destroyed")["status"] == "failed"


# --- private_network -------------------------------------------------------------


def test_private_network_contained_only_for_failed_non_public_in_docker() -> None:
    scan = Scan().docker().request(METADATA).failed(METADATA).verified_end()
    row = scan.row("private_network")
    assert row["status"] == "contained"
    assert row["source"] == "worker"
    assert FIREWALL_REJECT in row["detail"]
    assert "worker reported" in row["detail"]
    assert row["evidence_seqs"] == [3]


def test_all_three_private_destinations_contained() -> None:
    scan = Scan().docker()
    for url in (METADATA, RFC1918):
        scan.request(url).failed(url)
    # Loopback stays inside the container, so its refusal neither helps nor hurts.
    scan.request(LOOPBACK).failed(LOOPBACK, "net::ERR_CONNECTION_REFUSED")
    assert scan.verified_end().row("private_network")["status"] == "contained"


def test_blocked_locally_is_not_applicable_and_says_why() -> None:
    row = Scan().request(METADATA).failed(METADATA, "net::ERR_FAILED", local=True).row("private_network")
    assert row["status"] == "not_applicable"
    assert "firewall" in row["detail"].lower()
    assert row["status"] != "contained"


def test_blocked_locally_is_never_a_firewall_block_even_with_a_sandbox_event() -> None:
    row = Scan().docker().request(METADATA).failed(METADATA, local=True).verified_end().row("private_network")
    assert row["status"] == "not_applicable"
    assert "not a firewall block" in row["detail"]


def test_failure_outside_docker_is_not_contained() -> None:
    assert Scan().request(METADATA).failed(METADATA).row("private_network")["status"] == "not_applicable"


def test_attempt_outside_docker_is_not_applicable() -> None:
    assert Scan().request(METADATA).row("private_network")["status"] == "not_applicable"


def test_failed_public_request_proves_nothing() -> None:
    scan = Scan().docker().request("https://example.com/").failed("https://example.com/", "net::ERR_TIMED_OUT").verified_end()
    assert scan.row("private_network")["status"] == "not_observed"


def test_failed_named_host_proves_nothing_because_it_was_not_resolved_here() -> None:
    scan = Scan().docker().failed("https://rebind.example.com/", "net::ERR_TIMED_OUT").verified_end()
    assert scan.row("private_network")["status"] == "not_observed"


def test_firewall_error_on_a_public_name_is_a_possible_block_not_nothing() -> None:
    row = Scan().docker().failed("http://rebind.attacker.example/").verified_end().row("private_network")
    assert row["status"] == "observed"
    assert "may have blocked" in row["detail"]


def test_response_from_a_public_name_with_a_private_peer_is_a_failure() -> None:
    scan = (
        Scan()
        .docker()
        .worker("response", url="http://rebind.attacker.example/", status=200, peer_ip="169.254.169.254")
        .verified_end()
    )
    assert scan.row("private_network")["status"] == "failed"


def test_public_peer_on_a_public_name_is_not_a_private_answer() -> None:
    scan = Scan().docker().worker("response", url="http://a.example.org/", status=200, peer_ip="93.184.216.34")
    assert scan.verified_end().row("private_network")["status"] == "not_observed"


def test_subresource_answer_fails_the_row_even_after_a_later_abort() -> None:
    scan = (
        Scan()
        .docker()
        .request(METADATA)
        .worker("response", url=METADATA, status=200, peer_ip=None)
        .failed(METADATA, "net::ERR_ABORTED")
        .verified_end()
    )
    row = scan.row("private_network")
    assert row["status"] == "failed"
    assert "firewall" in row["detail"]


@pytest.mark.parametrize(
    "error",
    [
        "net::ERR_FAILED",
        "net::ERR_BLOCKED_BY_ORB",
        "net::ERR_UNSAFE_PORT",
        "csp",
        "net::ERR_CONNECTION_TIMED_OUT",
        "net::ERR_BLOCKED_BY_CLIENT",
    ],
)
def test_other_errors_are_never_contained(error: str) -> None:
    row = Scan().docker().request(RFC1918).failed(RFC1918, error).verified_end().row("private_network")
    assert row["status"] == "observed"
    assert "not proven" in row["detail"]


def test_connection_refused_from_a_private_host_is_evidence_of_a_gap() -> None:
    row = Scan().docker().request(RFC1918).failed(RFC1918, "net::ERR_CONNECTION_REFUSED").verified_end().row("private_network")
    assert row["status"] == "failed"
    assert "past the firewall" in row["detail"]


def test_connection_refused_on_the_sandbox_subnet_left_no_machine() -> None:
    url = "http://172.30.0.2:1/"
    row = Scan().docker().request(url).failed(url, "net::ERR_CONNECTION_REFUSED").verified_end().row("private_network")
    assert row["status"] == "observed"


@pytest.mark.parametrize(
    ("url", "error"),
    [
        (LOOPBACK, "net::ERR_CONNECTION_REFUSED"),
        ("http://foo.localhost/", "net::ERR_CONNECTION_REFUSED"),
        ("http://0.0.0.0/", "net::ERR_CONNECTION_REFUSED"),
        ("http://intranet/", "net::ERR_NAME_NOT_RESOLVED"),
    ],
)
def test_destinations_that_never_meet_the_firewall_are_not_contained(url: str, error: str) -> None:
    row = Scan().docker().request(url).failed(url, error).verified_end().row("private_network")
    assert row["status"] == "not_applicable"
    assert "not tested" in row["detail"]


def test_answer_on_the_sandboxs_own_loopback_is_not_a_breach() -> None:
    scan = Scan().docker().request(LOOPBACK).worker("response", url=LOOPBACK, status=200, peer_ip="127.0.0.1")
    row = scan.verified_end().row("private_network")
    assert row["status"] == "observed"
    assert "loopback" in row["detail"]


@pytest.mark.parametrize(
    "finished",
    [
        {"omitted": {"request": 3}},
        {"omitted": {"request_failed": 3}},
        {"tracking_shed": True},
    ],
)
def test_contained_needs_a_complete_request_log(finished: dict[str, Any]) -> None:
    scan = (
        Scan().docker().request(METADATA).failed(METADATA)
        .worker("worker_finished", status="ok", error=None, **finished)
        .host("sandbox_exit", exit_code=0, oom_killed=False)
        .host("sandbox_removed", verified=True)
    )
    assert scan.row("private_network")["status"] == "observed"


@pytest.mark.parametrize(
    "add_gap",
    [
        lambda scan: scan.host("output_dropped", count=2),
        lambda scan: scan.host("output_limit_killed", reason="x", kill_confirmed=True),
    ],
)
def test_lost_output_downgrades_contained(add_gap: Any) -> None:
    scan = add_gap(Scan().docker().request(METADATA).failed(METADATA)).verified_end()
    assert scan.row("private_network")["status"] == "observed"


def test_missing_worker_report_downgrades_contained_and_not_observed() -> None:
    ended = Scan().docker().request(METADATA).failed(METADATA).host("sandbox_exit", exit_code=137, oom_killed=False)
    assert ended.row("private_network")["status"] == "observed"
    quiet = Scan().docker().host("sandbox_exit", exit_code=137, oom_killed=False)
    assert quiet.row("private_network")["status"] == "observed"


def test_flooded_log_with_no_private_request_is_not_not_observed() -> None:
    scan = Scan().docker().worker("worker_finished", status="ok", error=None, omitted={"request": 40})
    row = scan.row("private_network")
    assert row["status"] == "observed"
    assert "incomplete" in row["detail"]


def test_fixture_origin_is_not_a_private_destination() -> None:
    url = "http://fixtures.invalid/benign"
    scan = Scan().docker().request(url).failed(url, "net::ERR_NAME_NOT_RESOLVED").verified_end()
    assert scan.row("private_network")["status"] == "not_observed"


def test_attempt_with_no_outcome_is_observed_not_contained() -> None:
    row = Scan().docker().request(METADATA).verified_end().row("private_network")
    assert row["status"] == "observed"
    assert "not proven" in row["detail"]


def test_firewall_signature_matches_the_vm_check() -> None:
    script = Path(__file__).resolve().parent.parent / "deploy" / "check_worker_events.py"
    assert all(f'"{error}"' in script.read_text() for error in FIREWALL_REJECT_ERRORS)


def test_abort_at_browser_close_is_not_proof_of_a_block() -> None:
    scan = Scan().docker().request(METADATA).failed(METADATA, "net::ERR_ABORTED").verified_end()
    assert scan.row("private_network")["status"] == "observed"


def test_request_still_pending_at_scan_end_is_not_proof_of_a_block() -> None:
    error = "no response before the scan ended"
    row = Scan().docker().request(METADATA).failed(METADATA, error).verified_end().row("private_network")
    assert row["status"] == "observed"
    assert "not proven" in row["detail"]


def test_one_unproven_request_prevents_contained() -> None:
    scan = Scan().docker().request(METADATA).failed(METADATA).request(RFC1918).verified_end()
    row = scan.row("private_network")
    assert row["status"] == "observed"
    assert "1 more" in row["detail"]


def test_failures_are_matched_per_url_not_by_total() -> None:
    # Two failures for one URL must not excuse the other URL having none.
    scan = Scan().docker().request(METADATA).request(RFC1918).failed(METADATA).failed(METADATA).verified_end()
    assert scan.row("private_network")["status"] == "observed"


def test_response_from_a_private_destination_is_a_failure() -> None:
    scan = (
        Scan()
        .docker()
        .request(RFC1918)
        .worker("navigation", url=RFC1918, status=200, redirected_from=None)
        .failed(METADATA)
        .verified_end()
    )
    row = scan.row("private_network")
    assert row["status"] == "failed"
    assert "firewall" in row["detail"]


def test_navigation_with_no_status_is_not_a_response() -> None:
    scan = Scan().docker().worker("navigation", url=RFC1918, status=None, redirected_from=None).verified_end()
    assert scan.row("private_network")["status"] == "not_observed"


# --- destroyed -------------------------------------------------------------------


def test_destroyed_contained_only_when_verified() -> None:
    row = Scan().docker().host("sandbox_removed", verified=True).row("destroyed")
    assert row["status"] == "contained"
    assert row["source"] == "host"
    assert row["evidence_seqs"] == [2]


@pytest.mark.parametrize("verified", [False, None, "true", 1])
def test_destroyed_failed_unless_exactly_true(verified: object) -> None:
    assert Scan().docker().host("sandbox_removed", verified=verified).row("destroyed")["status"] == "failed"


def test_destroyed_failed_when_a_finished_scan_never_recorded_removal() -> None:
    assert Scan().docker().host("scan_finished", status="ok").row("destroyed")["status"] == "failed"


def test_destroyed_still_pending_while_running() -> None:
    assert Scan().docker().row("destroyed")["status"] == "not_observed"


def test_destroyed_no_sandbox_is_not_contained() -> None:
    assert Scan().host("sandbox_removed", verified=True).row("destroyed")["status"] == "not_observed"


def test_destroyed_failed_removal_with_no_sandbox_event_still_fails() -> None:
    assert Scan().host("sandbox_removed", verified=False).row("destroyed")["status"] == "failed"


# --- downloads -------------------------------------------------------------------


def _download(scan: Scan) -> Scan:
    return scan.worker("download_attempt", url="http://x/a.txt", suggested_filename="a.txt")


def test_download_contained_with_verified_destruction() -> None:
    row = _download(Scan().docker()).verified_end().row("downloads")
    assert row["status"] == "contained"
    assert row["source"] == "both"


def test_download_observed_when_removal_failed() -> None:
    row = _download(Scan().docker()).host("sandbox_removed", verified=False).row("downloads")
    assert row["status"] == "observed"


def test_download_observed_with_no_sandbox() -> None:
    assert _download(Scan()).row("downloads")["status"] == "observed"


def test_download_not_observed() -> None:
    assert Scan().docker().verified_end().row("downloads")["status"] == "not_observed"


def test_download_detail_never_echoes_attacker_filename() -> None:
    scan = Scan().docker().worker("download_attempt", url="http://x/", suggested_filename="<b>evil</b>.exe")
    assert "evil" not in scan.verified_end().row("downloads")["detail"]


# --- freeze ----------------------------------------------------------------------


def test_freeze_contained_by_a_confirmed_deadline_kill_and_verified_removal() -> None:
    row = (
        Scan()
        .docker()
        .worker("page_unresponsive", operation="goto", timeout_ms=100)
        .host("deadline_killed", deadline_s=60, kill_confirmed=True)
        .host("sandbox_removed", verified=True)
        .row("freeze")
    )
    assert row["status"] == "contained"
    assert "(60 s)" in row["detail"]
    assert row["source"] == "both"


@pytest.mark.parametrize(
    ("kill_confirmed", "verified"),
    [(False, True), (True, False), (False, False)],
)
def test_freeze_and_limits_need_both_a_confirmed_kill_and_verified_removal(kill_confirmed: bool, verified: bool) -> None:
    scan = (
        Scan()
        .docker()
        .host("deadline_killed", deadline_s=60, kill_confirmed=kill_confirmed)
        .host("sandbox_removed", verified=verified)
    )
    assert scan.row("freeze")["status"] == "observed"
    assert scan.row("limits")["status"] == "observed"


def test_kill_without_a_recorded_outcome_is_not_confirmed() -> None:
    scan = Scan().docker().host("deadline_killed", deadline_s=60).host("sandbox_removed", verified=True)
    assert scan.row("freeze")["status"] == "observed"


def test_freeze_self_exit_does_not_claim_host_control() -> None:
    scan = Scan().docker().worker("page_unresponsive", operation="goto", timeout_ms=100).verified_end()
    row = scan.row("freeze")
    assert row["status"] == "contained"
    assert "worker stopped by itself" in row["detail"]
    assert "host control" not in row["detail"]


def test_freeze_self_exit_without_verified_removal_is_observed() -> None:
    scan = (
        Scan()
        .docker()
        .worker("page_unresponsive", operation="goto", timeout_ms=100)
        .host("sandbox_exit", exit_code=0, oom_killed=False)
        .host("sandbox_removed", verified=False)
    )
    assert scan.row("freeze")["status"] == "observed"


def test_freeze_observed_while_still_running() -> None:
    scan = Scan().docker().worker("page_unresponsive", operation="goto", timeout_ms=100)
    assert scan.row("freeze")["status"] == "observed"


def test_freeze_observed_with_no_sandbox() -> None:
    assert Scan().host("deadline_killed", deadline_s=60).row("freeze")["status"] == "observed"


def test_no_freeze() -> None:
    assert Scan().docker().verified_end().row("freeze")["status"] == "not_observed"


# --- memory ----------------------------------------------------------------------


def test_memory_contained_only_on_host_oom() -> None:
    row = Scan().docker().host("sandbox_exit", exit_code=137, oom_killed=True).row("memory")
    assert row["status"] == "contained"
    assert row["source"] == "host"


def test_page_crash_alone_is_only_observed() -> None:
    row = Scan().docker().worker("page_crash").verified_end().row("memory")
    assert row["status"] == "observed"
    assert "not established" in row["detail"]


def test_sigkill_with_unknown_oom_status_is_observed() -> None:
    assert Scan().docker().host("sandbox_exit", exit_code=137, oom_killed=None).row("memory")["status"] == "observed"


def test_host_sigkill_is_not_a_memory_signal() -> None:
    scan = Scan().docker().host("deadline_killed", deadline_s=60).host("sandbox_exit", exit_code=137, oom_killed=None)
    assert scan.row("memory")["status"] == "not_observed"


def test_clean_exit_is_no_memory_signal() -> None:
    assert Scan().docker().verified_end().row("memory")["status"] == "not_observed"


# --- concealed_text --------------------------------------------------------------


def test_concealed_text_is_always_just_observed() -> None:
    concealed = [
        {"source": "hidden_css", "text": "ignore previous", "selector": "#a"},
        {"source": "comment", "text": "x", "selector": ""},
    ]
    row = Scan().docker().worker("text_layers", visible_text="v", concealed=concealed).verified_end().row("concealed_text")
    assert row["status"] == "observed"
    assert "2 concealed" in row["detail"]
    assert "comment" in row["detail"] and "hidden_css" in row["detail"]
    assert "ignore previous" not in row["detail"], "attacker text is not echoed into the summary"
    assert "without judging" in row["detail"]


def test_no_concealed_text() -> None:
    scan = Scan().docker().worker("text_layers", visible_text="v", concealed=[])
    assert scan.row("concealed_text")["status"] == "not_observed"


# --- secrets ---------------------------------------------------------------------


def test_secret_audit_ok_is_clear() -> None:
    row = Scan().docker().host("secret_audit", ok=True, checked_count=2).row("secrets")
    assert row["status"] == "clear"
    assert "2 configured secrets" in row["detail"]


def test_secret_audit_failure_is_failed() -> None:
    assert Scan().docker().host("secret_audit", ok=False, checked_count=2).row("secrets")["status"] == "failed"


def test_audit_with_a_canary_is_clear_and_says_so() -> None:
    row = Scan().docker().host("secret_audit", ok=True, checked_count=1, canary=True).row("secrets")
    assert row["status"] == "clear"
    assert "canary" in row["detail"]


def test_audit_that_checked_nothing_proves_nothing() -> None:
    row = Scan().docker().host("secret_audit", ok=True, checked_count=0).row("secrets")
    assert row["status"] == "not_observed"
    assert "no secrets were configured" in row["detail"]


# --- limits ----------------------------------------------------------------------


def test_output_kill_in_docker_is_contained() -> None:
    scan = Scan().docker().host("output_limit_killed", reason="line_too_long", kill_confirmed=True)
    row = scan.host("sandbox_removed", verified=True).row("limits")
    assert row["status"] == "contained"
    assert "line_too_long" in row["detail"]


def test_deadline_kill_in_docker_is_contained() -> None:
    scan = Scan().docker().host("deadline_killed", deadline_s=60, kill_confirmed=True)
    assert scan.host("sandbox_removed", verified=True).row("limits")["status"] == "contained"


def test_worker_deadline_is_not_clear() -> None:
    scan = (
        Scan()
        .docker()
        .worker("worker_finished", status="partial", error="internal deadline reached", deadline_reached=True)
        .host("sandbox_exit", exit_code=0, oom_killed=False)
        .host("sandbox_removed", verified=True)
    )
    row = scan.row("limits")
    assert row["status"] == "observed"
    assert "time limit" in row["detail"]


def test_kill_with_no_sandbox_is_only_observed() -> None:
    assert Scan().host("output_limit_killed", reason="x").row("limits")["status"] == "observed"


def test_dropped_output_is_observed_with_its_count() -> None:
    row = Scan().docker().host("output_dropped", count=7).verified_end().row("limits")
    assert row["status"] == "observed"
    assert "7 worker output lines" in row["detail"]


def test_clean_exit_is_clear() -> None:
    assert Scan().docker().verified_end().row("limits")["status"] == "clear"


def test_running_scan_has_no_limit_verdict_yet() -> None:
    assert Scan().docker().row("limits")["status"] == "not_observed"


# --- Whole-scan shapes -----------------------------------------------------------


def test_local_scan_can_never_show_contained() -> None:
    scan = (
        Scan()
        .worker("worker_started", url="http://fixtures.invalid/hostile-gauntlet", mode="fixture", offline=True)
        .request(METADATA)
        .failed(METADATA, "net::ERR_FAILED", local=True)
        .worker("download_attempt", url="http://x/", suggested_filename="f")
        .worker("page_unresponsive", operation="goto", timeout_ms=1)
        .worker("page_crash")
        .worker("text_layers", visible_text="", concealed=[{"source": "alt", "text": "x", "selector": "s"}])
        .host("deadline_killed", deadline_s=60)
        .host("output_dropped", count=1)
        .worker("worker_finished", status="partial", error=None)
    )
    statuses = {row["id"]: row["status"] for row in compute_blast_radius(scan.events)}
    assert "contained" not in statuses.values()
    assert statuses["private_network"] == "not_applicable"
    assert statuses["concealed_text"] == "observed"


def test_verdict_is_not_part_of_blast_radius() -> None:
    scan = Scan().docker().verified_end().host("verdict", status="pending")
    assert all("verdict" not in row["id"] for row in compute_blast_radius(scan.events))


def test_malformed_event_data_does_not_crash_the_report() -> None:
    events = [
        {"seq": 1, "source": "host", "type": "sandbox_created"},
        {"seq": 2, "source": "worker", "type": "text_layers", "data": {"concealed": ["not a dict"]}},
        {"seq": "x", "source": "host", "type": "secret_audit", "data": None},
        {"source": "host", "type": "output_dropped", "data": {"count": "lots"}},
        {"seq": 3, "source": "worker", "type": "request", "data": {"url": 5}},
    ]
    assert [row["id"] for row in compute_blast_radius(events)] == ROW_IDS


def _finished(**fields: object) -> dict[str, object]:
    data = {"status": "ok", "error": None, **fields}
    return {"seq": 1, "source": "worker", "type": "worker_finished", "data": data}


def test_limits_row_reports_counts_held_back_by_the_worker() -> None:
    row = {r["id"]: r for r in compute_blast_radius([_finished(omitted={"request": 37})])}["limits"]
    assert row["status"] == "observed"
    assert "request x37" in row["detail"]
    assert row["source"] == "worker"


def test_limits_row_ignores_an_empty_omitted_map() -> None:
    row = {r["id"]: r for r in compute_blast_radius([_finished(omitted={})])}["limits"]
    assert row["status"] == "not_observed"
