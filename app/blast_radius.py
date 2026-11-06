"""Blast Radius: a pure function from scan events to report rows.

The report is only worth anything if it never overclaims, so:

- `contained` needs proof in the events, and proof of isolation comes from host
  events. An event only counts when its `source` is the right one, whatever it claims.
- A row with no evidence is `not_observed`, never a reassuring status.
- `clear` means a check really ran and found nothing; `contained` means something
  happened and was stopped.
- A request the worker aborted locally (`--offline`) was never tested against a
  firewall and is never presented as if it had been.
"""

from __future__ import annotations

import ipaddress
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from app.urlpolicy import (
    IPAddress,
    address_stays_in_sandbox,
    destination_is_non_public,
    destination_stays_in_sandbox,
    is_public_ip,
)

MAX_EVIDENCE_SEQS = 50

# What Chromium should report for the firewall's REJECT: icmp-admin-prohibited becomes
# EHOSTUNREACH, which is net::ERR_ADDRESS_UNREACHABLE. That is reasoning from the kernel's
# and Chromium's sources. deploy/verify_sandbox.sh measures it on the VM, and fails if
# this list is wrong. Every other error may have a cause that has nothing to do with the
# firewall, such as a browser's own check, a CORS refusal or a page's CSP.
FIREWALL_REJECT_ERRORS = ("net::ERR_ADDRESS_UNREACHABLE",)
CONNECTION_RESET_ERROR = "net::ERR_CONNECTION_REFUSED"
UNRESOLVED_NAME_ERROR = "net::ERR_NAME_NOT_RESOLVED"
REQUEST_EVENT_TYPES = frozenset({"request", "request_failed", "response"})
# Mirrors LD_SANDBOX_SUBNET in deploy/common.sh.
SANDBOX_SUBNET = ipaddress.ip_network("172.30.0.0/24")

Event = Mapping[str, Any]


class _Events:
    """Read access to events, filtered by who is allowed to assert each type."""

    def __init__(self, events: Iterable[Event]) -> None:
        self._events = list(events)
        self.source_by_seq = {
            event["seq"]: event.get("source")
            for event in self._events
            if isinstance(event.get("seq"), int)
        }

    def host(self, event_type: str) -> list[Event]:
        return self._of(event_type, "host")

    def worker(self, event_type: str) -> list[Event]:
        return self._of(event_type, "worker")

    def _of(self, event_type: str, source: str) -> list[Event]:
        return [
            event
            for event in self._events
            if event.get("type") == event_type and event.get("source") == source
        ]

    @property
    def is_docker_scan(self) -> bool:
        return bool(self.host("sandbox_created"))

    @property
    def removal_verified(self) -> bool:
        removals = self.host("sandbox_removed")
        return bool(removals) and _data(removals[-1]).get("verified") is True


def _data(event: Event) -> Mapping[str, Any]:
    data = event.get("data")
    return data if isinstance(data, Mapping) else {}


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


class _RowBuilder:
    """Builds one row, deriving `source` from the events cited as evidence."""

    def __init__(self, events: _Events, row_id: str, label: str) -> None:
        self._events = events
        self._id = row_id
        self._label = label

    def __call__(self, status: str, detail: str, evidence: Iterable[Event] = ()) -> dict[str, Any]:
        seqs = sorted({event["seq"] for event in evidence if isinstance(event.get("seq"), int)})
        sources = {self._events.source_by_seq.get(seq) for seq in seqs}
        source = None if not sources else sources.pop() if len(sources) == 1 else "both"
        return {
            "id": self._id,
            "label": self._label,
            "status": status,
            "detail": detail,
            "evidence_seqs": seqs[:MAX_EVIDENCE_SEQS],
            "source": source,
        }


def _downloads(events: _Events) -> dict[str, Any]:
    attempts = events.worker("download_attempt")
    make = _RowBuilder(events, "downloads", "Downloads")
    if not attempts:
        return make("not_observed", "No download attempt was recorded.")
    count = _plural(len(attempts), "download attempt")
    if events.is_docker_scan and events.removal_verified:
        return make(
            "contained",
            f"{count} recorded. The worker never keeps or opens files, and the sandbox "
            "was verifiably destroyed.",
            [*attempts, *events.host("sandbox_removed")],
        )
    return make(
        "observed",
        f"{count} recorded. Containment is not proven: this run has no verified "
        "destruction of a sandbox.",
        attempts,
    )


def _private_network(events: _Events) -> dict[str, Any]:
    make = _RowBuilder(events, "private_network", "Private network")
    attempts = [e for e in events.worker("request") if _is_non_public(e, "url")]
    failures = [e for e in events.worker("request_failed") if _is_non_public(e, "url")]
    answers = [e for e in events.worker("response") if _answered_from_non_public(e)]
    answers += [
        e
        for e in events.worker("navigation")
        if _is_non_public(e, "url") and isinstance(_data(e).get("status"), int)
    ]
    local_aborts = [e for e in failures if _data(e).get("blocked_locally") is True]
    real_failures = [e for e in failures if _data(e).get("blocked_locally") is not True]

    if not events.is_docker_scan:
        if local_aborts or real_failures or attempts or answers:
            return make(
                "not_applicable",
                "No firewall was exercised: this run had no sandbox. Requests to non-public "
                "destinations were not tested, and a local abort is not a firewall block.",
                [*attempts, *failures, *answers],
            )
        return make("not_observed", "No request to a non-public destination was recorded.")

    # An answer outranks anything else in this row. Only one that came from outside the
    # sandbox says something about the firewall, which never sees the sandbox's own loopback.
    breaches = [e for e in answers if not _answered_from_inside(e)]
    if breaches:
        return make(
            "failed",
            f"{_plural(_distinct_urls(breaches), 'non-public destination')} answered the "
            "browser. The firewall did not stop this traffic.",
            breaches,
        )
    # The firewall rejects with an ICMP error. A refusal is a TCP reset, so a host answered.
    resets = [e for e in real_failures if _is_reset_from_past_the_firewall(e)]
    if resets:
        return make(
            "failed",
            f"{_plural(len(resets), 'request')} to non-public destinations got a connection "
            "reset, not the firewall's rejection. The traffic got past the firewall.",
            resets,
        )

    gap = _evidence_gap(events)
    gap_note = f" {gap.detail}" if gap else ""
    gap_events = gap.events if gap else []

    if not attempts and not failures and not answers:
        return _no_private_request(events, make, gap)

    if local_aborts and not real_failures:
        return make(
            "not_applicable",
            "These requests were aborted locally by the worker, so the firewall was not "
            "tested. A local abort is not a firewall block.",
            local_aborts,
        )

    never_resolved = {_url_of(e) for e in real_failures if UNRESOLVED_NAME_ERROR in _error_of(e)}
    routable_attempts = [e for e in attempts if not _stays_in_sandbox(e) and _url_of(e) not in never_resolved]
    routable_failures = [e for e in real_failures if _could_reach_firewall(e)]
    if not routable_attempts and not routable_failures:
        return _firewall_not_exercised(make, answers, [*attempts, *real_failures], gap_note, gap_events)

    blocked = [e for e in routable_failures if _has_firewall_signature(e)]
    inconclusive = [e for e in routable_failures if not _has_firewall_signature(e)]
    # A request that merely ended with the browser may already have reached its target,
    # and one with no recorded outcome may have succeeded. Neither proves a block.
    unproven = _count_without_failure(routable_attempts, blocked)
    if blocked and not unproven and not inconclusive and not gap:
        return make(
            "contained",
            f"The worker reported {_plural(len(blocked), 'request')} to non-public destinations "
            f"failing with the firewall's rejection: {_summarize_errors(blocked)}.",
            blocked,
        )
    evidence = [*routable_attempts, *routable_failures, *gap_events]
    if blocked:
        unexplained = max(unproven, len(inconclusive))
        return make(
            "observed",
            f"{_plural(len(blocked), 'request')} to non-public destinations failed with the "
            f"firewall's rejection, but {unexplained} more did not. Those are not proven "
            f"blocked.{gap_note}",
            evidence,
        )
    errors = f" Errors seen: {_summarize_errors(inconclusive)}." if inconclusive else ""
    return make(
        "observed",
        "Requests to non-public destinations were made, but none failed with the firewall's "
        f"rejection. They are not proven blocked.{errors}{gap_note}",
        evidence,
    )


def _no_private_request(events: _Events, make: _RowBuilder, gap: _EvidenceGap | None) -> dict[str, Any]:
    # A name that looks public can resolve to a private address, and a failed request has
    # no peer address. The firewall's own error on one may be a block worth showing.
    possible = [
        e
        for e in events.worker("request_failed")
        if _has_firewall_signature(e) and _data(e).get("blocked_locally") is not True
    ]
    if possible:
        return make(
            "observed",
            f"{_plural(len(possible), 'request')} to public-looking names failed with the "
            "firewall's error. The firewall may have blocked them, but the address they "
            "resolved to is not recorded.",
            possible,
        )
    if gap:
        return make(
            "observed",
            f"No request to a non-public destination was recorded, but the record is "
            f"incomplete. {gap.detail}",
            gap.events,
        )
    return make("not_observed", "No request to a non-public destination was recorded.")


def _firewall_not_exercised(
    make: _RowBuilder, answers: list[Event], requests: list[Event], gap_note: str, gap_events: list[Event]
) -> dict[str, Any]:
    if answers:
        return make(
            "observed",
            "Something inside the sandbox answered on its own loopback. That traffic never "
            f"reaches the firewall, so this says nothing about it.{gap_note}",
            [*answers, *requests, *gap_events],
        )
    if gap_note:
        return make("observed", f"The firewall was not exercised by what was recorded.{gap_note}", [*requests, *gap_events])
    return make(
        "not_applicable",
        "These requests went to the sandbox's own loopback or to a name that did not resolve. "
        "Neither reaches the firewall, so it was not tested.",
        requests,
    )


@dataclass(frozen=True)
class _EvidenceGap:
    detail: str
    events: list[Event]


def _evidence_gap(events: _Events) -> _EvidenceGap | None:
    """Why the request log may be incomplete. A flood must not be able to earn `contained`."""
    finished = events.worker("worker_finished")
    if any(_data(e).get("tracking_shed") is True for e in finished):
        return _EvidenceGap("The worker stopped recording requests during a flood.", finished)
    held_back = [e for e in finished if set(_omitted_counts(e)) & REQUEST_EVENT_TYPES]
    if held_back:
        return _EvidenceGap("The request log hit a cap, so some requests are not recorded.", held_back)
    dropped = [e for e in events.host("output_dropped") if _data(e).get("count")]
    killed = events.host("output_limit_killed")
    if dropped or killed:
        return _EvidenceGap("Some worker output did not reach this report.", [*dropped, *killed])
    ended = events.host("sandbox_exit") or events.host("scan_finished")
    if ended and not finished:
        return _EvidenceGap("The worker never finished its report.", ended)
    return None


def _count_without_failure(attempts: list[Event], failures: list[Event]) -> int:
    remaining = Counter(str(_data(e).get("url")) for e in attempts)
    remaining.subtract(str(_data(e).get("url")) for e in failures)
    return sum(count for count in remaining.values() if count > 0)


def _distinct_urls(items: list[Event]) -> int:
    return len({str(_data(e).get("url")) for e in items})


def _is_non_public(event: Event, field: str) -> bool:
    return destination_is_non_public(_data(event).get(field))


def _peer_address(event: Event) -> IPAddress | None:
    peer = _data(event).get("peer_ip")
    if not isinstance(peer, str):
        return None
    try:
        return ipaddress.ip_address(peer)
    except ValueError:
        return None


def _answered_from_non_public(event: Event) -> bool:
    """Judged by where the browser really connected, so DNS rebinding cannot hide it."""
    peer = _peer_address(event)
    return not is_public_ip(peer) if peer is not None else _is_non_public(event, "url")


def _answered_from_inside(event: Event) -> bool:
    peer = _peer_address(event)
    return address_stays_in_sandbox(peer) if peer is not None else _stays_in_sandbox(event)


def _stays_in_sandbox(event: Event) -> bool:
    return destination_stays_in_sandbox(_data(event).get("url"))


def _url_of(event: Event) -> str:
    return str(_data(event).get("url"))


def _error_of(event: Event) -> str:
    return str(_data(event).get("error", ""))


def _could_reach_firewall(event: Event) -> bool:
    return not _stays_in_sandbox(event) and UNRESOLVED_NAME_ERROR not in _error_of(event)


def _has_firewall_signature(event: Event) -> bool:
    return any(error in _error_of(event) for error in FIREWALL_REJECT_ERRORS)


def _is_reset_from_past_the_firewall(event: Event) -> bool:
    if CONNECTION_RESET_ERROR not in _error_of(event) or _stays_in_sandbox(event):
        return False
    # The sandbox's own address is local to it, so a refusal there left no machine.
    host = urlsplit(str(_data(event).get("url"))).hostname or ""
    try:
        return ipaddress.ip_address(host) not in SANDBOX_SUBNET
    except ValueError:
        return True


def _summarize_errors(failures: list[Event]) -> str:
    counts = Counter(str(_data(event).get("error", "unknown"))[:64] for event in failures)
    return ", ".join(f"{error} x{count}" for error, count in counts.most_common(3))


def _kill_confirmed(event: Event) -> bool:
    return _data(event).get("kill_confirmed") is True


def _freeze(events: _Events) -> dict[str, Any]:
    make = _RowBuilder(events, "freeze", "Frozen page")
    unresponsive = events.worker("page_unresponsive")
    killed = events.host("deadline_killed")
    if not unresponsive and not killed:
        return make("not_observed", "No page freeze was recorded.")
    evidence = [*unresponsive, *killed]
    if not events.is_docker_scan:
        return make(
            "observed",
            "The page stopped responding or hit the deadline. This run had no sandbox.",
            evidence,
        )
    removals = events.host("sandbox_removed")
    if killed:
        deadline = _data(killed[-1]).get("deadline_s")
        limit = f" ({deadline:g} s)" if isinstance(deadline, int | float) else ""
        if not _kill_confirmed(killed[-1]):
            return make(
                "observed",
                f"The deadline{limit} passed, but the host could not confirm that docker kill "
                "stopped the sandbox.",
                [*evidence, *removals],
            )
        if events.removal_verified:
            return make(
                "contained",
                f"The host killed the sandbox at its deadline{limit}, and its removal was verified.",
                [*evidence, *removals],
            )
        return make(
            "observed",
            f"The host killed the sandbox at its deadline{limit}, but its removal is not verified.",
            [*evidence, *removals],
        )
    operations = _plural(len(unresponsive), "browser operation")
    if events.removal_verified:
        return make(
            "contained",
            f"{operations} timed out on a frozen page. The worker stopped by itself, and the "
            "sandbox was then verifiably destroyed.",
            [*evidence, *removals],
        )
    return make("observed", f"{operations} timed out on a frozen page.", [*evidence, *removals])


def _memory(events: _Events) -> dict[str, Any]:
    make = _RowBuilder(events, "memory", "Memory")
    exits = events.host("sandbox_exit")
    oom = [e for e in exits if _data(e).get("oom_killed") is True]
    if oom:
        return make(
            "contained",
            "The sandbox's memory limit was enforced: the kernel OOM killer acted inside it.",
            oom,
        )
    crashes = events.worker("page_crash")
    if crashes:
        return make(
            "observed",
            f"{_plural(len(crashes), 'page crash')} recorded. The host did not record an "
            "OOM kill, so the cause is not established.",
            crashes,
        )
    host_kills = events.host("deadline_killed") or events.host("output_limit_killed")
    unexplained = [
        e
        for e in exits
        if _data(e).get("exit_code") == 137 and _data(e).get("oom_killed") is None and not host_kills
    ]
    if unexplained:
        return make(
            "observed",
            "The sandbox was killed by a signal the host did not send, and the OOM status "
            "is unknown.",
            unexplained,
        )
    return make("not_observed", "No memory exhaustion was recorded.")


def _concealed_text(events: _Events) -> dict[str, Any]:
    make = _RowBuilder(events, "concealed_text", "Concealed text")
    layers = [e for e in events.worker("text_layers") if _concealed_items(e)]
    if not layers:
        return make("not_observed", "No concealed text was found.")
    sources = Counter(_concealed_source(item) for e in layers for item in _concealed_items(e))
    total = sum(sources.values())
    breakdown = ", ".join(sorted(sources))
    return make(
        "observed",
        f"{_plural(total, 'concealed text fragment')} extracted ({breakdown}). "
        "This row reports them without judging them.",
        layers,
    )


def _concealed_items(event: Event) -> list[Any]:
    items = _data(event).get("concealed")
    return items if isinstance(items, list) else []


def _concealed_source(item: object) -> str:
    return str(item.get("source", "unknown")) if isinstance(item, Mapping) else "unknown"


def _secrets(events: _Events) -> dict[str, Any]:
    make = _RowBuilder(events, "secrets", "Secrets")
    audits = events.host("secret_audit")
    if not audits:
        return make("not_observed", "No secret audit ran for this scan.")
    audit = _data(audits[-1])
    if audit.get("ok") is not True:
        return make(
            "failed",
            "The secret audit failed: a configured secret was in the sandbox's environment, "
            "or the environment could not be read. The sandbox was killed.",
            audits,
        )
    checked = audit.get("checked_count")
    if not isinstance(checked, int) or checked < 1:
        return make(
            "not_observed",
            "The audit ran, but no secrets were configured to compare against.",
            audits,
        )
    if audit.get("canary") is True:
        return make(
            "clear",
            f"{_plural(checked, 'value')} compared against the sandbox's environment, including "
            "a random canary planted in the orchestrator's. None was present.",
            audits,
        )
    return make(
        "clear",
        f"{_plural(checked, 'configured secret')} compared against the sandbox's environment. "
        "None was present.",
        audits,
    )


def _limits(events: _Events) -> dict[str, Any]:
    make = _RowBuilder(events, "limits", "Limits")
    output_kills = events.host("output_limit_killed")
    deadline_kills = events.host("deadline_killed")
    dropped = events.host("output_dropped")
    dropped_count = sum(
        count for e in dropped if isinstance(count := _data(e).get("count"), int)
    )

    if output_kills or deadline_kills:
        reasons = [str(_data(e).get("reason", "unknown")) for e in output_kills]
        reasons += ["deadline"] * len(deadline_kills)
        summary = f"Hard limit hit ({', '.join(reasons)})"
        evidence = [*output_kills, *deadline_kills, *dropped]
        if not events.is_docker_scan:
            return make("observed", f"{summary}: the host killed the process. This run had no sandbox.", evidence)
        evidence += events.host("sandbox_removed")
        if not all(_kill_confirmed(e) for e in [*output_kills, *deadline_kills]):
            return make("observed", f"{summary}, but the host could not confirm the kill.", evidence)
        if events.removal_verified:
            return make("contained", f"{summary}: the host killed the sandbox, and its removal was verified.", evidence)
        return make("observed", f"{summary}: the host killed the sandbox, but its removal is not verified.", evidence)
    if dropped_count:
        return make(
            "observed",
            f"{_plural(dropped_count, 'worker output line')} failed validation or passed a "
            "per-type cap, and did not reach this report.",
            dropped,
        )
    self_stopped = [e for e in events.worker("worker_finished") if _data(e).get("deadline_reached") is True]
    if self_stopped:
        return make(
            "observed",
            "The worker reached its own time limit and stopped the scan early. The host did "
            "not have to act, but what the page did after that point is not recorded.",
            self_stopped,
        )
    omitted = [e for e in events.worker("worker_finished") if _omitted_counts(e)]
    if omitted:
        counts = Counter[str]()
        for event in omitted:
            counts.update(_omitted_counts(event))
        summary = ", ".join(f"{name} x{count}" for name, count in sorted(counts.items()))
        return make(
            "observed",
            f"The worker reported events held back by its own caps ({summary}). "
            "They did not reach this report.",
            omitted,
        )
    exits = events.host("sandbox_exit")
    if exits:
        return make("clear", "The scan ended without reaching a time or output limit.", exits)
    return make("not_observed", "No limit event has been recorded.")


def _omitted_counts(event: Event) -> Mapping[str, int]:
    counts = _data(event).get("omitted")
    return counts if isinstance(counts, Mapping) else {}


def _destroyed(events: _Events) -> dict[str, Any]:
    make = _RowBuilder(events, "destroyed", "Sandbox destroyed")
    removals = events.host("sandbox_removed")
    created = events.host("sandbox_created")
    if removals and not events.removal_verified:
        return make(
            "failed",
            "Removal could not be verified: docker inspect did not report the container as gone.",
            removals,
        )
    if removals and created:
        return make(
            "contained",
            "Verified after cleanup: docker inspect reports that the container does not exist.",
            removals,
        )
    if removals:
        return make("not_observed", "No sandbox was started, so there was nothing to destroy.", removals)
    if created and events.host("scan_finished"):
        return make(
            "failed",
            "The scan finished without any record that the sandbox was removed.",
            [*created, *events.host("scan_finished")],
        )
    return make("not_observed", "No sandbox removal has been recorded.", created)


def compute_blast_radius(events: Iterable[Event]) -> list[dict[str, Any]]:
    """Returns one row per contract row id, in the contract's order."""
    view = _Events(events)
    return [
        _downloads(view),
        _private_network(view),
        _freeze(view),
        _memory(view),
        _concealed_text(view),
        _secrets(view),
        _limits(view),
        _destroyed(view),
    ]
