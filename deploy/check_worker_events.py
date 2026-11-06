"""Judges a real worker run for verify_sandbox.sh. Standard library only, runs on the VM.

Reads the worker's event lines on stdin and prints one line per result: PASS or FAIL,
check name, detail, separated by tabs. This is where the claim behind the private_network
row gets measured: the row trusts only FIREWALL_REJECT_ERRORS, which must match what
Chromium really reports for the firewall's REJECT. If this fails, fix the cause or change
that list in app/blast_radius.py and here, together.
"""

import ipaddress
import json
import sys
from collections import Counter
from urllib.parse import urlsplit

FIREWALL_REJECT_ERRORS = ("net::ERR_ADDRESS_UNREACHABLE",)


def emit(ok: bool, check: str, detail: str) -> None:
    clean = detail.replace("\t", " ").replace("\n", " ")
    print(f"{'PASS' if ok else 'FAIL'}\t{check}\t{clean}", flush=True)


def read_events(lines: list[str]) -> list[dict]:
    events = []
    for line in lines:
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if isinstance(event, dict) and isinstance(event.get("data"), dict):
            events.append(event)
    return events


def routable_private(url: object) -> bool:
    """A private literal that has to cross the firewall. Loopback stays in the container."""
    try:
        address = ipaddress.ip_address(urlsplit(str(url)).hostname or "")
    except ValueError:
        return False
    return not address.is_global and not address.is_loopback and not address.is_unspecified


def check_private_network(events: list[dict]) -> None:
    errors = Counter(
        str(event["data"].get("error"))
        for event in events
        if event.get("type") == "request_failed" and routable_private(event["data"].get("url"))
    )
    summary = ", ".join(f"{error} x{count}" for error, count in errors.most_common(5)) or "none recorded"
    matched = bool(errors) and all(error in FIREWALL_REJECT_ERRORS for error in errors)
    emit(matched, "browser sees the firewall error", f"errors for private targets: {summary}")

    answers = [event["data"].get("url") for event in events if event.get("type") == "response"]
    leaks = [url for url in answers if not _stays_local(url)]
    emit(bool(errors) and not leaks, "no private answers", f"{len(leaks)} answer(s) from past the firewall")


def _stays_local(url: object) -> bool:
    try:
        address = ipaddress.ip_address(urlsplit(str(url)).hostname or "")
    except ValueError:
        return False
    return address.is_loopback or address.is_unspecified


def check_live_page(events: list[dict]) -> None:
    statuses = [
        event["data"].get("status")
        for event in events
        if event.get("type") == "navigation" and isinstance(event["data"].get("status"), int)
    ]
    emit(bool(statuses), "live page loads", f"navigation statuses: {statuses[:5] or 'none'}")


CHECKS = {"private-network": check_private_network, "live-page": check_live_page}


def main(argv: list[str]) -> int:
    CHECKS[argv[0]](read_events(sys.stdin.read().splitlines()))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
