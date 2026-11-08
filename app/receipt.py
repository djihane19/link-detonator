"""Evidence receipts: a scan's recorded events as canonical JSON, linked by a SHA-256 hash
chain, with a final digest.

Trust model, stated in every receipt: the chain makes any change to the events, their
order, the scan record or the screenshots detectable against a digest saved somewhere
this server does not control, for example in a ticket when the scan finished. The digest
is not stored anywhere: the server recomputes it from its event log on every request and
shows it on the report page, so the page is not an independent copy. Anyone who controls
the server, or holds a receipt, can recompute a whole chain over altered events. It is not
a signature, and nothing here claims authenticity.

Verification needs only the Python standard library: see tools/verify_receipt.py, which
repeats these exact rules.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

VERSION = "link-detonator-receipt-v1"
TRUST_MODEL = (
    "This receipt is tamper-evident, not authenticated. The SHA-256 chain shows whether "
    "any event, the order of events, the scan record or a screenshot changed, when its final "
    "digest is compared with a copy saved somewhere the server does not control (for "
    "example a ticket, written when the scan finished). The server recomputes the digest "
    "from its own records on every request and shows it on the report page, so that page "
    "is not an independent copy. Anyone who controls the server or holds a receipt can "
    "recompute a whole chain over altered events. No signing key is used."
)


def canonical(value: Any) -> bytes:
    """One byte string per value: sorted keys, no whitespace, ASCII only."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def genesis(record: Mapping[str, Any]) -> str:
    return sha256_hex(VERSION.encode("ascii") + b"\n" + canonical(record))


def link(previous: str, event: Mapping[str, Any]) -> str:
    return sha256_hex(previous.encode("ascii") + b"\n" + canonical(event))


def final_digest(last: str, artifacts: Sequence[Mapping[str, Any]]) -> str:
    return sha256_hex(last.encode("ascii") + b"\n" + canonical(list(artifacts)))


def build_receipt(
    record: Mapping[str, Any],
    events: Sequence[Mapping[str, Any]],
    artifacts: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """`record` identifies the scan; `artifacts` are {"seq", "sha256"} of stored screenshots."""
    chain = []
    current = genesis(record)
    start = current
    for event in events:
        current = link(current, event)
        chain.append(current)
    ordered = sorted(artifacts, key=lambda item: item["seq"])
    return {
        "version": VERSION,
        "hash": "sha256",
        "canonicalization": "JSON with sorted keys, separators ',' and ':', ASCII escapes, no NaN",
        "trust_model": TRUST_MODEL,
        "record": dict(record),
        "genesis": start,
        "events": list(events),
        "chain": chain,
        "artifacts": ordered,
        "final_digest": final_digest(current, ordered),
    }


def verify_receipt(receipt: Mapping[str, Any]) -> list[str]:
    """Problems found, empty when the receipt is internally consistent."""
    problems: list[str] = []
    if receipt.get("version") != VERSION or receipt.get("hash") != "sha256":
        return ["unknown receipt version or hash"]
    events, chain = receipt.get("events"), receipt.get("chain")
    if not isinstance(events, list) or not isinstance(chain, list) or len(events) != len(chain):
        return ["events and chain do not line up"]
    current = genesis(receipt.get("record", {}))
    if current != receipt.get("genesis"):
        problems.append("the scan record does not match the genesis hash")
    previous_seq = 0
    for index, event in enumerate(events):
        current = link(current, event)
        if current != chain[index]:
            problems.append(f"chain breaks at event {index} (seq {event.get('seq') if isinstance(event, Mapping) else '?'})")
            break
        seq = event.get("seq") if isinstance(event, Mapping) else None
        if not isinstance(seq, int) or seq <= previous_seq:
            problems.append(f"event {index} is out of order (seq {seq})")
            break
        previous_seq = seq
    artifacts = receipt.get("artifacts", [])
    if not problems and final_digest(current, artifacts) != receipt.get("final_digest"):
        problems.append("the final digest does not match the events and artifacts")
    return problems
