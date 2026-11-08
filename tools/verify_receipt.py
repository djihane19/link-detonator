#!/usr/bin/env python3
"""Checks a Link Detonator evidence receipt offline. Standard library only.

    python3 tools/verify_receipt.py receipt.json [--digest HEX] [--screenshots DIR]

What a pass means: the receipt is internally consistent (every event, their order and the
scan record match the hash chain and final digest) and, with --digest, matches a digest you
saved earlier somewhere the server does not control, such as a ticket written when the scan
finished. The report page is not such a place: the same server computes what it shows. With --screenshots, each listed
screenshot file (<seq>.jpg) must match its recorded SHA-256.

What it does not mean: the chain is not a signature. Anyone can recompute a full chain over
altered events, so a receipt that passes on its own proves consistency, not origin.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

VERSION = "link-detonator-receipt-v1"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def check(receipt, digest=None, screenshots=None):
    problems = []
    if not isinstance(receipt, dict) or receipt.get("version") != VERSION or receipt.get("hash") != "sha256":
        return ["unknown receipt version or hash"]
    events, chain = receipt.get("events"), receipt.get("chain")
    if not isinstance(events, list) or not isinstance(chain, list) or len(events) != len(chain):
        return ["events and chain do not line up"]
    current = sha256_hex(VERSION.encode("ascii") + b"\n" + canonical(receipt.get("record", {})))
    if current != receipt.get("genesis"):
        problems.append("the scan record does not match the genesis hash")
    previous_seq = 0
    for index, event in enumerate(events):
        current = sha256_hex(current.encode("ascii") + b"\n" + canonical(event))
        if current != chain[index]:
            problems.append(f"chain breaks at event {index}")
            break
        seq = event.get("seq") if isinstance(event, dict) else None
        if not isinstance(seq, int) or seq <= previous_seq:
            problems.append(f"event {index} is out of order (seq {seq})")
            break
        previous_seq = seq
    artifacts = receipt.get("artifacts", [])
    final = sha256_hex(current.encode("ascii") + b"\n" + canonical(artifacts))
    if not problems and final != receipt.get("final_digest"):
        problems.append("the final digest does not match the events and artifacts")
    if digest is not None and receipt.get("final_digest") != digest.strip().lower():
        problems.append("the final digest differs from the one you supplied")
    if screenshots is not None:
        for item in artifacts:
            path = Path(screenshots) / f"{int(item['seq'])}.jpg"
            try:
                actual = sha256_hex(path.read_bytes())
            except OSError:
                problems.append(f"screenshot {path.name} is missing")
                continue
            if actual != item.get("sha256"):
                problems.append(f"screenshot {path.name} does not match its recorded hash")
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("receipt", type=Path)
    parser.add_argument("--digest", help="a final digest you saved earlier, outside the server that produced the receipt")
    parser.add_argument("--screenshots", type=Path, help="folder holding <seq>.jpg screenshot files")
    args = parser.parse_args(argv)
    try:
        receipt = json.loads(args.receipt.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"FAIL: cannot read receipt: {exc}")
        return 1
    problems = check(receipt, args.digest, args.screenshots)
    if problems:
        for problem in problems:
            print(f"FAIL: {problem}")
        return 1
    events = receipt.get("events", [])
    print(f"OK: {len(events)} events and {len(receipt.get('artifacts', []))} screenshot hashes are consistent")
    print(f"final digest {receipt['final_digest']}")
    if args.digest is None:
        print("Note: compare this digest with a copy saved earlier outside the server. The chain is not a signature.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
