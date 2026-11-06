"""Deterministic detectors. They run without the model, so a manipulated model cannot
silence them. They detect text patterns only: a match is not proof of intent, and a
paraphrased attack can miss every pattern."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

PATTERNS: dict[str, re.Pattern[str]] = {
    "override_instructions": re.compile(r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|earlier|system|all)\b.{0,30}\b(instructions?|prompts?|rules?)\b", re.I | re.S),
    "reveal_prompt": re.compile(r"\b(reveal|print|repeat|show|output|disclose)\b.{0,40}\b(system prompt|your (instructions|prompt)|hidden prompt)\b", re.I | re.S),
    "steer_verdict": re.compile(r"\b(report|mark|classify|label|tell)\b.{0,50}\b(safe|benign|legitimate|verified|trusted)\b", re.I | re.S),
    "exfiltrate": re.compile(r"\b(send|post|upload|exfiltrate|forward)\b.{0,50}\b(credentials?|api keys?|tokens?|secrets?|cookies?|passwords?)\b", re.I | re.S),
    "local_or_internal": re.compile(r"(file:///|169\.254\.169\.254|\b(read|open|access)\b.{0,30}\b(local files?|/etc/passwd|internal (service|admin))\b)", re.I | re.S),
    "run_download": re.compile(r"\b(download|install)\b.{0,40}\b(execute|run)\b", re.I | re.S),
}


def match_patterns(text: str) -> list[str]:
    return [name for name, pattern in PATTERNS.items() if pattern.search(text)]


def collect_signals(events: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Each signal says which layer the text was in, because hidden and visible differ:
    an article can discuss these phrases in the open, and that alone proves nothing."""
    found: dict[tuple[str, str], dict[str, Any]] = {}

    def note(pattern: str, layer: str, seq: int) -> None:
        found.setdefault((pattern, layer), {"pattern": pattern, "layer": layer, "evidence_seqs": []})["evidence_seqs"].append(seq)

    for event in events:
        if event.get("type") != "text_layers":
            continue
        data, seq = event.get("data", {}), event.get("seq", -1)
        for pattern in match_patterns(str(data.get("visible_text", ""))):
            note(pattern, "visible", seq)
        for item in data.get("concealed", []):
            for pattern in match_patterns(str(item.get("text", ""))):
                note(pattern, "concealed", seq)
    return list(found.values())


def has_concealed_attack(signals: Iterable[Mapping[str, Any]]) -> bool:
    return any(signal["layer"] == "concealed" for signal in signals)
