"""The investigation loop: analyse, gate proposals, detonate approved links in fresh
sandboxes, analyse again, then verify. The final class can only be raised by the
deterministic checks, never lowered by the model's reading of hostile text."""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from app.agent import evidence, policy, signals
from app.agent.llm import Analysis, CallBudget, ChatClient, ModelError, VultrChatClient
from app.agent.settings import API_KEY_ENV, AgentSettings
from app.agent.verify import verify
from app.sandbox import SandboxRunner
from app.verdict import PendingVerdictEngine, VerdictEngine

logger = logging.getLogger(__name__)

RANK = {"inconclusive": 0, "benign": 1, "suspicious": 2, "malicious": 3}
LIMITATIONS = (
    "Model output is an opinion, not a verified fact. Prompt injection cannot be fully prevented "
    "in a model; prohibited actions are stopped by the rule engine, sandbox and firewall instead."
)


class AgentEngine:
    def __init__(self, client: ChatClient, runner: SandboxRunner, data_dir: Path, settings: AgentSettings | None = None) -> None:
        self._client, self._runner, self._data_dir = client, runner, data_dir
        self._settings = settings or AgentSettings()

    async def evaluate(self, scan_id: str, events: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        found = signals.collect_signals(events)
        canary = evidence.new_canary()
        raw_outputs: list[str] = []
        calls = 0

        async def ask(include_concealed: bool, extra: Mapping[str, Any] | None = None) -> Analysis:
            nonlocal calls
            if calls >= self._settings.calls_per_scan:
                raise ModelError("This scan used all its model calls.")
            calls += 1
            view = evidence.build_view(events, include_concealed=include_concealed)
            shot = evidence.latest_screenshot(events, self._data_dir / "scans" / scan_id)
            analysis, raw = await self._client.analyse(evidence.build_messages(view, canary=canary, screenshot=shot, extra=extra))
            raw_outputs.append(raw)
            return analysis

        try:
            full = await ask(True)
            has_concealed = any(e.get("type") == "text_layers" and e.get("data", {}).get("concealed") for e in events)
            surface = await ask(False) if has_concealed else full
            first = full
            decisions, followups, full = await self._follow_links(scan_id, events, first, ask)
        except ModelError as exc:
            # Evidence stays valid without a model, and no verdict is invented.
            return {"status": "unavailable", "reason": str(exc), "signals": found, "verification": verify(events, [], [], canary_leaked=False, verdict_flipped=False)}

        leaked = any(canary in raw for raw in raw_outputs)
        # Compared on the same evidence: a later answer also saw the follow-ups.
        flipped = RANK[first.classification] < RANK[surface.classification]
        final = max((first.classification, surface.classification, full.classification), key=RANK.__getitem__)
        reasons = []
        if leaked:
            reasons.append("The model output leaked a planted secret.")
        if flipped:
            reasons.append("Hidden text made the model judge the page safer.")
        if signals.has_concealed_attack(found):
            reasons.append("Hidden text matched a known attack pattern.")
        raised = bool(reasons) and RANK[final] < RANK["suspicious"]
        if raised:
            final = "suspicious"

        known = {e.get("seq") for e in events}
        decisions = [{**d, "target": str(d["target"]).replace(canary, "[redacted]")} for d in decisions]
        return {
            "status": "complete",
            "classification": final,
            "model_classification": full.classification,
            "raised_by_rules": raised,
            "model_confidence": full.confidence,
            "summary": full.summary.replace(canary, "[redacted]"),
            "indicators": [
                {"claim": i.claim.replace(canary, "[redacted]"), "evidence_seqs": [s for s in i.evidence_seqs if s in known]}
                for i in full.indicators
            ],
            "injection_reported_by_model": full.injection_detected,
            "signals": found,
            "manipulation": {"canary_leaked": leaked, "verdict_flipped": flipped, "reasons": reasons},
            "policy_decisions": decisions,
            "followups": followups,
            "verification": verify(events, decisions, followups, canary_leaked=leaked, verdict_flipped=flipped),
            "model": {"id": self._client.model, "calls": calls},
            "limitations": LIMITATIONS,
        }

    async def _follow_links(self, scan_id: str, events: Sequence[Mapping[str, Any]], analysis: Analysis, ask: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]], Analysis]:
        decisions: list[dict[str, Any]] = []
        followups: list[dict[str, Any]] = []
        started = next((e.get("data", {}) for e in events if e.get("type") == "worker_started"), {})
        mode = str(started.get("mode", "live"))
        observed = evidence.observed_urls(events)
        visited = {str(started.get("url", ""))}
        while True:
            approved = []
            for action in analysis.proposed_actions:
                decision, target = await policy.decide(
                    action.kind, action.target, mode=mode, observed_urls=observed, visited=visited,
                    followups_left=self._settings.max_followups - len(followups) - len(approved),
                )
                decisions.append(decision.as_dict())
                if target is not None:
                    visited.add(action.target)
                    approved.append((action.target, target))
            if not approved:
                return decisions, followups, analysis
            for url, target in approved:
                followups.append(await self._detonate(f"{scan_id}-f{len(followups) + 1}", url, target))
            analysis = await ask(True, {"opened": followups})

    async def _detonate(self, name: str, url: str, target: Any) -> dict[str, Any]:
        """Runs one approved link in its own sandbox. Everything it emits stays hostile."""
        collected: list[dict[str, Any]] = []

        async def emit(kind: str, data: dict[str, Any], source: str = "worker") -> None:
            if kind == "screenshot":
                return  # not needed for the summary, and it keeps the verdict event small
            collected.append({"type": kind, "data": data, "source": source, "seq": len(collected)})

        try:
            await self._runner.run(name, target, emit)
        except Exception:
            logger.exception("follow-up sandbox failed")
        view = evidence.build_view(collected, include_concealed=True)
        removed = next((e["data"].get("verified") for e in collected if e["type"] == "sandbox_removed" and e["source"] == "host"), False)
        return {"target": url, "removed_verified": bool(removed), "signals": signals.collect_signals(collected), "evidence": {k: view[k] for k in ("navigations", "forms", "downloads", "concealed_text")}}


def build_engine(runner: SandboxRunner, data_dir: Path, env: Mapping[str, str] | None = None) -> VerdictEngine:
    """Without a key the verdict honestly stays pending, with no stand-in model."""
    source = os.environ if env is None else env
    if not source.get(API_KEY_ENV, "").strip():
        return PendingVerdictEngine()
    settings = AgentSettings.from_env(source)
    budget = CallBudget(data_dir / "llm_budget.json", settings.calls_per_day)
    return AgentEngine(VultrChatClient(settings, budget), runner, data_dir, settings)
