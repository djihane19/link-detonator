"""Model configuration, kept apart from agent logic. The key is read at call time and
is never stored on this object, so logging it cannot leak the key."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

API_KEY_ENV = "VULTR_API_KEY"


@dataclass(frozen=True)
class AgentSettings:
    base_url: str = "https://api.vultrinference.com/v1"
    model: str = "glm-5.3-flash"
    request_timeout_s: float = 45.0
    # glm-5.3-flash is a reasoning model. Its reasoning tokens count against this cap, and
    # at its default effort it used all 1500 before answering (measured on the VM).
    max_output_tokens: int = 4000
    reasoning_effort: str = "low"
    max_followups: int = 2
    calls_per_day: int = 400
    calls_per_scan: int = 6

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> AgentSettings:
        source = os.environ if env is None else env
        base = cls()
        return cls(
            base_url=source.get("LD_LLM_BASE_URL", base.base_url).rstrip("/"),
            model=source.get("LD_LLM_MODEL", base.model),
            reasoning_effort=source.get("LD_LLM_REASONING_EFFORT", base.reasoning_effort),
            max_output_tokens=int(source.get("LD_LLM_MAX_TOKENS", base.max_output_tokens)),
            request_timeout_s=float(source.get("LD_LLM_TIMEOUT_S", base.request_timeout_s)),
            max_followups=int(source.get("LD_AGENT_MAX_FOLLOWUPS", base.max_followups)),
            calls_per_day=int(source.get("LD_LLM_CALLS_PER_DAY", base.calls_per_day)),
        )
