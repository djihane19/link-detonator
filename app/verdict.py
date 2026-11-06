"""The verdict seam.

Only the interface exists here. An engine that reaches a conclusion is written
after the hackathon kickoff; until then the scan always reports "pending". Never
fabricate or hard-code a verdict.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class VerdictEngine(Protocol):
    """Runs once for every finished scan, and scans can be started by anyone.

    An engine that costs money must enforce its own hard global spend budget before each
    call: nothing else here bounds what it spends.
    """

    async def evaluate(
        self, scan_id: str, events: Sequence[Mapping[str, Any]]
    ) -> dict[str, Any]:
        """Returns the data of the `verdict` event for a finished scan."""
        ...


class PendingVerdictEngine:
    """Reaches no conclusion: the status is always "pending"."""

    async def evaluate(
        self, scan_id: str, events: Sequence[Mapping[str, Any]]
    ) -> dict[str, Any]:
        return {"status": "pending"}
