"""Sliding-window limits, per client and for global budgets.

Limits are in memory on purpose: there is a single orchestrator process, and
losing the counters on restart is acceptable. Memory is bounded by evicting the
least recently seen client, so a flood of spoofed-looking clients cannot grow it.
"""

from __future__ import annotations

import ipaddress
import time
from collections import OrderedDict, deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass

MINUTE_S = 60.0
HOUR_S = 3600.0
DAY_S = 86_400.0
UNKNOWN_CLIENT = "unknown"
IPV6_CLIENT_PREFIX = 64


@dataclass(frozen=True)
class RateDecision:
    allowed: bool
    retry_after_s: int = 0


class SlidingWindowLimiter:
    """Allows `per_minute` and `per_hour` hits per client over rolling windows.

    `per_minute=0` turns the short window off. `long_window_s` changes what the long
    window measures, so a daily budget is `per_hour=N, long_window_s=DAY_S`.
    """

    def __init__(
        self,
        per_minute: int,
        per_hour: int,
        clock: Callable[[], float] = time.monotonic,
        max_clients: int = 10_000,
        long_window_s: float = HOUR_S,
    ) -> None:
        self._per_minute = per_minute
        self._per_hour = per_hour
        self._clock = clock
        self._max_clients = max_clients
        self._long_window_s = long_window_s
        self._hits: OrderedDict[str, deque[float]] = OrderedDict()

    def check(self, client: str) -> RateDecision:
        """Records a hit if the client is within limits; never records a refused hit."""
        now = self._clock()
        hits = self._hits_for(client, now)
        retry_after = self._retry_after(hits, now)
        if retry_after > 0:
            return RateDecision(allowed=False, retry_after_s=retry_after)
        hits.append(now)
        return RateDecision(allowed=True)

    def peek(self, client: str) -> RateDecision:
        """The decision `check` would make, without recording anything."""
        now = self._clock()
        retry_after = self._retry_after(self._hits_for(client, now), now)
        return RateDecision(allowed=retry_after <= 0, retry_after_s=retry_after)

    def tracked_clients(self) -> int:
        return len(self._hits)

    def _hits_for(self, client: str, now: float) -> deque[float]:
        hits = self._hits.get(client)
        if hits is None:
            hits = deque()
            self._hits[client] = hits
        self._hits.move_to_end(client)
        while hits and now - hits[0] >= self._long_window_s:
            hits.popleft()
        while len(self._hits) > self._max_clients:
            self._hits.popitem(last=False)
        return hits

    def _retry_after(self, hits: deque[float], now: float) -> int:
        wait = 0.0
        if len(hits) >= self._per_hour:
            wait = max(wait, hits[-self._per_hour] + self._long_window_s - now)
        if self._per_minute > 0 and len(hits) >= self._per_minute:
            wait = max(wait, hits[-self._per_minute] + MINUTE_S - now)
        return _ceil_seconds(wait)


def client_key(
    peer_host: str | None,
    headers: Mapping[str, str],
    trust_proxy: bool,
) -> str:
    """Returns the rate-limit key for a request.

    With a trusted proxy, only the right-most X-Forwarded-For entry is used. That
    entry is the one our proxy appended; anything to its left is client-supplied
    and spoofable.
    """
    if trust_proxy:
        forwarded = headers.get("x-forwarded-for", "")
        candidate = forwarded.rsplit(",", 1)[-1].strip()
        normalised = _normalise_ip(candidate)
        if normalised is not None:
            return normalised
    normalised = _normalise_ip(peer_host or "")
    if normalised is not None:
        return normalised
    return peer_host or UNKNOWN_CLIENT


def _normalise_ip(value: str) -> str | None:
    """Canonicalises an address. IPv6 clients are keyed by /64, the usual end-site size."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return str(address.ipv4_mapped)
        return str(ipaddress.ip_network((address, IPV6_CLIENT_PREFIX), strict=False))
    return str(address)


def _ceil_seconds(value: float) -> int:
    if value <= 0:
        return 0
    return int(value) + (0 if value == int(value) else 1)
