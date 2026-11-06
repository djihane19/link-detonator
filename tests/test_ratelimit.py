"""Per-client limits and client identification."""

from __future__ import annotations

from app.ratelimit import SlidingWindowLimiter, client_key


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def make_limiter(per_minute: int = 5, per_hour: int = 30, **kwargs: int) -> tuple[SlidingWindowLimiter, FakeClock]:
    clock = FakeClock()
    return SlidingWindowLimiter(per_minute, per_hour, clock=clock, **kwargs), clock


def test_allows_up_to_the_minute_limit_then_refuses_with_retry_after() -> None:
    limiter, clock = make_limiter()
    assert all(limiter.check("a").allowed for _ in range(5))
    clock.now += 10
    refused = limiter.check("a")
    assert not refused.allowed
    assert refused.retry_after_s == 50


def test_minute_window_slides() -> None:
    limiter, clock = make_limiter()
    for _ in range(5):
        limiter.check("a")
    clock.now += 60
    assert limiter.check("a").allowed


def test_refused_hits_are_not_recorded() -> None:
    limiter, clock = make_limiter()
    for _ in range(5):
        limiter.check("a")
    for _ in range(100):
        clock.now += 0.1
        assert not limiter.check("a").allowed
    clock.now = 1060.0
    assert limiter.check("a").allowed


def test_hour_limit_applies_across_minutes() -> None:
    limiter, clock = make_limiter(per_minute=5, per_hour=6)
    for _ in range(6):
        assert limiter.check("a").allowed
        clock.now += 61
    refused = limiter.check("a")
    assert not refused.allowed
    # The oldest hit was 366 s ago and leaves the hour window after 3600 s.
    assert refused.retry_after_s == 3600 - 366
    clock.now += refused.retry_after_s
    assert limiter.check("a").allowed


def test_clients_are_independent() -> None:
    limiter, _ = make_limiter(per_minute=1)
    assert limiter.check("a").allowed
    assert not limiter.check("a").allowed
    assert limiter.check("b").allowed


def test_tracked_clients_are_bounded() -> None:
    limiter, _ = make_limiter(max_clients=3)
    for index in range(50):
        limiter.check(f"client-{index}")
    assert limiter.tracked_clients() == 3


def test_forwarded_header_is_ignored_without_trust() -> None:
    assert client_key("198.51.100.7", {"x-forwarded-for": "203.0.113.9"}, False) == "198.51.100.7"


def test_trusted_proxy_uses_the_right_most_entry_so_clients_cannot_spoof() -> None:
    headers = {"x-forwarded-for": "1.1.1.1, 2.2.2.2, 203.0.113.9"}
    assert client_key("127.0.0.1", headers, True) == "203.0.113.9"


def test_trusted_proxy_falls_back_to_peer_on_a_bad_header() -> None:
    assert client_key("127.0.0.1", {"x-forwarded-for": "not-an-ip"}, True) == "127.0.0.1"
    assert client_key("127.0.0.1", {}, True) == "127.0.0.1"


def test_ipv6_clients_share_a_key_per_64() -> None:
    first = client_key("2001:db8:1:2::1", {}, False)
    second = client_key("2001:db8:1:2:ffff::9", {}, False)
    other = client_key("2001:db8:1:3::1", {}, False)
    assert first == second
    assert first != other


def test_ipv4_mapped_address_is_keyed_as_ipv4() -> None:
    assert client_key("::ffff:203.0.113.9", {}, False) == "203.0.113.9"


def test_missing_peer_has_a_stable_key() -> None:
    assert client_key(None, {}, False) == "unknown"
