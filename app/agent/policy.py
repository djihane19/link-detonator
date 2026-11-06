"""The deterministic action gate. Every model proposal passes through here, and the
model's reasoning is never an input: only the action kind, target and known facts."""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import asdict, dataclass
from urllib.parse import urlsplit

from app.models import FIXTURE_NAMES, ScanTarget
from app.urlpolicy import Resolver, UrlPolicyError, validate_url

FIXTURE_HOST = "fixtures.invalid"
ALLOWED_KINDS = frozenset({"open_link"})


@dataclass(frozen=True)
class Decision:
    kind: str
    target: str
    allowed: bool
    rule: str
    detail: str

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def fixture_name(url: str) -> str | None:
    parts = urlsplit(url)
    name = parts.path.strip("/")
    if parts.scheme == "http" and parts.hostname == FIXTURE_HOST and name in FIXTURE_NAMES:
        return name
    return None


async def decide(
    kind: str,
    target: str,
    *,
    mode: str,
    observed_urls: Collection[str],
    visited: Collection[str],
    followups_left: int,
    resolver: Resolver | None = None,
) -> tuple[Decision, ScanTarget | None]:
    def deny(rule: str, detail: str) -> tuple[Decision, None]:
        return Decision(kind, target, False, rule, detail), None

    if kind not in ALLOWED_KINDS:
        return deny("action_not_permitted", "Only opening a link in a new sandbox is permitted.")
    if followups_left <= 0:
        return deny("followup_budget", "This scan has used all its follow-ups.")
    if target in visited:
        return deny("already_visited", "This address was already investigated.")
    if target not in observed_urls:
        return deny("not_observed", "The address did not appear in the recorded evidence.")
    if mode == "fixture":
        name = fixture_name(target)
        if name is None:
            return deny("outside_test_scope", "A test scan may only open other built-in test pages.")
        return Decision(kind, target, True, "allowed_fixture", "Opens in a new sandbox."), ScanTarget(kind="fixture", value=name)
    try:
        checked = await validate_url(target, resolver)
    except UrlPolicyError as exc:
        return deny("url_policy", str(exc))
    return Decision(kind, target, True, "allowed_public_url", "Opens in a new sandbox."), ScanTarget(kind="url", value=checked)
