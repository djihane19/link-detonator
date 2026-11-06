"""Validation of submitted URLs.

This check is UX and defence in depth. The firewall is the real boundary, because
DNS answers can change after this check and a page can redirect anywhere.

Hosts are parsed the way browsers parse them (WHATWG URL): `0x7f.1`, `2130706433`
and `１２７.０.０.１` all mean loopback. The normalized URL is what gets scanned, so the
browser receives exactly the host that was checked.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import threading
from collections.abc import Awaitable, Callable, Iterable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit

import idna

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[[str], Awaitable[Iterable[str]]]

MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES = frozenset({"http", "https"})
ALLOWED_PORTS = frozenset({80, 443})
DNS_TIMEOUT_S = 5.0
DNS_WORKERS = 4
# getaddrinfo cannot be cancelled, so an abandoned lookup holds its place until it returns.
DNS_MAX_IN_FLIGHT = 8

# Names that only ever mean something inside a network. Chromium also resolves
# *.localhost to loopback without consulting DNS, so a DNS check would miss it.
_LOCAL_SUFFIXES = (
    "localhost",
    "local",
    "internal",
    "intranet",
    "lan",
    "home",
    "corp",
    "private",
    "home.arpa",
)
# Reserved names that never resolve publicly. `fixtures.invalid` is the fixture
# origin and must only ever be reachable through a fixture scan.
_RESERVED_SUFFIXES = ("invalid", "test", "example", "onion", "alt", "arpa")

_LABEL = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
_MAX_HOST_LENGTH = 253
_NAT64_PREFIX = ipaddress.ip_network("64:ff9b::/96")
# Browsers strip tabs and newlines and treat `\` as `/`. Rejecting them removes any
# difference between how this module and the browser read the same string.
_FORBIDDEN_URL_CHARS = re.compile(r"[\x00-\x20\x7f\\\s]")


class ResolverBusy(Exception):
    """Too many lookups are in flight. The URL was not judged, so this is not a refusal."""


class UrlPolicyError(ValueError):
    """The URL is refused. `code` is stable for clients; str(exc) is for people."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class CheckedUrl:
    """A URL that passed every check that does not need DNS."""

    url: str
    host: str
    ip: IPAddress | None


async def validate_url(raw: object, resolver: Resolver | None = None) -> str:
    """Returns the normalized URL, or raises UrlPolicyError. Performs a DNS lookup."""
    checked = check_url_syntax(raw)
    if checked.ip is not None:
        return checked.url
    await _check_dns(checked.host, resolver or system_resolver)
    return checked.url


def check_url_syntax(raw: object) -> CheckedUrl:
    """Runs every check that does not need the network."""
    if not isinstance(raw, str) or not raw:
        raise UrlPolicyError("invalid_url", "A URL is required.")
    if len(raw) > MAX_URL_LENGTH:
        raise UrlPolicyError("too_long", f"The URL is longer than {MAX_URL_LENGTH} characters.")
    # JSON can carry a lone surrogate, which could never be sent or stored as UTF-8.
    if not _is_encodable(raw):
        raise UrlPolicyError("invalid_url", "The URL contains an invalid character.")
    if _FORBIDDEN_URL_CHARS.search(raw):
        raise UrlPolicyError("invalid_url", "The URL contains whitespace, control or backslash.")

    parts = _split(raw)
    if parts.scheme not in ALLOWED_SCHEMES:
        raise UrlPolicyError("bad_scheme", "Only http and https URLs are accepted.")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise UrlPolicyError("userinfo", "URLs with embedded credentials are not accepted.")
    port = _port(parts)
    host, ip = _parse_host(parts.hostname)
    if ip is not None and not is_public_ip(ip):
        raise UrlPolicyError("non_public_host", "That address is not on the public internet.")
    if ip is None:
        _check_name_is_public(host)
    url = _rebuild(parts, host, port)
    # IDNA encoding can lengthen a URL that was within the limit as submitted.
    if len(url) > MAX_URL_LENGTH:
        raise UrlPolicyError("too_long", f"The URL is longer than {MAX_URL_LENGTH} characters.")
    return CheckedUrl(url=url, host=host, ip=ip)


def _is_encodable(text: str) -> bool:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def is_public_ip(ip: IPAddress) -> bool:
    """True only for globally routable unicast addresses.

    `is_global` alone is not enough: it is True for IPv4 multicast (224.0.0.1) and
    for site-local IPv6, and for transition ranges that embed a private IPv4.
    """
    embedded = _embedded_ipv4(ip)
    if embedded is not None:
        return is_public_ip(embedded)
    if ip.is_multicast or ip.is_unspecified or ip.is_loopback or ip.is_link_local:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.is_site_local:
        return False
    return ip.is_global and not ip.is_private and not ip.is_reserved


def destination_is_non_public(url: object) -> bool:
    """Classifies a URL seen in events without any DNS lookup.

    True for non-public IP literals in any notation, and for local-only names. A
    public-looking name returns False: where it resolved to is not known here.
    Reserved never-resolving names such as `fixtures.invalid` also return False.
    """
    if not isinstance(url, str):
        return False
    try:
        hostname = urlsplit(url).hostname
        host, ip = _parse_host(hostname)
    except (ValueError, UrlPolicyError):
        return False
    if ip is not None:
        return not is_public_ip(ip)
    return "." not in host or _has_suffix(host, _LOCAL_SUFFIXES)


def destination_stays_in_sandbox(url: object) -> bool:
    """True when traffic to this URL never leaves the machine that makes the request.

    Loopback is local to the container, so no host firewall rule sees it. Chromium also
    resolves *.localhost and connects 0.0.0.0 to itself without touching the network.
    """
    if not isinstance(url, str):
        return False
    try:
        host, ip = _parse_host(urlsplit(url).hostname)
    except (ValueError, UrlPolicyError):
        return False
    if ip is not None:
        return address_stays_in_sandbox(ip)
    return _has_suffix(host, ("localhost",))


def address_stays_in_sandbox(ip: IPAddress) -> bool:
    embedded = _embedded_ipv4(ip)
    return address_stays_in_sandbox(embedded) if embedded is not None else ip.is_loopback or ip.is_unspecified


class _BoundedResolver:
    """Runs getaddrinfo on its own small pool, so slow lookups cannot stall the app.

    The shared executor also serves disk reads. A lookup whose caller gave up keeps its
    thread until the OS returns, and a nameserver that never answers can arrange that.
    """

    def __init__(self, workers: int = DNS_WORKERS, max_in_flight: int = DNS_MAX_IN_FLIGHT) -> None:
        self._executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="ld-dns")
        self._max_in_flight = max_in_flight
        self._in_flight = 0
        self._lock = threading.Lock()

    def _release(self, _: Future[object]) -> None:
        with self._lock:
            self._in_flight -= 1

    async def __call__(self, host: str) -> list[str]:
        with self._lock:
            if self._in_flight >= self._max_in_flight:
                raise ResolverBusy
            self._in_flight += 1
        future = self._executor.submit(socket.getaddrinfo, host, None, type=socket.SOCK_STREAM)
        future.add_done_callback(self._release)
        async with asyncio.timeout(DNS_TIMEOUT_S):
            answers = await asyncio.wrap_future(future)
        return [str(answer[4][0]) for answer in answers]


system_resolver = _BoundedResolver()


async def _check_dns(host: str, resolver: Resolver) -> None:
    try:
        answers = list(await resolver(host))
    except (OSError, TimeoutError, ValueError) as exc:
        raise UrlPolicyError("dns_failed", "The host name could not be resolved.") from exc
    if not answers:
        raise UrlPolicyError("dns_failed", "The host name could not be resolved.")
    for answer in answers:
        try:
            address = ipaddress.ip_address(answer)
        except ValueError as exc:
            raise UrlPolicyError("dns_failed", "The host name could not be resolved.") from exc
        if not is_public_ip(address):
            raise UrlPolicyError(
                "non_public_dns", "The host name resolves to an address that is not public."
            )


def _split(raw: str) -> SplitResult:
    try:
        return urlsplit(raw)
    except ValueError as exc:
        raise UrlPolicyError("invalid_url", "The URL could not be parsed.") from exc


def _port(parts: SplitResult) -> int | None:
    try:
        port = parts.port
    except ValueError as exc:
        raise UrlPolicyError("bad_port", "The URL has an invalid port.") from exc
    if port is not None and port not in ALLOWED_PORTS:
        raise UrlPolicyError("bad_port", "Only ports 80 and 443 are accepted.")
    return port


def _parse_host(hostname: str | None) -> tuple[str, IPAddress | None]:
    """Returns (normalized host, IP if the host is an IP literal in any notation)."""
    if not hostname:
        raise UrlPolicyError("invalid_host", "The URL has no host.")
    # Browsers percent-decode hosts, so `%31%32%37.0.0.1` would be loopback.
    if "%" in hostname:
        raise UrlPolicyError("invalid_host", "Percent-encoded hosts are not accepted.")
    if ":" in hostname:
        return _parse_ipv6(hostname)

    ascii_host = _to_ascii(hostname).lower()
    host = ascii_host[:-1] if ascii_host.endswith(".") else ascii_host
    if not host:
        raise UrlPolicyError("invalid_host", "The URL has no host.")

    ipv4 = _parse_browser_ipv4(host)
    if ipv4 is not None:
        return str(ipv4), ipv4

    if len(host) > _MAX_HOST_LENGTH or not all(_LABEL.match(part) for part in host.split(".")):
        raise UrlPolicyError("invalid_host", "The host name is not valid.")
    return host, None


def _parse_ipv6(hostname: str) -> tuple[str, IPAddress]:
    try:
        ip = ipaddress.IPv6Address(hostname)
    except ValueError as exc:
        raise UrlPolicyError("invalid_host", "The IPv6 address is not valid.") from exc
    return f"[{ip.compressed}]", ip


def _to_ascii(hostname: str) -> str:
    if hostname.isascii():
        return hostname
    try:
        # UTS46 non-transitional, as browsers do: `faß.de` must stay a different domain from
        # `fass.de`, or the scan would open a site other than the one in the link. The
        # mapping is also what turns fullwidth digits and dots into their ASCII forms.
        return idna.encode(hostname, uts46=True, transitional=False).decode("ascii")
    except UnicodeError as exc:
        raise UrlPolicyError("invalid_host", "The host name is not valid.") from exc


def _parse_browser_ipv4(host: str) -> ipaddress.IPv4Address | None:
    """Applies the WHATWG IPv4 rules.

    A host whose last label is numeric *is* an IPv4 address to a browser, and is
    otherwise invalid. So `1.2.3.4.5` and `foo.123` are refused rather than being
    treated as DNS names.
    """
    labels = host.split(".")
    if _parse_ipv4_number(labels[-1]) is None:
        return None
    numbers = [_parse_ipv4_number(label) for label in labels]
    if len(labels) > 4 or any(number is None for number in numbers):
        raise UrlPolicyError("invalid_host", "The numeric host is not a valid IPv4 address.")

    parts = [number for number in numbers if number is not None]
    if any(part > 255 for part in parts[:-1]) or parts[-1] >= 256 ** (5 - len(parts)):
        raise UrlPolicyError("invalid_host", "The numeric host is not a valid IPv4 address.")

    value = parts[-1]
    for index, part in enumerate(parts[:-1]):
        value += part * 256 ** (3 - index)
    return ipaddress.IPv4Address(value)


def _parse_ipv4_number(label: str) -> int | None:
    """Parses one label as decimal, 0-prefixed octal or 0x-prefixed hex."""
    if not label:
        return None
    if label.startswith("0x"):
        digits = label[2:]
        if not digits:
            return 0
        return int(digits, 16) if re.fullmatch(r"[0-9a-f]+", digits) else None
    if not re.fullmatch(r"[0-9]+", label):
        return None
    if len(label) > 1 and label.startswith("0"):
        return int(label, 8) if re.fullmatch(r"[0-7]+", label) else None
    return int(label)


def _check_name_is_public(host: str) -> None:
    if "." not in host:
        raise UrlPolicyError("single_label", "Single-label host names are not accepted.")
    if _has_suffix(host, _LOCAL_SUFFIXES) or _has_suffix(host, _RESERVED_SUFFIXES):
        raise UrlPolicyError("non_public_host", "That host name is not on the public internet.")


def _has_suffix(host: str, suffixes: tuple[str, ...]) -> bool:
    return any(host == suffix or host.endswith(f".{suffix}") for suffix in suffixes)


def _embedded_ipv4(ip: IPAddress) -> ipaddress.IPv4Address | None:
    """The IPv4 address carried inside an IPv6 transition address, if any."""
    if not isinstance(ip, ipaddress.IPv6Address):
        return None
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip.sixtofour is not None:
        return ip.sixtofour
    if ip in _NAT64_PREFIX:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def _rebuild(parts: SplitResult, host: str, port: int | None) -> str:
    netloc = host if port is None else f"{host}:{port}"
    url = f"{parts.scheme}://{netloc}{parts.path or '/'}"
    if parts.query:
        url += f"?{parts.query}"
    if parts.fragment:
        url += f"#{parts.fragment}"
    return url
