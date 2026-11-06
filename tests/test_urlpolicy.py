"""Submitted-URL policy. DNS is injected; a real lookup makes these tests fail."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Awaitable, Callable

import pytest

from app.urlpolicy import (
    UrlPolicyError,
    _embedded_ipv4,
    check_url_syntax,
    destination_is_non_public,
    is_public_ip,
    validate_url,
)


@pytest.fixture(autouse=True)
def forbid_real_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("a test attempted a real DNS lookup")

    monkeypatch.setattr(socket, "getaddrinfo", refuse)


def resolves_to(*answers: str) -> Callable[[str], Awaitable[list[str]]]:
    async def resolver(_host: str) -> list[str]:
        return list(answers)

    return resolver


PUBLIC_ANSWER = resolves_to("93.184.216.34")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("http://example.com", "http://example.com/"),
        ("https://example.com/a/b?q=1#frag", "https://example.com/a/b?q=1#frag"),
        ("HTTPS://EXAMPLE.COM/Path", "https://example.com/Path"),
        ("http://example.com:80/", "http://example.com:80/"),
        ("https://example.com:443/x", "https://example.com:443/x"),
        ("https://example.com.", "https://example.com/"),
        ("https://sub_domain.example.com/", "https://sub_domain.example.com/"),
        ("https://bücher.example/", None),
        ("https://bücher.com/", "https://xn--bcher-kva.com/"),
        ("https://example.com/path?next=http://127.0.0.1/", "https://example.com/path?next=http://127.0.0.1/"),
    ],
)
async def test_accepts_public_urls(raw: str, expected: str | None) -> None:
    if expected is None:
        with pytest.raises(UrlPolicyError):
            await validate_url(raw, PUBLIC_ANSWER)
    else:
        assert await validate_url(raw, PUBLIC_ANSWER) == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("http://1.1.1.1/", "http://1.1.1.1/"),
        ("http://16843009/", "http://1.1.1.1/"),
        ("http://0x01010101/", "http://1.1.1.1/"),
        ("http://01.01.01.01/", "http://1.1.1.1/"),
        ("http://[2606:4700:4700::1111]/", "http://[2606:4700:4700::1111]/"),
    ],
)
async def test_public_ip_literals_are_normalized_and_skip_dns(raw: str, expected: str) -> None:
    async def resolver_must_not_run(_host: str) -> list[str]:
        raise AssertionError("IP literals need no lookup")

    assert await validate_url(raw, resolver_must_not_run) == expected


def test_public_ipv4_mapped_address_is_accepted() -> None:
    # Spelled differently across Python versions, so only the meaning is asserted.
    checked = check_url_syntax("http://[::ffff:1.1.1.1]/")
    assert checked.ip == ipaddress.ip_address("::ffff:101:101")


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        (None, "invalid_url"),
        (123, "invalid_url"),
        ("", "invalid_url"),
        ("http://example.com/" + "a" * 2048, "too_long"),
        ("ftp://example.com/", "bad_scheme"),
        ("file:///etc/passwd", "bad_scheme"),
        ("javascript:alert(1)", "bad_scheme"),
        ("data:text/html,x", "bad_scheme"),
        ("example.com", "bad_scheme"),
        ("//example.com/", "bad_scheme"),
        ("http://example.com:8080/", "bad_port"),
        ("http://example.com:22/", "bad_port"),
        ("http://example.com:0/", "bad_port"),
        ("http://example.com:notaport/", "bad_port"),
        ("http://example.com:99999/", "bad_port"),
        ("http://user@example.com/", "userinfo"),
        ("http://user:pw@example.com/", "userinfo"),
        ("http://@example.com/", "userinfo"),
        ("http://example.com@127.0.0.1/", "userinfo"),
        ("http:///path", "invalid_host"),
        ("http:example.com", "invalid_host"),
        ("http://", "invalid_host"),
        ("http://exa mple.com/", "invalid_url"),
        ("http://example.com/\tx", "invalid_url"),
        ("http://example.com/\nx", "invalid_url"),
        ("http://example.com\\@127.0.0.1/", "invalid_url"),
        ("http://example.com/ x", "invalid_url"),
        ("http://exa_mple!.com/", "invalid_host"),
        ("http://a..b.com/", "invalid_host"),
        ("http://-bad.example.com/", "invalid_host"),
        ("http://" + "a" * 64 + ".com/", "invalid_host"),
        ("http://%31%32%37.0.0.1/", "invalid_host"),
        ("http://[fe80::1%25en0]/", "invalid_host"),
        ("http://1.2.3.4.5/", "invalid_host"),
        ("http://foo.123/", "invalid_host"),
        ("http://256.1.1.1/", "invalid_host"),
        ("http://1.1.1.256/", "invalid_host"),
        ("http://4294967296/", "invalid_host"),
        ("http://1.0xg.1/", "invalid_host"),
        ("http://08.1.1.1/", "invalid_host"),
    ],
)
def test_rejected_by_syntax(raw: object, code: str) -> None:
    with pytest.raises(UrlPolicyError) as caught:
        check_url_syntax(raw)
    assert caught.value.code == code


@pytest.mark.parametrize(
    "host",
    [
        # IPv4: every range the firewall drops.
        "127.0.0.1", "127.1.2.3", "10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1",
        "169.254.169.254", "100.64.0.1", "0.0.0.0", "0.1.2.3", "224.0.0.1", "239.1.1.1",
        "240.0.0.1", "255.255.255.255",
        # Other special-use IPv4.
        "192.0.0.1", "192.0.2.1", "198.18.0.1", "198.51.100.1", "203.0.113.1",
        # Integer, octal, hex, short and mixed forms.
        "2130706433", "0x7f000001", "017700000001", "0x7f.0.0.1", "0177.0.0.1", "127.1",
        "0x7f.1", "127.0.1", "0", "0x0", "0xa9fea9fe", "2852039166", "0251.0376.0251.0376",
        "169.254.43518", "3232235777", "012.0.0.1",
        # Trailing dot, case and fullwidth forms that browsers normalize.
        "127.0.0.1.", "0X7F.1", "１２７.０.０.１", "127。0。0。1",
        # IPv6.
        "[::1]", "[::]", "[fe80::1]", "[fc00::1]", "[fd12:3456::1]", "[fec0::1]", "[ff02::1]",
        "[2001:db8::1]", "[100::1]",
        # IPv4 inside IPv6.
        "[::ffff:127.0.0.1]", "[::ffff:7f00:1]", "[::ffff:10.0.0.1]", "[::ffff:169.254.169.254]",
        "[::127.0.0.1]", "[2002:7f00:1::]", "[2002:a00:1::]", "[64:ff9b::7f00:1]", "[64:ff9b::a00:1]",
        "[2001:0:4136:e378:8000:63bf:3fff:fdd2]",
    ],
)  # fmt: skip
def test_non_public_addresses_rejected(host: str) -> None:
    with pytest.raises(UrlPolicyError) as caught:
        check_url_syntax(f"http://{host}/")
    assert caught.value.code == "non_public_host"


@pytest.mark.parametrize(
    "host",
    [
        "localhost", "LOCALHOST", "localhost.", "intranet", "metadata", "db_1",
    ],
)  # fmt: skip
def test_single_label_rejected(host: str) -> None:
    with pytest.raises(UrlPolicyError) as caught:
        check_url_syntax(f"http://{host}/")
    assert caught.value.code == "single_label"


@pytest.mark.parametrize(
    "host",
    [
        "foo.localhost", "a.b.localhost", "printer.local", "metadata.google.internal",
        "corp.lan", "nas.home", "git.corp", "router.home.arpa", "fixtures.invalid",
        "x.invalid", "site.test", "site.example", "hidden.onion", "1.0.0.127.in-addr.arpa",
        "foo.localhost.",
    ],
)  # fmt: skip
def test_special_use_names_rejected_without_dns(host: str) -> None:
    with pytest.raises(UrlPolicyError) as caught:
        check_url_syntax(f"https://{host}/")
    assert caught.value.code == "non_public_host"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "answers",
    [
        ("127.0.0.1",),
        ("10.0.0.5",),
        ("169.254.169.254",),
        ("100.64.0.1",),
        ("::1",),
        ("fe80::1%en0",),
        ("::ffff:192.168.0.1",),
        # One bad answer among good ones is enough: this is the rebinding shape.
        ("93.184.216.34", "10.0.0.5"),
        ("2606:4700:4700::1111", "fd00::1"),
    ],
)
async def test_any_non_public_dns_answer_rejects(answers: tuple[str, ...]) -> None:
    with pytest.raises(UrlPolicyError) as caught:
        await validate_url("https://rebind.example.com/", resolves_to(*answers))
    assert caught.value.code == "non_public_dns"


@pytest.mark.asyncio
async def test_all_public_answers_accepted() -> None:
    resolver = resolves_to("93.184.216.34", "2606:4700:4700::1111")
    assert await validate_url("https://example.com/", resolver) == "https://example.com/"


@pytest.mark.asyncio
async def test_resolver_receives_normalized_host() -> None:
    seen: list[str] = []

    async def resolver(host: str) -> list[str]:
        seen.append(host)
        return ["93.184.216.34"]

    await validate_url("https://EXAMPLE.com./", resolver)
    assert seen == ["example.com"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error", [socket.gaierror("no such host"), TimeoutError(), OSError("network down")]
)
async def test_resolver_failure_rejects(error: Exception) -> None:
    async def resolver(_host: str) -> list[str]:
        raise error

    with pytest.raises(UrlPolicyError) as caught:
        await validate_url("https://example.com/", resolver)
    assert caught.value.code == "dns_failed"


@pytest.mark.asyncio
@pytest.mark.parametrize("answers", [(), ("not-an-ip",)])
async def test_empty_or_garbage_answers_reject(answers: tuple[str, ...]) -> None:
    with pytest.raises(UrlPolicyError) as caught:
        await validate_url("https://example.com/", resolves_to(*answers))
    assert caught.value.code == "dns_failed"


def test_length_boundary() -> None:
    prefix = "http://example.com/"
    at_limit = prefix + "a" * (2048 - len(prefix))
    assert check_url_syntax(at_limit).url == at_limit
    with pytest.raises(UrlPolicyError):
        check_url_syntax(at_limit + "a")


@pytest.mark.parametrize(
    ("address", "ipv4"),
    [
        ("::ffff:127.0.0.1", "127.0.0.1"),
        ("2002:7f00:1::", "127.0.0.1"),
        ("64:ff9b::a00:1", "10.0.0.1"),
    ],
)
def test_embedded_ipv4_is_extracted_on_every_python(address: str, ipv4: str) -> None:
    # Newer ipaddress versions handle mapped addresses themselves, so is_public_ip alone
    # would not show whether this code still works on the VM's older Python.
    assert _embedded_ipv4(ipaddress.ip_address(address)) == ipaddress.ip_address(ipv4)


def test_length_is_checked_again_after_idna_expansion() -> None:
    prefix = "http://bücher.com/"
    raw = prefix + "a" * (2048 - len(prefix))
    assert len(raw) == 2048
    with pytest.raises(UrlPolicyError) as caught:
        check_url_syntax(raw)
    assert caught.value.code == "too_long"


def test_every_accepted_url_is_a_valid_scan_target() -> None:
    from app.models import ScanTarget

    prefix = "http://example.com/"
    checked = check_url_syntax(prefix + "é" * (2048 - len(prefix)))
    assert ScanTarget(kind="url", value=checked.url).value == checked.url


@pytest.mark.parametrize(
    ("address", "public"),
    [
        ("1.1.1.1", True),
        ("2606:4700:4700::1111", True),
        ("::ffff:1.1.1.1", True),
        ("2002:101:101::", True),
        ("224.0.0.1", False),
        ("fec0::1", False),
        ("64:ff9b::a00:1", False),
    ],
)
def test_is_public_ip(address: str, public: bool) -> None:
    assert is_public_ip(ipaddress.ip_address(address)) is public


@pytest.mark.parametrize(
    ("url", "non_public"),
    [
        ("http://169.254.169.254/latest/meta-data/", True),
        ("http://10.0.0.1:8080/admin", True),
        ("http://127.0.0.1:3000/", True),
        ("http://[::1]/", True),
        ("http://localhost/", True),
        ("http://foo.localhost:9000/", True),
        ("http://metadata.google.internal/", True),
        ("http://user:pw@192.168.1.1/", True),
        ("http://metadata/", True),
        ("http://1.1.1.1/", False),
        ("https://example.com/", False),
        # The fixture origin is neither a private destination nor a real host.
        ("http://fixtures.invalid/benign", False),
        ("about:blank", False),
        ("data:text/plain,hi", False),
        ("not a url", False),
        ("http://[broken", False),
        (None, False),
        (12, False),
    ],
)
def test_destination_is_non_public(url: object, non_public: bool) -> None:
    assert destination_is_non_public(url) is non_public
