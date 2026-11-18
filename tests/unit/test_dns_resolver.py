import dns.asyncresolver
import dns.exception
import pytest

from reconmap.config import Settings
from reconmap.modules.dns import make_resolver


class FakeAnswer(list[str]):
    pass


class Record:
    def to_text(self) -> str:
        return "192.0.2.1"


async def test_resolver_retries_once_on_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    async def flaky(self: object, *args: object, **kwargs: object) -> list[Record]:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise dns.exception.Timeout
        return [Record()]

    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", flaky)
    assert await make_resolver(["192.0.2.53"])("example.com", "A") == ["192.0.2.1"]
    assert calls == 2


async def test_resolver_gives_up_after_second_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    async def dead(self: object, *args: object, **kwargs: object) -> list[Record]:
        raise dns.exception.Timeout

    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", dead)
    with pytest.raises(dns.exception.Timeout):
        await make_resolver(["192.0.2.53"])("example.com", "A")


def test_dns_servers_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RECONMAP_DNS_SERVERS", " 9.9.9.9, 1.1.1.1 ,")
    assert Settings().dns_servers == ("9.9.9.9", "1.1.1.1")
    monkeypatch.delenv("RECONMAP_DNS_SERVERS")
    assert Settings().dns_servers == ()
