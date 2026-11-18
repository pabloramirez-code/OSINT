import dns.exception
import dns.resolver
import pytest

from reconmap.models import Entity, EntityType, RelationType
from reconmap.modules.base import Context, ModuleError
from reconmap.modules.dns import Dns, Resolve
from tests.conftest import load_fixture

ROOT = Entity(type=EntityType.DOMAIN, value="example.com")


def fixture_resolver() -> Resolve:
    records = load_fixture("dns_example.com.json")
    assert isinstance(records, dict)

    async def resolve(name: str, record_type: str) -> list[str]:
        answer = records[record_type]
        if isinstance(answer, dict):
            raise dns.resolver.NoAnswer
        return list(answer)

    return resolve


def failing_resolver(error: Exception) -> Resolve:
    async def resolve(name: str, record_type: str) -> list[str]:
        raise error

    return resolve


async def test_a_records_create_resolves_to(ctx: Context) -> None:
    result = await Dns(fixture_resolver()).run(ROOT, ctx)
    ips = {r.to_ref.value for r in result.relations if r.type is RelationType.RESOLVES_TO}
    assert ips == {
        "104.20.23.154",
        "172.66.147.243",
        "2606:4700:10::6814:179a",
        "2606:4700:10::ac42:93f3",
    }


async def test_records_are_kept_as_attributes(ctx: Context) -> None:
    result = await Dns(fixture_resolver()).run(ROOT, ctx)
    records = result.entities[0].attributes["dns"]
    assert isinstance(records, dict)
    assert '"v=spf1 -all"' in records["TXT"]
    assert records["CNAME"] == []


@pytest.mark.parametrize(
    "error", [dns.resolver.NXDOMAIN(), dns.exception.Timeout()], ids=["nxdomain", "timeout"]
)
async def test_resolution_failures_are_module_errors(ctx: Context, error: Exception) -> None:
    with pytest.raises(ModuleError):
        await Dns(failing_resolver(error)).run(ROOT, ctx)


async def test_second_run_uses_cache(ctx: Context) -> None:
    calls = 0
    resolve = fixture_resolver()

    async def counting(name: str, record_type: str) -> list[str]:
        nonlocal calls
        calls += 1
        return await resolve(name, record_type)

    module = Dns(counting)
    await module.run(ROOT, ctx)
    await module.run(ROOT, ctx)
    assert calls == 7
