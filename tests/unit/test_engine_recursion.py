from reconmap.engine import Engine
from reconmap.models import Entity, EntityType, RunStatus
from reconmap.store import Store
from tests.conftest import FakeModule

SUB = frozenset({EntityType.SUBDOMAIN})
IP = frozenset({EntityType.IP})


async def scan(store: Store, modules: list[FakeModule], depth: int = 1, **engine: object) -> str:
    runner = Engine(store, list(modules), **engine)  # type: ignore[arg-type]
    scan_id = runner.create_scan("example.com", depth=depth)
    await runner.run(scan_id)
    return scan_id


async def test_discovered_subdomain_is_rescanned(store: Store) -> None:
    dns = FakeModule("dns", accepts=SUB)
    await scan(store, [FakeModule("crtsh", found=("www",)), dns])
    assert dns.seen == ["www.example.com"]


async def test_respects_max_depth(store: Store) -> None:
    for depth, expected in [
        (1, ["www.example.com"]),
        (2, ["www.example.com", "deep.www.example.com"]),
    ]:
        dns = FakeModule("dns", accepts=SUB, found=("deep",))
        await scan(store, [FakeModule("crtsh", found=("www",)), dns], depth=depth)
        assert dns.seen == expected


async def test_same_entity_is_processed_once(store: Store) -> None:
    dns = FakeModule("dns", accepts=SUB)
    await scan(
        store,
        [FakeModule("crtsh", found=("www", "api")), FakeModule("certspotter", found=("www",)), dns],
    )
    assert sorted(dns.seen) == ["api.example.com", "www.example.com"]


async def test_ips_are_processed_at_host_depth(store: Store) -> None:
    address = Entity(type=EntityType.IP, value="192.0.2.10")
    internetdb = FakeModule("internetdb", accepts=IP)
    await scan(
        store,
        [
            FakeModule("crtsh", found=("www",)),
            FakeModule("dns", accepts=SUB, extra=(address,)),
            internetdb,
        ],
    )
    assert internetdb.seen == ["192.0.2.10"]


async def test_foreign_hostnames_are_not_requeued(store: Store) -> None:
    address = Entity(type=EntityType.IP, value="192.0.2.10")
    foreign = Entity(type=EntityType.SUBDOMAIN, value="api.example.com.evil.net")
    dns = FakeModule("dns", accepts=SUB)
    await scan(
        store,
        [
            FakeModule("rootdns", extra=(address,)),
            FakeModule("internetdb", accepts=IP, extra=(foreign,)),
            dns,
        ],
        depth=3,
    )
    assert dns.seen == []


async def test_host_limit_is_enforced_and_reported(store: Store) -> None:
    dns = FakeModule("dns", accepts=SUB)
    scan_id = await scan(store, [FakeModule("crtsh", found=("a", "b", "c", "d")), dns], max_hosts=2)
    assert len(dns.seen) == 2
    assert store.get_scan(scan_id).host_limit_reached  # type: ignore[union-attr]


async def test_module_without_key_is_skipped(store: Store) -> None:
    shodan = FakeModule("shodan", requires_key="SHODAN_API_KEY")
    scan_id = await scan(store, [shodan, FakeModule("ok")])
    progress = {run.module: run for run in store.get_scan(scan_id).progress}  # type: ignore[union-attr]
    assert progress["shodan"].status is RunStatus.SKIPPED
    assert progress["shodan"].error == "Falta SHODAN_API_KEY"
    assert shodan.calls == 0

    await scan(store, [shodan], keys={"SHODAN_API_KEY": "x"})
    assert shodan.calls == 1


async def test_partial_errors_do_not_fail_the_module(store: Store) -> None:
    from reconmap.modules.base import ModuleError

    class Flaky(FakeModule):
        async def run(self, entity, ctx):  # type: ignore[no-untyped-def]
            if entity.value.startswith("bad"):
                self.seen.append(entity.value)
                raise ModuleError("timeout")
            return await super().run(entity, ctx)

    flaky = Flaky("dns", accepts=SUB)
    scan_id = await scan(store, [FakeModule("crtsh", found=("ok", "bad")), flaky])
    run = next(r for r in store.get_scan(scan_id).progress if r.module == "dns")  # type: ignore[union-attr]
    assert run.status is RunStatus.DONE
    assert (run.done, run.total, run.errors) == (2, 2, 1)
