
from reconmap.engine import Engine
from reconmap.models import Contact, EntityType, RunStatus, ScanStatus
from reconmap.modules.base import ModuleError
from reconmap.store import Store
from tests.conftest import FakeModule


def runs(store: Store, scan_id: str) -> dict[str, RunStatus]:
    scan = store.get_scan(scan_id)
    assert scan is not None
    return {run.module: run.status for run in scan.progress}


async def test_failing_module_does_not_stop_the_others(store: Store) -> None:
    engine = Engine(
        store,
        [
            FakeModule("boom", error=RuntimeError("explota")),
            FakeModule("expected", error=ModuleError("HTTP 502")),
            FakeModule("ok", found=("www", "api")),
        ],
    )
    scan_id = engine.create_scan("example.com")
    await engine.run(scan_id)

    scan = store.get_scan(scan_id)
    assert scan is not None and scan.status is ScanStatus.DONE
    progress = {run.module: run for run in scan.progress}
    assert progress["ok"].status is RunStatus.DONE and progress["ok"].results == 2
    assert progress["expected"].error == "HTTP 502"
    assert progress["boom"].error == "Error inesperado (RuntimeError)"
    assert len(store.entities(scan_id, EntityType.SUBDOMAIN)) == 2


async def test_scan_fails_when_every_module_fails(store: Store) -> None:
    engine = Engine(store, [FakeModule(error=ModuleError("sin red"))])
    scan_id = engine.create_scan("example.com")
    await engine.run(scan_id)
    assert store.get_scan(scan_id).status is ScanStatus.FAILED  # type: ignore[union-attr]


async def test_active_modules_only_run_in_active_scans(store: Store) -> None:
    active = FakeModule("activo", contact=Contact.ACTIVE)
    engine = Engine(store, [active, FakeModule("ok")])
    scan_id = engine.create_scan("example.com", allow_light=True)
    await engine.run(scan_id)
    assert runs(store, scan_id)["activo"] is RunStatus.SKIPPED
    assert active.calls == 0


async def test_light_module_needs_scan_authorization(store: Store) -> None:
    light = FakeModule("light", contact=Contact.LIGHT)
    engine = Engine(store, [light, FakeModule("ok")])

    denied = engine.create_scan("example.com", allow_light=False)
    await engine.run(denied)
    assert runs(store, denied)["light"] is RunStatus.SKIPPED
    assert light.calls == 0

    allowed = engine.create_scan("example.com", allow_light=True)
    await engine.run(allowed)
    assert runs(store, allowed)["light"] is RunStatus.DONE
    assert light.calls == 1
