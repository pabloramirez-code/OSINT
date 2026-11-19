import pytest
from fastapi.testclient import TestClient

from reconmap.config import Settings, in_allowlist
from reconmap.engine import ContactNotAllowedError, Engine
from reconmap.models import Contact, RunStatus, ScanStatus
from reconmap.store import Store
from reconmap.web.app import create_app
from tests.conftest import FakeModule
from tests.web.test_projects import rescan_form

ALLOW = ("example.com",)
XSS = "<script>alert(1)</script>"


def test_in_allowlist() -> None:
    assert in_allowlist("example.com", ALLOW)
    assert in_allowlist("api.example.com", ALLOW)
    assert not in_allowlist("example.com.evil.net", ALLOW)
    assert not in_allowlist("notexample.com", ALLOW)
    assert not in_allowlist("example.com", ())


def test_allowlist_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RECONMAP_ACTIVE_ALLOWLIST", " Example.com. , otro.es ")
    assert Settings().active_allowlist == ("example.com", "otro.es")


# Motor


def active_module() -> FakeModule:
    return FakeModule("activo", contact=Contact.ACTIVE)


def test_active_modules_need_an_allowlist(store: Store) -> None:
    with pytest.raises(ContactNotAllowedError):
        Engine(store, [active_module()])  # type: ignore[list-item]


def test_active_scan_only_for_allowlisted_targets(store: Store) -> None:
    engine = Engine(store, [active_module()], active_allowlist=ALLOW)  # type: ignore[list-item]
    with pytest.raises(ContactNotAllowedError):
        engine.create_scan("otro.org", allow_active=True)
    scan = store.get_scan(engine.create_scan("example.com", allow_active=True))
    assert scan is not None
    assert scan.allow_active and scan.allow_light  # Activo implica Ligero
    assert scan.mode == "activo"


async def test_active_module_runs_only_in_active_mode(store: Store) -> None:
    module = active_module()
    engine = Engine(store, [module], active_allowlist=ALLOW)  # type: ignore[list-item]
    passive = engine.create_scan("example.com")
    await engine.run(passive)
    assert module.seen == []
    progress = store.get_scan(passive)
    assert progress is not None
    assert progress.progress[0].status is RunStatus.SKIPPED
    active = engine.create_scan("example.com", allow_active=True)
    await engine.run(active)
    assert module.seen == ["example.com"]


# Interfaz


@pytest.fixture
def active_client(store: Store) -> TestClient:
    app = create_app(
        store=store, modules=[FakeModule(found=("www",))], keys={}, active_allowlist=ALLOW
    )
    return TestClient(app)


def test_active_option_hidden_without_allowlist(client: TestClient) -> None:
    page = client.get("/").text
    assert 'name="authorized" value="2"' not in page
    assert "Desactivado" in page


def test_active_option_shown_with_allowlist(active_client: TestClient) -> None:
    page = active_client.get("/").text
    assert 'name="authorized" value="2"' in page
    assert "example.com" in page  # la lista blanca se ve en el título de la opción


def test_active_scan_rejected_outside_allowlist(active_client: TestClient, store: Store) -> None:
    response = active_client.post("/scans", data={"domain": "otro.org", "authorized": "2"})
    assert response.status_code == 422
    assert "lista blanca" in response.text
    assert not store.list_scans()


def test_active_scan_created_for_allowlisted(active_client: TestClient, store: Store) -> None:
    response = active_client.post(
        "/scans",
        data={"domain": "api.example.com", "authorized": "2", "depth": "1"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    (scan,) = store.list_scans()
    assert scan.allow_active and scan.mode == "activo"


def test_projects_offer_active_only_for_allowlisted(
    active_client: TestClient, store: Store
) -> None:
    for target in ("example.com", "otro.org"):
        scan = store.create_scan(target)
        store.update_scan(scan.id, status=ScanStatus.DONE)
    page = active_client.get("/projects").text
    assert 'name="authorized" value="2"' in rescan_form(page, "example.com")
    assert 'name="authorized" value="2"' not in rescan_form(page, "otro.org")


def test_mode_pill(active_client: TestClient, store: Store) -> None:
    scan = store.create_scan("example.com", allow_active=True)
    store.update_scan(scan.id, status=ScanStatus.DONE)
    assert 'class="pill pill-activo"' in active_client.get("/projects").text
