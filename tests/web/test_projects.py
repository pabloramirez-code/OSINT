import re

from fastapi.testclient import TestClient

from reconmap.models import Entity, EntityType, ScanStatus
from reconmap.store import Store

XSS = "<b>x</b>"


def finished_scan(store: Store, target: str, subdomains: int) -> str:
    scan = store.create_scan(target)
    store.update_scan(scan.id, status=ScanStatus.DONE)
    for i in range(subdomains):
        store.upsert_entity(scan.id, Entity(type=EntityType.SUBDOMAIN, value=f"s{i}.{target}"), "t")
    return scan.id


def test_projects_group_scans_by_domain(client: TestClient, store: Store) -> None:
    first = finished_scan(store, "example.com", 2)
    second = finished_scan(store, "example.com", 3)
    other = finished_scan(store, "example.org", 1)

    page = client.get("/projects").text
    assert page.count('<details class="project">') == 2
    assert re.search(r"\b2 escaneos\b", page) and re.search(r"\b1 escaneo\b", page)
    for scan_id in (first, second, other):
        assert f"/scans/{scan_id}" in page
    assert '<span class="nav-count">2</span>' in page


def test_projects_empty_state(client: TestClient) -> None:
    assert "Todavía no hay proyectos" in client.get("/projects").text


def test_home_shows_recent_projects_and_form(client: TestClient, store: Store) -> None:
    finished_scan(store, "example.com", 4)
    page = client.get("/").text
    assert "Proyectos recientes" in page and "4 subdominios" in page
    assert 'name="domain"' in page


def test_entity_counts(store: Store) -> None:
    scan_id = finished_scan(store, "example.com", 3)
    assert store.entity_counts([scan_id])[scan_id] == {"subdomain": 3}
    assert store.entity_counts([]) == {}


def test_active_scan_appears_in_sidebar(client: TestClient, store: Store) -> None:
    scan = store.create_scan("example.com")
    store.update_scan(scan.id, status=ScanStatus.RUNNING)
    page = client.get("/projects").text
    assert "En curso:" in page and f"/scans/{scan.id}" in page


def test_project_names_are_escaped(client: TestClient, store: Store) -> None:
    scan = store.create_scan(XSS)
    store.update_scan(scan.id, status=ScanStatus.DONE)
    page = client.get("/projects").text
    assert XSS not in page and "&lt;b&gt;x&lt;/b&gt;" in page


def rescan_form(page: str, target: str) -> str:
    match = re.search(
        r'<form class="rescan".*?name="domain" value="' + re.escape(target) + r'".*?</form>',
        page,
        re.S,
    )
    assert match, f"sin botón de actualizar para {target}"
    return match.group(0)


def test_each_project_has_a_rescan_button(client: TestClient, store: Store) -> None:
    finished_scan(store, "example.com", 1)
    finished_scan(store, "example.org", 1)
    page = client.get("/projects").text
    for target in ("example.com", "example.org"):
        form = rescan_form(page, target)
        assert 'hx-post="/scans"' in form and "Actualizar" in form


def test_rescan_keeps_depth_but_defaults_to_passive(client: TestClient, store: Store) -> None:
    scan = store.create_scan("example.com", depth=2, allow_light=True)
    store.update_scan(scan.id, status=ScanStatus.DONE)
    form = rescan_form(client.get("/projects").text, "example.com")
    assert '<option value="2" selected>' in form
    # El modo Ligero se elige en cada escaneo (regla 1): nunca viene marcado.
    assert re.search(r'name="authorized" value="" checked', form)
    assert not re.search(r'name="authorized" value="1" checked', form)


def test_rescan_is_disabled_while_a_scan_runs(client: TestClient, store: Store) -> None:
    finished_scan(store, "example.com", 1)
    running = store.create_scan("example.org")
    store.update_scan(running.id, status=ScanStatus.RUNNING)
    form = rescan_form(client.get("/projects").text, "example.com")
    assert "Escaneando…" in form and "disabled" in form


def test_rescan_launches_a_new_scan(client: TestClient, store: Store) -> None:
    first = finished_scan(store, "example.com", 1)
    response = client.post(
        "/scans",
        data={"domain": "example.com", "depth": "1", "authorized": ""},
        follow_redirects=False,
    )
    assert response.status_code == 303
    new_id = response.headers["location"].rsplit("/", 1)[1]
    assert new_id != first
    scan = store.get_scan(new_id)
    assert scan is not None and scan.target == "example.com" and not scan.allow_light
