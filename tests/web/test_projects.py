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
