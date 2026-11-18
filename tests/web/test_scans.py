import time

from fastapi.testclient import TestClient

from reconmap.models import Entity, EntityType, ScanStatus
from reconmap.store import Store

XSS = "<img src=x onerror=alert(1)>"


def wait_until_finished(store: Store, scan_id: str) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        scan = store.get_scan(scan_id)
        if scan is not None and not scan.is_active:
            return
        time.sleep(0.05)
    raise AssertionError("El escaneo no terminó")


def test_valid_post_redirects_to_scan(client: TestClient) -> None:
    response = client.post("/scans", data={"domain": "Example.COM"}, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"].startswith("/scans/")


def test_htmx_post_uses_hx_redirect(client: TestClient) -> None:
    response = client.post("/scans", data={"domain": "example.com"}, headers={"HX-Request": "true"})
    assert response.headers["HX-Redirect"].startswith("/scans/")


def test_invalid_domain_is_422_and_escaped(client: TestClient) -> None:
    response = client.post("/scans", data={"domain": "<script>alert(1)</script>"})
    assert response.status_code == 422
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in response.text
    assert "<script>alert(1)" not in response.text


def test_second_post_while_running_is_429(client: TestClient, store: Store) -> None:
    scan = store.create_scan("example.com")
    store.update_scan(scan.id, status=ScanStatus.RUNNING)
    response = client.post("/scans", data={"domain": "example.org"})
    assert response.status_code == 429


def test_progress_polls_only_while_running(client: TestClient, store: Store) -> None:
    scan = store.create_scan("example.com")
    store.update_scan(scan.id, status=ScanStatus.RUNNING)
    assert 'hx-trigger="every 1s"' in client.get(f"/scans/{scan.id}/progress").text

    store.update_scan(scan.id, status=ScanStatus.DONE)
    assert 'hx-trigger="every 1s"' not in client.get(f"/scans/{scan.id}/progress").text


def test_full_scan_shows_subdomains(client: TestClient, store: Store) -> None:
    location = client.post("/scans", data={"domain": "example.com"}, follow_redirects=False)
    scan_id = location.headers["location"].rsplit("/", 1)[1]
    wait_until_finished(store, scan_id)

    page = client.get(f"/scans/{scan_id}/tabs/subdomains")
    assert "www.example.com" in page.text
    report = client.get(f"/api/scans/{scan_id}/report").json()
    assert report["scan"]["status"] == "done"


def test_external_data_is_escaped_in_subdomain_table(client: TestClient, store: Store) -> None:
    scan = store.create_scan("example.com")
    store.update_scan(scan.id, status=ScanStatus.DONE)
    store.upsert_entity(
        scan.id, Entity(type=EntityType.SUBDOMAIN, value=f"{XSS}.example.com"), "crtsh"
    )

    response = client.get(f"/scans/{scan.id}/tabs/subdomains")
    assert "&lt;img src=x onerror=alert(1)&gt;" in response.text
    assert XSS not in response.text


def test_unknown_scan_is_404_page(client: TestClient) -> None:
    response = client.get("/scans/inexistente")
    assert response.status_code == 404
    assert "Ese escaneo no existe" in response.text
    assert client.get("/api/scans/inexistente/report").status_code == 404
