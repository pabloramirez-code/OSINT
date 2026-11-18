from fastapi.testclient import TestClient

from reconmap.models import Entity, EntityType, ScanStatus
from reconmap.store import Store
from tests.conftest import load_fixture

XSS = "<script>alert(1)</script>"


def scan_id_from(response_location: str) -> str:
    return response_location.rsplit("/", 1)[1]


def test_authorization_checkbox_sets_allow_light(client: TestClient, store: Store) -> None:
    unchecked = client.post("/scans", data={"domain": "example.com"}, follow_redirects=False)
    first = store.get_scan(scan_id_from(unchecked.headers["location"]))
    assert first is not None and first.allow_light is False

    store.update_scan(first.id, status=ScanStatus.DONE)
    checked = client.post(
        "/scans", data={"domain": "example.org", "authorized": "1"}, follow_redirects=False
    )
    second = store.get_scan(scan_id_from(checked.headers["location"]))
    assert second is not None and second.allow_light is True


def test_mail_tab_shows_risk_and_escapes_records(client: TestClient, store: Store) -> None:
    scan = store.create_scan("example.com")
    store.update_scan(scan.id, status=ScanStatus.DONE)
    mail = load_fixture("mail_github.com.json")
    assert isinstance(mail, dict)
    mail["spf"] = [f"v=spf1 {XSS} ~all"]
    store.upsert_entity(
        scan.id,
        Entity(type=EntityType.DOMAIN, value="example.com", attributes={"mail": mail}),
        "mail",
    )

    page = client.get(f"/scans/{scan.id}/tabs/mail").text
    assert "Riesgo de suplantación" in page
    assert "RSA de 1024 bits" in page
    assert XSS not in page and "&lt;script&gt;" in page
    assert "BAJO" in client.get(f"/scans/{scan.id}/tabs/summary").text


def test_mail_tab_without_data(client: TestClient, store: Store) -> None:
    scan = store.create_scan("example.com")
    store.update_scan(scan.id, status=ScanStatus.DONE)
    assert "no incluye datos de correo" in client.get(f"/scans/{scan.id}/tabs/mail").text
