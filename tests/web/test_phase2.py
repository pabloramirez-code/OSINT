from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from reconmap.models import Entity, EntityType, Relation, RelationType, ScanStatus
from reconmap.store import Store
from reconmap.web.app import create_app
from tests.conftest import FakeModule

FAKE_KEY = "sk-test-0123456789abcdef"


@pytest.mark.parametrize("depth", ["0", "4", "abc"])
def test_depth_out_of_range_is_422(client: TestClient, depth: str) -> None:
    response = client.post("/scans", data={"domain": "example.com", "depth": depth})
    assert response.status_code == 422


@pytest.fixture
def client_with_key(store: Store) -> Iterator[TestClient]:
    modules = [
        FakeModule("certspotter", requires_key="CERTSPOTTER_API_KEY"),
        FakeModule("vt", requires_key="VIRUSTOTAL_API_KEY"),
    ]
    app = create_app(store=store, modules=modules, keys={"CERTSPOTTER_API_KEY": FAKE_KEY})  # type: ignore[arg-type]
    with TestClient(app) as client:
        yield client


def test_settings_never_shows_key_values(client_with_key: TestClient) -> None:
    page = client_with_key.get("/settings").text
    assert FAKE_KEY not in page
    assert FAKE_KEY[:8] not in page
    assert "CERTSPOTTER_API_KEY" in page
    assert "Falta VIRUSTOTAL_API_KEY" in page


def test_ips_tab_shows_asn_ports_and_escapes(client: TestClient, store: Store) -> None:
    scan = store.create_scan("example.com")
    store.update_scan(scan.id, status=ScanStatus.DONE)
    ip = Entity(type=EntityType.IP, value="192.0.2.10", attributes={"vulns": ["CVE-2024-0001"]})
    asn = Entity(type=EntityType.ASN, value="AS64500")
    org = Entity(type=EntityType.ORG, value="<b>Org</b>")
    port = Entity(type=EntityType.PORT, value="192.0.2.10:443")
    for entity in (ip, asn, org, port):
        store.upsert_entity(scan.id, entity, "test")
    for a, kind, b in [
        (ip, RelationType.BELONGS_TO_ASN, asn),
        (asn, RelationType.OWNED_BY, org),
        (ip, RelationType.EXPOSES_PORT, port),
    ]:
        store.add_relation(
            scan.id, Relation(from_ref=a.ref, type=kind, to_ref=b.ref, source="test")
        )

    page = client.get(f"/scans/{scan.id}/tabs/ips").text
    assert "AS64500" in page and "443" in page and "CVE-2024-0001" in page
    assert "&lt;b&gt;Org&lt;/b&gt;" in page and "<b>Org</b>" not in page


def test_summary_warns_when_host_limit_reached(client: TestClient, store: Store) -> None:
    scan = store.create_scan("example.com")
    store.update_scan(scan.id, status=ScanStatus.DONE, host_limit_reached=True)
    assert "tope de subdominios" in client.get(f"/scans/{scan.id}/tabs/summary").text
