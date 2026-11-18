from datetime import UTC, datetime

from fastapi.testclient import TestClient

from reconmap.checks import Status
from reconmap.insights import ScanIndex
from reconmap.models import Entity, EntityType, ModuleResult, Relation, RelationType, ScanStatus
from reconmap.report.graph import build_graph
from reconmap.store import Store

NOW = datetime(2026, 11, 18, tzinfo=UTC)
XSS = "<script>alert(1)</script>"


def entity(entity_type: EntityType, value: str, **attributes: object) -> Entity:
    return Entity(type=entity_type, value=value, attributes=attributes)


def link(a: Entity, kind: RelationType, b: Entity) -> Relation:
    return Relation(from_ref=a.ref, type=kind, to_ref=b.ref)


def build(store: Store) -> str:
    scan = store.create_scan("example.com")
    root = entity(EntityType.DOMAIN, "example.com")
    app = entity(EntityType.SUBDOMAIN, "app.example.com")
    old = entity(EntityType.SUBDOMAIN, "old.example.com", nxdomain=True)
    ip = entity(EntityType.IP, "192.0.2.10", vulns=["CVE-2024-0001"], tags=["cdn"])
    ports = [entity(EntityType.PORT, f"192.0.2.10:{p}") for p in (22, 443, 3306)]
    expired = entity(EntityType.CERTIFICATE, "01", not_after="2025-01-01T00:00:00")
    git = entity(EntityType.URL, "http://example.com/.git/config")
    store.save_result(
        scan.id,
        "test",
        ModuleResult(
            entities=[root, app, old, ip, *ports, expired, git],
            relations=[
                link(root, RelationType.HAS_SUBDOMAIN, app),
                link(root, RelationType.HAS_SUBDOMAIN, old),
                link(app, RelationType.RESOLVES_TO, ip),
                link(app, RelationType.HAS_CERTIFICATE, expired),
                link(root, RelationType.ARCHIVED_URL, git),
                *(link(ip, RelationType.EXPOSES_PORT, p) for p in ports),
            ],
        ),
    )
    return scan.id


def statuses(store: Store, scan_id: str, nid: str) -> dict[str, Status]:
    insights = ScanIndex(store, scan_id, now=NOW).insights(nid)
    assert insights is not None
    return {c.control: c.status for c in insights.problems}


def test_ip_problems(store: Store) -> None:
    scan_id = build(store)
    problems = statuses(store, scan_id, "ip:192.0.2.10")
    assert problems["Base de datos expuesta"] is Status.FAIL
    assert problems["Administración expuesta"] is Status.WARN
    assert problems["CVE"] is Status.WARN
    assert problems["CDN"] is Status.INFO
    insights = ScanIndex(store, scan_id, now=NOW).insights("ip:192.0.2.10")
    assert insights is not None and insights.worst is Status.FAIL
    assert ("Hosts que apuntan aquí", "app.example.com") in insights.info


def test_subdomain_inherits_ip_problems_and_checks_certificates(store: Store) -> None:
    scan_id = build(store)
    insights = ScanIndex(store, scan_id, now=NOW).insights("subdomain:app.example.com")
    assert insights is not None
    summaries = [c.summary for c in insights.problems]
    assert any("MySQL" in s and "192.0.2.10" in s for s in summaries)
    assert any("caducó el 2025-01-01" in s for s in summaries)
    assert {r["id"] for r in insights.related} >= {"ip:192.0.2.10", "domain:example.com"}


def test_unresolved_subdomain_is_only_informative(store: Store) -> None:
    scan_id = build(store)
    insights = ScanIndex(store, scan_id, now=NOW).insights("subdomain:old.example.com")
    assert insights is not None and insights.worst is None
    assert insights.problems[0].status is Status.INFO


def test_sensitive_archived_path(store: Store) -> None:
    scan_id = build(store)
    assert statuses(store, scan_id, "url:http://example.com/.git/config") == {
        "Ruta sensible": Status.WARN
    }


def test_graph_nodes_have_order_and_severity(store: Store) -> None:
    scan_id = build(store)
    nodes = build_graph(store, scan_id)["nodes"]
    assert isinstance(nodes, list)
    assert sorted(n["order"] for n in nodes) == list(range(len(nodes)))
    worst = {n["id"]: n["worst"] for n in nodes}
    assert worst["ip:192.0.2.10"] == "fail"
    assert worst["subdomain:old.example.com"] is None


def test_node_api(client: TestClient, store: Store) -> None:
    scan_id = build(store)
    store.update_scan(scan_id, status=ScanStatus.DONE)
    store.upsert_entity(scan_id, entity(EntityType.ORG, XSS), "bgp")

    data = client.get(f"/api/scans/{scan_id}/node", params={"id": "ip:192.0.2.10"}).json()
    assert data["type_label"] == "IP" and data["worst"] == "fail"
    org = client.get(f"/api/scans/{scan_id}/node", params={"id": f"org:{XSS}"}).json()
    assert org["title"] == XSS
    missing = client.get(f"/api/scans/{scan_id}/node", params={"id": "ip:203.0.113.1"})
    assert missing.status_code == 404
