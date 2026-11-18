from fastapi.testclient import TestClient

from reconmap.models import Entity, EntityType, ModuleResult, Relation, RelationType, ScanStatus
from reconmap.report.graph import build_graph
from reconmap.store import Store

XSS = "<img src=x onerror=alert(1)>"


def entity(entity_type: EntityType, value: str, **attributes: object) -> Entity:
    return Entity(type=entity_type, value=value, attributes=attributes)


def link(a: Entity, kind: RelationType, b: Entity) -> Relation:
    return Relation(from_ref=a.ref, type=kind, to_ref=b.ref)


def sample_scan(store: Store, urls: int = 0) -> str:
    scan = store.create_scan("example.com")
    root = entity(EntityType.DOMAIN, "example.com")
    www = entity(EntityType.SUBDOMAIN, "www.example.com")
    ip = entity(EntityType.IP, "192.0.2.10", vulns=["CVE-2024-0001"])
    asn = entity(EntityType.ASN, "AS64500")
    archived = [entity(EntityType.URL, f"https://example.com/{i}") for i in range(urls)]
    result = ModuleResult(
        entities=[root, www, ip, asn, *archived],
        relations=[
            link(root, RelationType.HAS_SUBDOMAIN, www),
            link(www, RelationType.RESOLVES_TO, ip),
            link(www, RelationType.RESOLVES_TO, ip),
            link(ip, RelationType.BELONGS_TO_ASN, asn),
            link(ip, RelationType.BELONGS_TO_ASN, entity(EntityType.ASN, "AS-NO-EXISTE")),
            *(link(root, RelationType.ARCHIVED_URL, url) for url in archived),
        ],
    )
    store.save_result(scan.id, "test", result)
    return scan.id


def test_edges_point_to_existing_nodes_and_nodes_are_unique(store: Store) -> None:
    graph = build_graph(store, sample_scan(store))
    nodes = graph["nodes"]
    edges = graph["edges"]
    assert isinstance(nodes, list) and isinstance(edges, list)
    ids = [n["id"] for n in nodes]
    assert len(ids) == len(set(ids)) == 4
    assert all(e["source"] in ids and e["target"] in ids for e in edges)
    assert len(edges) == 3


def test_grouping_only_above_threshold(store: Store) -> None:
    small = build_graph(store, sample_scan(store, urls=10), max_nodes=300)
    assert small["grouped"] == []

    big = build_graph(store, sample_scan(store, urls=400), max_nodes=300)
    assert big["grouped"] == ["url"]
    nodes = big["nodes"]
    assert isinstance(nodes, list)
    group = next(n for n in nodes if n["group"])
    assert group["label"] == "400 URLs archivadas"
    assert len(nodes) == 5
    edges = big["edges"]
    assert isinstance(edges, list)
    assert sum(e["target"] == group["id"] for e in edges) == 1


def test_external_values_travel_as_plain_text(store: Store) -> None:
    scan = store.create_scan("example.com")
    store.upsert_entity(scan.id, entity(EntityType.ORG, XSS, note=XSS), "bgp")
    nodes = build_graph(store, scan.id)["nodes"]
    assert isinstance(nodes, list)
    assert nodes[0]["label"] == XSS
    assert nodes[0]["details"] == {"note": XSS}


def test_graph_api(client: TestClient, store: Store) -> None:
    scan_id = sample_scan(store)
    store.update_scan(scan_id, status=ScanStatus.DONE)
    data = client.get(f"/api/scans/{scan_id}/graph").json()
    assert {n["type"] for n in data["nodes"]} == {"domain", "subdomain", "ip", "asn"}
    assert client.get("/api/scans/inexistente/graph").status_code == 404
    tab = client.get(f"/scans/{scan_id}/tabs/graph").text
    assert f'data-graph-url="/api/scans/{scan_id}/graph"' in tab


def test_scan_page_can_open_a_tab_directly(client: TestClient, store: Store) -> None:
    scan_id = sample_scan(store)
    store.update_scan(scan_id, status=ScanStatus.DONE)
    assert f"/scans/{scan_id}/tabs/graph" in client.get(f"/scans/{scan_id}?tab=graph").text
    assert f"/scans/{scan_id}/tabs/summary" in client.get(f"/scans/{scan_id}?tab=nope").text


def test_short_labels() -> None:
    from reconmap.report.graph import short_label

    assert short_label(entity(EntityType.PORT, "2606:4700::1:443")) == "443"
    cert = entity(EntityType.CERTIFICATE, "0a" * 20, not_after="2027-08-01T21:19:03")
    assert short_label(cert) == "cert. 2027-08-01"
    assert len(short_label(entity(EntityType.SUBDOMAIN, "a" * 60 + ".example.com"))) == 30
