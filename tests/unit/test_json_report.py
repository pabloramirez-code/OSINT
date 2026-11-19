import json
from datetime import UTC, datetime

from fastapi.testclient import TestClient

from reconmap.models import Entity, EntityType, ModuleResult, Relation, RelationType
from reconmap.report.json_report import ReportLevel, build_report
from reconmap.store import Store

NOW = datetime(2026, 11, 18, tzinfo=UTC)


def entity(entity_type: EntityType, value: str, **attributes: object) -> Entity:
    return Entity(type=entity_type, value=value, attributes=attributes)


def link(a: Entity, kind: RelationType, b: Entity) -> Relation:
    return Relation(from_ref=a.ref, type=kind, to_ref=b.ref)


def build(store: Store, urls: int = 0, certificates: int = 0) -> str:
    scan = store.create_scan("example.com")
    root = entity(
        EntityType.DOMAIN,
        "example.com",
        rdap={"registrar": "Registrador\nDe Prueba", "expires": "2030-01-01T00:00:00Z"},
    )
    app = entity(EntityType.SUBDOMAIN, "app.example.com")
    db = entity(EntityType.SUBDOMAIN, "db.example.com")
    old = entity(EntityType.SUBDOMAIN, "old.example.com", nxdomain=True)
    ip = entity(EntityType.IP, "192.0.2.10", vulns=["CVE-2024-0001"])
    asn = entity(EntityType.ASN, "AS64500")
    org = entity(EntityType.ORG, "Ejemplo <b>Hosting</b>")
    ports = [entity(EntityType.PORT, f"192.0.2.10:{p}") for p in (443, 3306)]
    expired = entity(
        EntityType.CERTIFICATE, "01", not_after="2025-01-01T00:00:00", issuer="C=US, O=Test CA"
    )
    git = entity(EntityType.URL, "http://example.com/.git/config")
    many_urls = [entity(EntityType.URL, f"http://example.com/p/{i}") for i in range(urls)]
    many_certs = [
        entity(
            EntityType.CERTIFICATE,
            f"serial-unico-{i}",
            not_after="2027-01-01T00:00:00",
            issuer="O=Big CA",
        )
        for i in range(certificates)
    ]
    store.save_result(
        scan.id,
        "test",
        ModuleResult(
            entities=[
                root,
                app,
                db,
                old,
                ip,
                asn,
                org,
                *ports,
                expired,
                git,
                *many_urls,
                *many_certs,
            ],
            relations=[
                link(root, RelationType.HAS_SUBDOMAIN, app),
                link(root, RelationType.HAS_SUBDOMAIN, db),
                link(root, RelationType.HAS_SUBDOMAIN, old),
                link(app, RelationType.RESOLVES_TO, ip),
                link(db, RelationType.RESOLVES_TO, ip),
                link(ip, RelationType.BELONGS_TO_ASN, asn),
                link(asn, RelationType.OWNED_BY, org),
                link(app, RelationType.HAS_CERTIFICATE, expired),
                link(root, RelationType.ARCHIVED_URL, git),
                *(link(ip, RelationType.EXPOSES_PORT, p) for p in ports),
                *(link(root, RelationType.ARCHIVED_URL, u) for u in many_urls),
                *(link(app, RelationType.HAS_CERTIFICATE, c) for c in many_certs),
            ],
        ),
    )
    return scan.id


def report(store: Store, scan_id: str, level: ReportLevel) -> dict[str, object]:
    data = build_report(store, scan_id, level, now=NOW)
    assert data is not None
    json.dumps(data)  # serializable
    return data


def test_all_levels_are_valid_json(store: Store) -> None:
    scan_id = build(store)
    for level in ReportLevel:
        assert report(store, scan_id, level)["level"] == level.value


def test_extended_keeps_everything(store: Store) -> None:
    scan_id = build(store)
    data = report(store, scan_id, ReportLevel.EXTENDED)
    assert len(data["entities"]) == len(store.entities(scan_id))  # type: ignore[arg-type]
    assert len(data["relations"]) == len(store.relations(scan_id))  # type: ignore[arg-type]


def test_compact_has_every_host(store: Store) -> None:
    scan_id = build(store)
    data = report(store, scan_id, ReportLevel.COMPACT)
    hosts: dict[str, list[object]] = data["hosts"]  # type: ignore[assignment]
    names = {row[0] for row in hosts["rows"]}  # type: ignore[index]
    assert names == {"example.com", "app.example.com", "db.example.com"}
    assert data["nxdomain"] == ["old.example.com"]
    assert "relations" not in data and "entities" not in data


def test_compact_host_row_is_flattened(store: Store) -> None:
    scan_id = build(store)
    data = report(store, scan_id, ReportLevel.COMPACT)
    hosts: dict[str, list[list[object]]] = data["hosts"]  # type: ignore[assignment]
    columns = hosts["columns"]
    row = dict(
        zip(columns, next(r for r in hosts["rows"] if r[0] == "db.example.com"), strict=True)
    )
    assert row["ips"] == "192.0.2.10"
    assert row["asn"] == "AS64500"
    assert row["ports"] == "443, 3306"
    assert any("MySQL" in str(p) for p in row["problems"])  # type: ignore[attr-defined]
    assert data["asns"] == {"AS64500": "Ejemplo <b>Hosting</b>"}


def test_compact_only_relevant_urls_and_certificates(store: Store) -> None:
    scan_id = build(store, urls=50, certificates=40)
    data = report(store, scan_id, ReportLevel.COMPACT)
    assert data["wayback"] == {"total": 51, "sensitive": ["http://example.com/.git/config"]}
    certificates: dict[str, object] = data["certificates"]  # type: ignore[assignment]
    assert certificates["total"] == 41
    assert certificates["expired"] == 1
    assert certificates["by_issuer"] == {"Big CA": 40, "Test CA": 1}
    assert "serial-unico-0" not in json.dumps(data)


def test_summary_has_no_individual_urls_or_certificates(store: Store) -> None:
    scan_id = build(store, urls=50, certificates=40)
    data = report(store, scan_id, ReportLevel.SUMMARY)
    text = json.dumps(data)
    assert "http://example.com/" not in text
    assert "serial-unico-0" not in text
    assert data["sensitive_urls"] == 1
    assert data["domain_expires"] == "2030-01-01"


def test_summary_groups_problems_and_keeps_every_fail(store: Store) -> None:
    scan_id = build(store)
    data = report(store, scan_id, ReportLevel.SUMMARY)
    problems: dict[str, object] = data["problems"]  # type: ignore[assignment]
    top_fail: list[dict[str, object]] = problems["top_fail"]  # type: ignore[assignment]
    mysql = next(g for g in top_fail if "MySQL" in str(g["summary"]))
    assert mysql["hosts_total"] == 2
    assert mysql["hosts"] == ["app.example.com", "db.example.com"]
    assert problems["fail"] == len(top_fail)


def test_external_text_is_single_line(store: Store) -> None:
    scan_id = build(store)
    data = report(store, scan_id, ReportLevel.COMPACT)
    domain: dict[str, object] = data["domain"]  # type: ignore[assignment]
    assert domain["registrar"] == "Registrador De Prueba"


def test_compact_and_summary_are_much_smaller(store: Store) -> None:
    scan_id = build(store, urls=500, certificates=300)
    sizes = {
        level: len(json.dumps(report(store, scan_id, level), ensure_ascii=False))
        for level in ReportLevel
    }
    assert sizes[ReportLevel.COMPACT] < sizes[ReportLevel.EXTENDED] / 10
    assert sizes[ReportLevel.SUMMARY] < 2000 * 4  # ~2000 tokens a 4 caracteres por token


def test_report_endpoint_levels(client: TestClient, store: Store) -> None:
    scan_id = build(store)
    for level, label in (
        ("summary", "resumen"),
        ("compact", "comprimido"),
        ("extended", "extendido"),
    ):
        response = client.get(f"/api/scans/{scan_id}/report?level={level}")
        assert response.status_code == 200
        assert response.json()["level"] == level
        assert f"-{label}.json" in response.headers["content-disposition"]
    assert client.get(f"/api/scans/{scan_id}/report").json()["level"] == "extended"
    assert client.get(f"/api/scans/{scan_id}/report?level=todo").status_code == 422


def test_json_tab_offers_three_downloads(client: TestClient, store: Store) -> None:
    scan_id = build(store)
    page = client.get(f"/scans/{scan_id}/tabs/json").text
    for level in ReportLevel:
        assert f"report?level={level.value}" in page
