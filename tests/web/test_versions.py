from fastapi.testclient import TestClient

from reconmap.models import Entity, EntityType, ModuleResult, Relation, RelationType, ScanStatus
from reconmap.store import Store
from reconmap.web import views

XSS = "<img src=x onerror=alert(1)>"


def tech(value: str, name: str, version: str | None, **extra: object) -> Entity:
    return Entity(
        type=EntityType.TECHNOLOGY,
        value=value,
        attributes={"name": name, "version": version, **extra},
    )


def build(store: Store, name: str = "PHP") -> str:
    scan = store.create_scan("example.com")
    store.update_scan(scan.id, status=ScanStatus.DONE)
    www = Entity(type=EntityType.SUBDOMAIN, value="www.example.com")
    dev = Entity(type=EntityType.SUBDOMAIN, value="dev.example.com")
    ip_a = Entity(type=EntityType.IP, value="198.51.100.1")
    ip_b = Entity(type=EntityType.IP, value="198.51.100.2")
    old = tech("php:php:7.2.24", name, "7.2.24", cve_lookup="hecho")
    new = tech("php:php:8.3.36", name, "8.3.36", cve_lookup="hecho")
    bare = tech("php:php:*", name, None)
    wordpress = tech("wordpress:wordpress:*", "WordPress", None)
    kev = Entity(
        type=EntityType.CVE,
        value="CVE-2024-4577",
        attributes={"nvd": {"cvss": 9.8, "kev": True}},
    )

    def rel(a: Entity, kind: RelationType, b: Entity) -> Relation:
        return Relation(from_ref=a.ref, type=kind, to_ref=b.ref)

    store.save_result(
        scan.id,
        "dns",
        ModuleResult(
            entities=[www, dev, ip_a, ip_b],
            relations=[
                rel(www, RelationType.RESOLVES_TO, ip_a),
                rel(dev, RelationType.RESOLVES_TO, ip_b),
            ],
        ),
    )
    store.save_result(
        scan.id,
        "internetdb",
        ModuleResult(
            entities=[old, new, wordpress, kev],
            relations=[
                rel(ip_a, RelationType.USES_TECHNOLOGY, new),
                rel(ip_b, RelationType.USES_TECHNOLOGY, old),
                rel(ip_b, RelationType.USES_TECHNOLOGY, wordpress),
                rel(old, RelationType.HAS_VULNERABILITY, kev),
            ],
        ),
    )
    store.save_result(
        scan.id,
        "headers",
        ModuleResult(entities=[bare], relations=[rel(www, RelationType.USES_TECHNOLOGY, bare)]),
    )
    return scan.id


def test_versions_grouped_by_product(store: Store) -> None:
    scan = store.get_scan(build(store))
    assert scan is not None
    data = views.versions(store, scan)
    (php,) = data["with_version"]  # type: ignore[misc]
    assert php.several
    assert [v.version for v in php.versions] == ["8.3.36", "7.2.24"]  # la más alta primero
    old = php.versions[1]
    assert old.where == ["198.51.100.2 · dev.example.com"]
    assert old.sources == ["Shodan InternetDB (CPE)"]
    assert (old.cves, old.max_cvss, old.kev) == (1, 9.8, 1)
    assert php.unversioned_where == ["www.example.com"]
    assert [p.name for p in data["without_version"]] == ["WordPress"]  # type: ignore[attr-defined]
    assert data["counts"] == {
        "Productos": 2,
        "Con versión exacta": 1,
        "Con varias versiones": 1,
        "Sin versión": 1,
    }


def test_version_ordering_is_numeric() -> None:
    assert views._version_key("10.0.1") > views._version_key("9.9.9")
    assert views._version_key("1.1.1f") == (1, 1, 1)


def test_versions_tab(client: TestClient, store: Store) -> None:
    page = client.get(f"/scans/{build(store, name=XSS)}/tabs/versions").text
    assert "Versiones detectadas" in page
    assert "2 versiones distintas" in page
    assert "8.3.36" in page and "7.2.24" in page
    assert "1 KEV" in page
    assert "Detectados sin versión" in page and "WordPress" in page
    assert "también visto sin versión en 1 sitio" in page
    assert XSS not in page and "&lt;img src=x onerror=alert(1)&gt;" in page


def test_versions_tab_empty(client: TestClient, store: Store) -> None:
    scan = store.create_scan("example.com")
    store.update_scan(scan.id, status=ScanStatus.DONE)
    page = client.get(f"/scans/{scan.id}/tabs/versions").text
    assert "No se han detectado tecnologías" in page
