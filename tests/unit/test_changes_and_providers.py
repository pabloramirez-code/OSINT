from fastapi.testclient import TestClient

from reconmap.checks import Status
from reconmap.insights import ScanIndex, environment_kind
from reconmap.models import (
    Entity,
    EntityType,
    ModuleResult,
    Relation,
    RelationType,
    ScanStatus,
)
from reconmap.report.diff import comparable_scans, diff_scans
from reconmap.report.json_report import ReportLevel, build_report
from reconmap.store import Store
from reconmap.third_parties import DNS, MAIL, SENDING, WEB, find_third_parties

XSS = "<b>x</b>"
ROOT_DNS = {
    "MX": ["1 ejemplo-com.mail.protection.outlook.com."],
    "NS": ["ana.ns.cloudflare.com.", "bob.ns.cloudflare.com."],
    "TXT": [
        '"MS=ms12345678"',
        '"google-site-verification=SECRETO123"',
        '"token-raro-sin-proveedor"',
        '"v=spf1 include:spf.protection.outlook.com include:_spf.socio.net '
        'include:_spf.example.com" " -all"',
        '"v=DMARC1; p=reject"',
    ],
}

# Proveedores externos


def providers_of(root_dns: object, cnames: dict[str, list[str]] | None = None) -> dict[str, str]:
    found = find_third_parties("example.com", root_dns, cnames or {})
    return {p.name: p.category for p in found.providers}


def test_providers_from_txt_spf_mx_and_ns() -> None:
    providers = providers_of(ROOT_DNS)
    assert providers["Microsoft 365"] == MAIL  # MX y SPF pesan más que el TXT
    assert providers["Google"]
    assert providers["Cloudflare DNS"] == DNS


def test_unknown_items_are_listed_or_counted_never_guessed() -> None:
    found = find_third_parties("example.com", ROOT_DNS, {})
    assert found.unknown_spf == ["_spf.socio.net"]  # el include propio no cuenta
    assert found.unidentified_txt == 1
    assert "SECRETO123" not in str(found.as_dict())  # los tokens nunca se muestran


def test_cname_targets() -> None:
    cnames = {
        "app.example.com": ["k8s-prod-123.elb.eu-west-1.amazonaws.com."],
        "docs.example.com": ["example-docs.gitlab.io."],
        "go.example.com": ["example.mktoweb.com."],
        "old.example.com": ["web1.hosting-desconocido.net."],
        "www.example.com": ["example.com."],
    }
    found = find_third_parties("example.com", {}, cnames)
    names = {p.name: p.category for p in found.providers}
    assert names == {
        "AWS Elastic Load Balancing": WEB,
        "GitLab Pages": WEB,
        "Marketo": SENDING,
    }
    assert found.unknown_cname == ["web1.hosting-desconocido.net"]


def test_split_spf_record_is_joined() -> None:
    found = find_third_parties(
        "example.com", {"TXT": ['"v=spf1 include:sendgrid.net" " include:mailgun.org -all"']}, {}
    )
    assert {p.name for p in found.providers} == {"SendGrid", "Mailgun"}


# Entornos no productivos


def test_environment_kind() -> None:
    assert environment_kind("staging.example.com", "example.com") == (
        "Entorno no productivo",
        "staging",
    )
    assert environment_kind("api-dev2.example.com", "example.com") == (
        "Entorno no productivo",
        "dev",
    )
    assert environment_kind("grafana-prod.example.com", "example.com") == (
        "Herramienta interna",
        "grafana",
    )
    assert environment_kind("design.example.com", "example.com") is None
    assert environment_kind("www.example.com", "example.com") is None
    assert environment_kind("test.com", "test.com") is None  # el propio dominio no cuenta


def entity(entity_type: EntityType, value: str, **attributes: object) -> Entity:
    return Entity(type=entity_type, value=value, attributes=attributes)


def link(a: Entity, kind: RelationType, b: Entity) -> Relation:
    return Relation(from_ref=a.ref, type=kind, to_ref=b.ref)


def test_public_non_production_is_a_warning_private_only_is_info(store: Store) -> None:
    scan = store.create_scan("example.com")
    root = entity(EntityType.DOMAIN, "example.com")
    public = entity(EntityType.SUBDOMAIN, "staging.example.com")
    private = entity(EntityType.SUBDOMAIN, "grafana.example.com")
    public_ip = entity(EntityType.IP, "51.15.0.1")
    private_ip = entity(EntityType.IP, "10.0.0.5")
    store.save_result(
        scan.id,
        "t",
        ModuleResult(
            entities=[root, public, private, public_ip, private_ip],
            relations=[
                link(public, RelationType.RESOLVES_TO, public_ip),
                link(private, RelationType.RESOLVES_TO, private_ip),
            ],
        ),
    )
    index = ScanIndex(store, scan.id)

    def status(host: str, control: str) -> Status:
        insights = index.insights(f"subdomain:{host}")
        assert insights is not None
        return next(c.status for c in insights.problems if c.control == control)

    assert status("staging.example.com", "Entorno no productivo") is Status.WARN
    assert status("grafana.example.com", "Herramienta interna") is Status.INFO


# Cambios entre escaneos


def make_scan(
    store: Store,
    hosts: dict[str, str],
    ports: tuple[str, ...] = (),
    cves: tuple[str, ...] = (),
    light: bool = False,
    depth: int = 1,
    status: ScanStatus = ScanStatus.DONE,
    modules: tuple[str, ...] = ("DNS",),
    root_dns: object = None,
) -> str:
    """`hosts`: subdominio → IP (cadena vacía si no resuelve)."""
    scan = store.create_scan("example.com", depth=depth, allow_light=light)
    store.update_scan(scan.id, status=status)
    store.start_module_runs(scan.id, [(m.lower(), m) for m in modules])
    root = entity(EntityType.DOMAIN, "example.com", dns=root_dns or {})
    entities: list[Entity] = [root]
    relations = []
    for host, ip in hosts.items():
        sub = entity(EntityType.SUBDOMAIN, host)
        entities.append(sub)
        if ip:
            address = entity(EntityType.IP, ip)
            entities.append(address)
            relations.append(link(sub, RelationType.RESOLVES_TO, address))
    for port in ports:
        ip, _ = port.rsplit(":", 1)
        exposed = entity(EntityType.PORT, port)
        entities.append(exposed)
        relations.append(link(entity(EntityType.IP, ip), RelationType.EXPOSES_PORT, exposed))
    for cve_id in cves:
        cve = entity(EntityType.CVE, cve_id, internetdb=True)
        entities.append(cve)
        relations.append(link(entities[2], RelationType.HAS_VULNERABILITY, cve))
    store.save_result(scan.id, "t", ModuleResult(entities=entities, relations=relations))
    return scan.id


def test_diff_finds_what_is_new_and_gone(store: Store) -> None:
    old = make_scan(store, {"www.example.com": "51.15.0.1", "old.example.com": "51.15.0.2"},
                    ports=("51.15.0.1:443", "51.15.0.1:22"))  # fmt: skip
    new = make_scan(
        store,
        {"www.example.com": "51.15.0.1", "dev.example.com": "51.15.0.3"},
        ports=("51.15.0.1:443", "51.15.0.1:3306"),
        cves=("CVE-2024-0001",),
        root_dns={"MX": ["1 x.mail.protection.outlook.com."]},
    )
    previous, current = store.get_scan(old), store.get_scan(new)
    assert previous and current
    diff = diff_scans(store, previous, current)
    changes = {c.label: c for c in diff.changes}
    assert changes["Subdominios conocidos"].added == ["dev.example.com"]
    assert changes["Subdominios conocidos"].removed == ["old.example.com"]
    assert changes["Puertos abiertos"].added == ["51.15.0.1:3306"]
    assert changes["Puertos abiertos"].removed == ["51.15.0.1:22"]
    assert changes["CVEs"].added == ["CVE-2024-0001"]
    assert changes["Proveedores externos"].added == ["Microsoft 365"]
    new_problems = changes["Problemas (por host)"].added
    assert any("dev.example.com" in p and "no productivo" in p for p in new_problems)
    assert any("MySQL" in p for p in new_problems)
    assert diff.caveats == []


def test_diff_warns_when_scans_are_not_comparable(store: Store) -> None:
    old = make_scan(store, {}, light=True, depth=2, modules=("DNS",))
    new = make_scan(store, {}, light=False, depth=1, modules=("DNS", "NVD (CVEs)"))
    previous, current = store.get_scan(old), store.get_scan(new)
    assert previous and current
    caveats = " ".join(diff_scans(store, previous, current).caveats)
    assert "Modo distinto (Ligero → Pasivo)" in caveats
    assert "Profundidad distinta (2 → 1)" in caveats
    assert "no existían en el escaneo anterior: NVD (CVEs)" in caveats


def test_comparable_scans_are_earlier_finished_same_domain(store: Store) -> None:
    first = make_scan(store, {})
    make_scan(store, {}, status=ScanStatus.FAILED)
    other = store.create_scan("example.org")
    store.update_scan(other.id, status=ScanStatus.DONE)
    current = store.get_scan(make_scan(store, {}))
    make_scan(store, {})  # posterior: no cuenta
    assert current is not None
    assert [s.id for s in comparable_scans(store, current)] == [first]


# Interfaz e informes


def test_changes_tab(client: TestClient, store: Store) -> None:
    lone = make_scan(store, {})
    assert "No hay ningún escaneo anterior" in client.get(f"/scans/{lone}/tabs/changes").text
    newer = make_scan(store, {"api.example.com": "51.15.0.9"})
    page = client.get(f"/scans/{newer}/tabs/changes").text
    assert "api.example.com" in page and "+1 nuevo" in page
    page = client.get(f"/scans/{newer}/tabs/changes?against={lone}").text
    assert f'value="{lone}" selected' in page


def test_summary_shows_changes_and_providers(client: TestClient, store: Store) -> None:
    make_scan(store, {})
    scan_id = make_scan(
        store,
        {"staging.example.com": "51.15.0.4"},
        root_dns={"TXT": [f'"v=spf1 include:{XSS}.net -all"', '"MS=ms1"']},
    )
    page = client.get(f"/scans/{scan_id}/tabs/summary").text
    assert "Cambios desde el" in page
    assert "Proveedores externos" in page and "Microsoft 365" in page
    assert XSS not in page and "&lt;b&gt;x&lt;/b&gt;" in page
    subdomains = client.get(f"/scans/{scan_id}/tabs/subdomains").text
    assert "entorno no productivo: staging" in subdomains


def test_reports_include_changes_and_providers(store: Store) -> None:
    make_scan(store, {})
    scan_id = make_scan(store, {"api.example.com": "51.15.0.9"}, root_dns={"TXT": ['"MS=ms1"']})
    summary = build_report(store, scan_id, ReportLevel.SUMMARY)
    assert summary is not None
    assert summary["third_parties"] == {"Productividad e identidad": ["Microsoft 365"]}
    changes: dict[str, object] = summary["changes_since_previous"]  # type: ignore[assignment]
    labels = [c["label"] for c in changes["changes"]]  # type: ignore[attr-defined]
    assert "Subdominios conocidos" in labels
    compact = build_report(store, scan_id, ReportLevel.COMPACT)
    assert compact is not None and compact["third_parties"]


def test_caveats_use_stored_progress_even_from_history_list(store: Store) -> None:
    make_scan(store, {}, modules=("DNS",))
    current = store.get_scan(make_scan(store, {}, modules=("DNS", "NVD (CVEs)")))
    assert current is not None
    previous = comparable_scans(store, current)[0]  # viene de list_scans, sin progreso
    caveats = " ".join(diff_scans(store, previous, current).caveats)
    assert "no existían en el escaneo anterior: NVD (CVEs)." in caveats
