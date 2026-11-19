from fastapi.testclient import TestClient

from reconmap.edge_assessment import (
    Confidence,
    IpInfo,
    WafStatus,
    assess_edge,
    ip_provider,
    org_name,
)
from reconmap.insights import ScanIndex, edge_overview
from reconmap.models import Entity, EntityType, ModuleResult, Relation, RelationType, ScanStatus
from reconmap.report.json_report import ReportLevel, build_report
from reconmap.store import Store

CLOUDFLARE_IP = IpInfo("104.20.44.74", asns=["AS13335"], orgs=["CLOUDFLARENET - Cloudflare, Inc."])
OVH_IP = IpInfo("51.15.0.1", asns=["AS16276"], orgs=["OVH OVH SAS"])
AWS_IP = IpInfo("3.5.0.1", asns=["AS16509"], orgs=["AMAZON-02 - Amazon.com, Inc."])


def headers(server: str | None = None, cookies: tuple[str, ...] = ()) -> dict[str, object]:
    response = {
        "status": 200,
        "headers": {"server": server} if server else {},
        "cookies": [{"name": name} for name in cookies],
    }
    return {"https": response, "http": {"error": "No responde"}}


# Evaluación pura


def test_cloudflare_asn_is_possible_waf() -> None:
    edge = assess_edge([CLOUDFLARE_IP])
    assert edge is not None
    assert edge.status is WafStatus.POSSIBLE
    assert edge.label == "Posible WAF · Cloudflare"
    assert edge.ip_label == "IP de Cloudflare"
    assert edge.confidence is Confidence.MEDIUM


def test_two_independent_signals_give_high_confidence() -> None:
    edge = assess_edge([CLOUDFLARE_IP], http_headers=headers(server="cloudflare"))
    assert edge is not None
    assert edge.confidence is Confidence.HIGH
    assert "Cabecera server: cloudflare" in edge.evidence


def test_aws_without_cloudfront_signal_is_not_checked() -> None:
    edge = assess_edge([AWS_IP])
    assert edge is not None
    assert edge.status is WafStatus.UNKNOWN
    assert edge.label == "No se ha podido comprobar si existe WAF"
    assert edge.ip_label == "IP de AWS"


def test_aws_with_cdn_tag_is_cloudfront() -> None:
    tagged = IpInfo(AWS_IP.ip, asns=AWS_IP.asns, orgs=AWS_IP.orgs, tags=["cdn"])
    edge = assess_edge([tagged])
    assert edge is not None
    assert edge.label == "Posible WAF · AWS CloudFront"
    assert edge.ip_providers == ["AWS CloudFront"]


def test_cname_to_provider_is_possible_waf() -> None:
    edge = assess_edge([AWS_IP], cname=["d111111abcdef8.cloudfront.net."])
    assert edge is not None
    assert edge.label == "Posible WAF · AWS CloudFront"
    assert "CNAME d111111abcdef8.cloudfront.net" in edge.evidence


def test_cloudflare_ns_alone_does_not_count() -> None:
    edge = assess_edge([OVH_IP], ns=["ana.ns.cloudflare.com."])
    assert edge is not None
    assert edge.status is WafStatus.UNKNOWN
    assert any("DNS gestionado por Cloudflare" in e for e in edge.evidence)


def test_appliance_cookie_on_hosting_ip_is_possible_waf() -> None:
    edge = assess_edge([OVH_IP], http_headers=headers(cookies=("TS01a2b3c4",)))
    assert edge is not None
    assert edge.label == "Posible WAF · F5 BIG-IP ASM"
    assert edge.ip_label == "IP de OVH"


def test_mixed_proxy_and_hosting_ips_is_not_checked() -> None:
    edge = assess_edge([CLOUDFLARE_IP, OVH_IP])
    assert edge is not None
    assert edge.status is WafStatus.UNKNOWN
    assert "Solo parte de las IPs pertenecen a un proveedor con WAF" in edge.evidence


def test_private_ips() -> None:
    edge = assess_edge([IpInfo("10.36.252.29")])
    assert edge is not None
    assert edge.private
    assert edge.ip_label == "IP privada"
    assert edge.status is WafStatus.UNKNOWN


def test_host_without_ips_is_not_assessed() -> None:
    assert assess_edge([]) is None


def test_unknown_org_uses_its_name() -> None:
    provider = ip_provider(IpInfo("185.10.0.1", asns=["AS64500"], orgs=["COMBELL-AS Combell NV"]))
    assert provider is not None
    assert provider.name == "Combell NV"
    assert not provider.proxy


def test_linode_is_hosting_not_akamai_proxy() -> None:
    provider = ip_provider(IpInfo("172.105.0.1", asns=["AS63949"], orgs=["Akamai Connected Cloud"]))
    assert provider is not None
    assert not provider.proxy


def test_org_name() -> None:
    assert org_name("CLOUDFLARENET - Cloudflare, Inc.") == "Cloudflare, Inc."
    assert org_name("OVH OVH SAS") == "OVH SAS"
    assert org_name("Some Org") == "Some Org"


def test_labels_never_claim_presence_or_absence() -> None:
    cases = [[CLOUDFLARE_IP], [OVH_IP], [AWS_IP], [IpInfo("10.0.0.1")], [CLOUDFLARE_IP, OVH_IP]]
    for ips in cases:
        edge = assess_edge(ips)
        assert edge is not None
        text = edge.label.lower()
        assert "sin waf" not in text and "con waf" not in text and "protegido" not in text


# Integración con el escaneo


def entity(entity_type: EntityType, value: str, **attributes: object) -> Entity:
    return Entity(type=entity_type, value=value, attributes=attributes)


def link(a: Entity, kind: RelationType, b: Entity) -> Relation:
    return Relation(from_ref=a.ref, type=kind, to_ref=b.ref)


def build(store: Store, org_label: str = "OVH OVH SAS") -> str:
    scan = store.create_scan("example.com")
    store.update_scan(scan.id, status=ScanStatus.DONE)
    root = entity(EntityType.DOMAIN, "example.com")
    origin = entity(EntityType.SUBDOMAIN, "origin.example.com")
    internal = entity(EntityType.SUBDOMAIN, "grafana.example.com")
    cf_ip = entity(EntityType.IP, "104.20.44.74", tags=["cdn"])
    ovh_ip = entity(EntityType.IP, "51.15.0.1")
    private_ip = entity(EntityType.IP, "10.0.0.5")
    cf_asn = entity(EntityType.ASN, "AS13335")
    ovh_asn = entity(EntityType.ASN, "AS64511")
    cf_org = entity(EntityType.ORG, "CLOUDFLARENET - Cloudflare, Inc.")
    ovh_org = entity(EntityType.ORG, org_label)
    store.save_result(
        scan.id,
        "test",
        ModuleResult(
            entities=[root, origin, internal, cf_ip, ovh_ip, private_ip, cf_asn, ovh_asn, cf_org,
                      ovh_org],
            relations=[
                link(root, RelationType.HAS_SUBDOMAIN, origin),
                link(root, RelationType.HAS_SUBDOMAIN, internal),
                link(root, RelationType.RESOLVES_TO, cf_ip),
                link(origin, RelationType.RESOLVES_TO, ovh_ip),
                link(internal, RelationType.RESOLVES_TO, private_ip),
                link(cf_ip, RelationType.BELONGS_TO_ASN, cf_asn),
                link(ovh_ip, RelationType.BELONGS_TO_ASN, ovh_asn),
                link(cf_asn, RelationType.OWNED_BY, cf_org),
                link(ovh_asn, RelationType.OWNED_BY, ovh_org),
            ],
        ),
    )  # fmt: skip
    return scan.id


def test_outside_proxy_only_for_public_hosts(store: Store) -> None:
    index = ScanIndex(store, build(store))
    assert index.outside_proxy("subdomain:origin.example.com")
    assert not index.outside_proxy("subdomain:grafana.example.com")  # IP privada
    assert not index.outside_proxy("domain:example.com")


def test_host_panel_shows_waf_and_provider(store: Store) -> None:
    index = ScanIndex(store, build(store))
    insights = index.insights("domain:example.com")
    assert insights is not None
    assert ("WAF", "Posible WAF · Cloudflare") in insights.info
    origin = index.insights("subdomain:origin.example.com")
    assert origin is not None
    assert "Fuera del proxy" in {c.control for c in origin.problems}


def test_overview_counts(store: Store) -> None:
    overview = edge_overview(ScanIndex(store, build(store)))
    assert overview.possible == [("Cloudflare", 1)]
    assert overview.unknown == 1
    assert overview.private == 1
    assert overview.hosts == 3
    assert overview.outside == ["origin.example.com"]
    assert overview.root_label == "Posible WAF · Cloudflare"


def test_reports_include_waf(store: Store) -> None:
    scan_id = build(store)
    compact = build_report(store, scan_id, ReportLevel.COMPACT)
    assert compact is not None
    hosts: dict[str, list[list[object]]] = compact["hosts"]  # type: ignore[assignment]
    rows = {str(r[0]): dict(zip(hosts["columns"], r, strict=True)) for r in hosts["rows"]}
    assert rows["example.com"]["waf"] == "Posible WAF · Cloudflare (alta)"
    assert rows["example.com"]["ip_provider"] == "Cloudflare"
    assert rows["grafana.example.com"]["ip_provider"] == "IP privada"
    summary = build_report(store, scan_id, ReportLevel.SUMMARY)
    assert summary is not None
    waf: dict[str, object] = summary["waf"]  # type: ignore[assignment]
    assert waf["possible"] == {"Cloudflare": 1}
    assert waf["outside_proxy"] == ["origin.example.com"]


def test_web_tabs_show_waf(client: TestClient, store: Store) -> None:
    scan_id = build(store)
    subdomains = client.get(f"/scans/{scan_id}/tabs/subdomains").text
    assert "No se ha podido comprobar si existe WAF" in subdomains
    assert "Posible origen fuera del proxy" in subdomains
    ips = client.get(f"/scans/{scan_id}/tabs/ips").text
    assert "Posible WAF" in ips
    summary = client.get(f"/scans/{scan_id}/tabs/summary").text
    assert "Hosts con posible WAF" in summary
    assert "Posible WAF · Cloudflare" in summary


def test_provider_name_is_escaped(client: TestClient, store: Store) -> None:
    scan_id = build(store, org_label="EVIL-AS <img src=x onerror=alert(1)>")
    page = client.get(f"/scans/{scan_id}/tabs/ips").text
    assert "<img src=x" not in page
    assert "&lt;img src=x onerror=alert(1)&gt;" in page
