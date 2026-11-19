import dns.resolver
import pytest
import respx
from fastapi.testclient import TestClient

from reconmap.checks import Status
from reconmap.edge_assessment import assess_edge
from reconmap.engine import Engine
from reconmap.insights import ScanIndex
from reconmap.models import (
    Entity,
    EntityType,
    ModuleResult,
    Relation,
    RelationType,
    ScanStatus,
)
from reconmap.modules.base import Context, ModuleError
from reconmap.modules.dns import Resolve
from reconmap.modules.headers import Headers
from reconmap.modules.internetdb import parse_internetdb
from reconmap.modules.nvd import NVD_URL, Nvd, reduce_nvd
from reconmap.report.graph import build_graph
from reconmap.report.json_report import ReportLevel, build_report
from reconmap.store import Store
from reconmap.technologies import from_cpe, from_header, from_http_headers, normalize_version
from tests.conftest import FakeModule, load_fixture

NGINX_CPE = "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"
XSS = "<img src=x onerror=alert(1)>"

# Detección (pura)


def test_cpe_from_internetdb() -> None:
    tech = from_cpe("cpe:/a:apache:http_server:2.4.41")
    assert tech is not None
    assert tech.label == "Apache HTTP Server 2.4.41"
    assert tech.cpe == "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"
    assert tech.key == "apache:http_server:2.4.41"


def test_openssh_update_goes_to_its_cpe_field() -> None:
    tech = from_cpe("cpe:/a:openbsd:openssh:8.9p1")
    assert tech is not None
    assert tech.label == "OpenSSH 8.9p1"
    assert tech.cpe == "cpe:2.3:a:openbsd:openssh:8.9:p1:*:*:*:*:*:*"


def test_distribution_suffix_is_dropped() -> None:
    assert normalize_version("10.11.19-MariaDB-0%2bdeb12u1") == ("10.11.19", None)
    assert normalize_version("abc") == (None, None)


def test_cpe_without_version_has_no_lookup() -> None:
    tech = from_cpe("cpe:/a:wordpress:wordpress")
    assert tech is not None
    assert tech.cpe is None
    assert tech.label == "WordPress"


def test_edge_providers_are_not_technologies() -> None:
    assert from_cpe("cpe:/a:cloudflare:cloudflare") is None
    assert from_cpe("cpe:/a:amazon:amazon_cloudfront") is None
    assert from_header("cloudflare") == []
    assert from_header("CloudFront") == []


def test_operating_system_cpe() -> None:
    tech = from_cpe("cpe:/o:fortinet:fortios:7.2.4")
    assert tech is not None and tech.cpe is not None
    assert tech.cpe.startswith("cpe:2.3:o:fortinet:fortios:7.2.4:")


def test_server_header_with_several_products() -> None:
    found = from_header("Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f")
    assert [t.label for t in found] == ["Apache HTTP Server 2.4.41", "OpenSSL 1.1.1f"]


def test_nginx_header_uses_f5_vendor() -> None:
    (tech,) = from_header("nginx/1.18.0 (Ubuntu)")
    assert tech.cpe == NGINX_CPE


def test_header_without_version_and_unknown_products() -> None:
    assert [t.label for t in from_header("nginx")] == ["nginx"]
    assert [t.label for t in from_header("Microsoft-IIS/10.0")] == ["Microsoft IIS 10.0"]
    assert [t.label for t in from_header("PHP/8.3.36, PleskLin")] == ["PHP 8.3.36", "Plesk"]
    assert from_header("MiServidor/1.0") == []


def test_headers_and_cookies() -> None:
    data = {
        "https": {
            "headers": {"server": "nginx/1.24.0", "x-powered-by": "PHP/8.1.2"},
            "cookies": [{"name": "PHPSESSID"}, {"name": "laravel_session"}],
        }
    }
    labels = sorted(t.label for t in from_http_headers(data))
    assert labels == ["Laravel", "PHP 8.1.2", "nginx 1.24.0"]


# InternetDB y cabeceras


def test_internetdb_cpes_and_vulns_become_entities() -> None:
    data = {
        "cpes": ["cpe:/a:f5:nginx:1.18.0", "cpe:/a:cloudflare:cloudflare"],
        "vulns": ["CVE-2021-23017"],
    }
    result = parse_internetdb("198.51.100.7", "example.com", data)
    techs = [e for e in result.entities if e.type is EntityType.TECHNOLOGY]
    cves = [e for e in result.entities if e.type is EntityType.CVE]
    assert [t.value for t in techs] == ["f5:nginx:1.18.0"]
    assert techs[0].attributes["cpe"] == NGINX_CPE
    assert [c.value for c in cves] == ["CVE-2021-23017"]
    kinds = {(r.type, r.to_ref.value) for r in result.relations}
    assert (RelationType.USES_TECHNOLOGY, "f5:nginx:1.18.0") in kinds
    assert (RelationType.HAS_VULNERABILITY, "CVE-2021-23017") in kinds


def resolver() -> Resolve:
    async def resolve(name: str, record_type: str) -> list[str]:
        if record_type == "A":
            return ["192.0.2.10"]
        raise dns.resolver.NXDOMAIN

    return resolve


@respx.mock
async def test_headers_module_emits_technologies_and_provider_headers(
    ctx: Context, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Headers, "rate_limit", 1000.0)
    respx.get("https://www.example.com/").respond(
        200,
        headers={"Server": "nginx/1.18.0", "CF-RAY": "8a1b2c3d4e-MAD", "X-Generator": "Drupal 10"},
    )
    respx.get("http://www.example.com/").respond(301, headers={"Location": "https://x"})
    host = Entity(type=EntityType.SUBDOMAIN, value="www.example.com")
    result = await Headers(resolver()).run(host, ctx)
    data = result.entities[0].attributes["http_headers"]
    assert data["https"]["edge_headers"] == ["cf-ray"]  # type: ignore[index]
    assert "8a1b2c3d4e" not in str(data)  # solo la presencia, nunca el valor
    techs = {e.value for e in result.entities if e.type is EntityType.TECHNOLOGY}
    assert techs == {"f5:nginx:1.18.0", "drupal:drupal:*"}
    edge = assess_edge([], http_headers=data)
    assert edge is None  # sin IPs no se evalúa, pero la cabecera sí cuenta con IPs:
    from reconmap.edge_assessment import IpInfo

    edge = assess_edge([IpInfo("198.51.100.7", orgs=["Otro hosting"])], http_headers=data)
    assert edge is not None and edge.label == "Posible WAF · Cloudflare"
    assert "Cabecera cf-ray" in edge.evidence


# NVD


def test_reduce_nvd_keeps_what_is_shown() -> None:
    data = reduce_nvd(load_fixture("nvd_f5_nginx_1.18.0.json"))
    assert isinstance(data, dict)
    cves = {c["id"]: c for c in data["cves"]}
    assert len(cves) == 6
    assert cves["CVE-2023-44487"]["kev"] is True
    assert cves["CVE-2021-23017"]["cvss"] == 7.7
    assert cves["CVE-2021-23017"]["severity"] == "high"
    assert cves["CVE-2025-23419"]["cvss_version"] == "4.0"
    assert "configurations" not in str(data)


def test_reduce_nvd_drops_rejected_and_checks_format() -> None:
    data = {"vulnerabilities": [{"cve": {"id": "CVE-2020-0001", "vulnStatus": "Rejected"}}]}
    assert reduce_nvd(data) == {"total": 0, "cves": []}
    with pytest.raises(ModuleError):
        reduce_nvd({"nope": 1})


def technology(cpe: str | None = NGINX_CPE) -> Entity:
    return Entity(
        type=EntityType.TECHNOLOGY,
        value="f5:nginx:1.18.0",
        attributes={"name": "nginx", "version": "1.18.0", "cpe": cpe},
    )


@pytest.fixture
def fast_nvd() -> Nvd:
    module = Nvd()
    module.rate_limit = 1000.0
    return module


@respx.mock
async def test_nvd_lookup_creates_cves(ctx: Context, fast_nvd: Nvd) -> None:
    route = respx.get(url__startswith=NVD_URL).respond(
        json=load_fixture("nvd_f5_nginx_1.18.0.json")
    )
    result = await fast_nvd.run(technology(), ctx)
    assert route.calls[0].request.url.params["cpeName"] == NGINX_CPE
    cves = [e for e in result.entities if e.type is EntityType.CVE]
    assert len(cves) == 6
    assert result.entities[0].attributes == {"cve_lookup": "hecho", "cve_total": 6}
    assert all(r.type is RelationType.HAS_VULNERABILITY for r in result.relations)
    await fast_nvd.run(technology(), ctx)
    assert route.call_count == 1  # caché


@respx.mock
async def test_nvd_without_version_does_not_ask(ctx: Context, fast_nvd: Nvd) -> None:
    assert (await fast_nvd.run(technology(cpe=None), ctx)).entities == []
    assert not respx.calls


@respx.mock
async def test_nvd_empty_answer(ctx: Context, fast_nvd: Nvd) -> None:
    respx.get(url__startswith=NVD_URL).respond(json=load_fixture("nvd_sin_resultados.json"))
    result = await fast_nvd.run(technology(), ctx)
    assert result.entities[0].attributes["cve_total"] == 0


@respx.mock
async def test_nvd_lookup_cap(ctx: Context) -> None:
    respx.get(url__startswith=NVD_URL).respond(json=load_fixture("nvd_sin_resultados.json"))
    module = Nvd(max_lookups=1)
    module.rate_limit = 1000.0
    await module.run(technology(), ctx)
    other = Entity(
        type=EntityType.TECHNOLOGY,
        value="php:php:8.1.2",
        attributes={"cpe": "cpe:2.3:a:php:php:8.1.2:*:*:*:*:*:*:*"},
    )
    result = await module.run(other, ctx)
    assert "tope" in str(result.entities[0].attributes["cve_lookup"])
    assert len(respx.calls) == 1


@respx.mock
async def test_nvd_key_is_sent_but_never_cached(store: Store) -> None:
    import httpx

    from reconmap.ratelimit import RateLimiter

    route = respx.get(url__startswith=NVD_URL).respond(json=load_fixture("nvd_sin_resultados.json"))
    module = Nvd(has_key=True)
    async with httpx.AsyncClient() as http:
        ctx = Context(
            http, store.cache, RateLimiter(), target="example.com", keys={"NVD_API_KEY": "SECRETA"}
        )
        await module.run(technology(), ctx)
    assert route.calls[0].request.headers["apiKey"] == "SECRETA"
    rows = store._query("SELECT key, value FROM cache")
    assert all("SECRETA" not in str(tuple(row)) for row in rows)


# Motor, grafo, interfaz e informes


async def test_engine_queues_technologies(store: Store) -> None:
    tech = technology()
    found = FakeModule("internetdb", extra=(tech,))
    lookups = FakeModule("nvd", accepts=frozenset({EntityType.TECHNOLOGY}))
    runner = Engine(store, [found, lookups])  # type: ignore[list-item]
    scan_id = runner.create_scan("example.com")
    await runner.run(scan_id)
    assert lookups.seen == ["f5:nginx:1.18.0"]


def build(store: Store, summary: str = "Resolver bug") -> str:
    scan = store.create_scan("example.com")
    store.update_scan(scan.id, status=ScanStatus.DONE)
    root = Entity(type=EntityType.DOMAIN, value="example.com")
    ip = Entity(type=EntityType.IP, value="198.51.100.7")
    tech = technology()
    tech.attributes["cve_lookup"] = "hecho"
    kev = Entity(
        type=EntityType.CVE,
        value="CVE-2023-44487",
        attributes={"nvd": {"cvss": 7.5, "severity": "high", "kev": True, "summary": summary}},
    )
    low = Entity(
        type=EntityType.CVE,
        value="CVE-2025-23419",
        attributes={"nvd": {"cvss": 5.3, "severity": "medium", "kev": False}},
    )
    store.save_result(
        scan.id,
        "test",
        ModuleResult(
            entities=[root, ip, tech, kev, low],
            relations=[
                Relation(from_ref=root.ref, type=RelationType.RESOLVES_TO, to_ref=ip.ref),
                Relation(from_ref=ip.ref, type=RelationType.USES_TECHNOLOGY, to_ref=tech.ref),
                Relation(from_ref=tech.ref, type=RelationType.HAS_VULNERABILITY, to_ref=kev.ref),
                Relation(from_ref=tech.ref, type=RelationType.HAS_VULNERABILITY, to_ref=low.ref),
            ],
        ),
    )
    return scan.id


def test_kev_marks_technology_ip_and_host(store: Store) -> None:
    index = ScanIndex(store, build(store))
    for nid in ("technology:f5:nginx:1.18.0", "ip:198.51.100.7", "domain:example.com"):
        insights = index.insights(nid)
        assert insights is not None
        assert insights.worst is Status.FAIL, nid
    cve = index.insights("cve:CVE-2023-44487")
    assert cve is not None and cve.problems[0].control == "KEV"
    assert ("Afecta a", "nginx 1.18.0") in cve.info


def test_graph_has_technology_and_cve_nodes(store: Store) -> None:
    graph = build_graph(store, build(store))
    types = {n["type"] for n in graph["nodes"]}  # type: ignore[attr-defined]
    assert {"technology", "cve"} <= types
    tech = next(n for n in graph["nodes"] if n["type"] == "technology")  # type: ignore[attr-defined]
    assert tech["short"] == "nginx 1.18.0"


def test_tech_tab(client: TestClient, store: Store) -> None:
    page = client.get(f"/scans/{build(store, summary=XSS)}/tabs/tech").text
    assert "nginx 1.18.0" in page
    assert "CVE-2023-44487" in page and "KEV" in page
    assert "https://nvd.nist.gov/vuln/detail/CVE-2023-44487" in page
    assert XSS not in page and "&lt;img src=x onerror=alert(1)&gt;" in page
    assert "no confirmadas" in page


def test_reports_include_technologies_and_cves(store: Store) -> None:
    scan_id = build(store)
    compact = build_report(store, scan_id, ReportLevel.COMPACT)
    assert compact is not None
    techs: dict[str, list[list[object]]] = compact["technologies"]  # type: ignore[assignment]
    assert techs["rows"][0][:2] == ["nginx 1.18.0", NGINX_CPE]
    cves: dict[str, object] = compact["cves"]  # type: ignore[assignment]
    rows: list[list[object]] = cves["rows"]  # type: ignore[assignment]
    assert [r[0] for r in rows] == ["CVE-2023-44487"]  # la de 5.3 solo cuenta en el total
    assert cves["total"] == 2
    summary = build_report(store, scan_id, ReportLevel.SUMMARY)
    assert summary is not None
    assert summary["technologies"] == ["nginx 1.18.0"]
    cve_summary: dict[str, object] = summary["cves"]  # type: ignore[assignment]
    assert cve_summary["kev"] == 1
    assert cve_summary["by_severity"] == {"high": 1, "medium": 1}


def test_letter_suffix_versions() -> None:
    assert normalize_version("1.1.1f") == ("1.1.1f", None)
    assert normalize_version("8.9p1") == ("8.9", "p1")
    assert normalize_version("2.4.41") == ("2.4.41", None)


def test_internetdb_drops_versionless_duplicate() -> None:
    data = {"cpes": ["cpe:/a:php:php", "cpe:/a:php:php:7.2.24"]}
    result = parse_internetdb("198.51.100.7", "example.com", data)
    techs = [e.value for e in result.entities if e.type is EntityType.TECHNOLOGY]
    assert techs == ["php:php:7.2.24"]


def test_important_cves_stay_visible_when_grouping(store: Store) -> None:
    scan_id = build(store)
    tech, extra = technology(), Entity(type=EntityType.CVE, value="CVE-2021-3618")
    store.save_result(
        scan_id,
        "test",
        ModuleResult(
            entities=[extra],
            relations=[
                Relation(from_ref=tech.ref, type=RelationType.HAS_VULNERABILITY, to_ref=extra.ref)
            ],
        ),
    )
    graph = build_graph(store, scan_id, max_nodes=3)
    ids = {n["id"] for n in graph["nodes"]}  # type: ignore[attr-defined]
    assert "cve:CVE-2023-44487" in ids  # KEV: siempre visible
    assert "cve:CVE-2025-23419" not in ids  # 5.3: dentro del grupo
    group = next(n for n in graph["nodes"] if n["id"] == "group:cve")  # type: ignore[attr-defined]
    assert group["label"] == "2 CVEs más (CVSS < 9)"
    targets = {e["target"] for e in graph["edges"]}  # type: ignore[attr-defined]
    assert {"cve:CVE-2023-44487", "group:cve"} <= targets
