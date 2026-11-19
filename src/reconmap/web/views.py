"""Datos que necesita cada pestaña. Las plantillas solo pintan; aquí se agrega."""

from collections import defaultdict
from dataclasses import dataclass, field

from reconmap.checks import SEVERITY_ORDER, Status
from reconmap.edge_assessment import ip_provider
from reconmap.headers_assessment import assess_host
from reconmap.insights import ScanIndex, edge_overview, node_id
from reconmap.mail_assessment import RISK_CRITERIA, MailAssessment, assess
from reconmap.models import EntityType, RelationType, Scan
from reconmap.store import Store


@dataclass(frozen=True)
class ProjectScan:
    scan: Scan
    subdomains: int
    ips: int
    mail_risk: str | None


@dataclass
class Project:
    target: str
    scans: list[ProjectScan] = field(default_factory=list)

    @property
    def latest(self) -> ProjectScan:
        return self.scans[0]


def projects(store: Store, limit: int = 500) -> list[Project]:
    """Escaneos agrupados por dominio, del más reciente al más antiguo."""
    scans = store.list_scans(limit=limit)
    counts = store.entity_counts([s.id for s in scans])
    grouped: dict[str, Project] = {}
    for scan in scans:
        roots = store.entities(scan.id, EntityType.DOMAIN)
        root = roots[0].attributes if roots else {}
        risk = _assessment(root).risk if isinstance(root.get("mail"), dict) else None
        by_type = counts.get(scan.id, {})
        grouped.setdefault(scan.target, Project(scan.target)).scans.append(
            ProjectScan(
                scan=scan,
                subdomains=by_type.get(EntityType.SUBDOMAIN, 0),
                ips=by_type.get(EntityType.IP, 0),
                mail_risk=risk,
            )
        )
    return list(grouped.values())


@dataclass(frozen=True)
class IpRow:
    ip: str
    hosts: list[str]
    asns: list[str]
    orgs: list[str]
    ports: list[int]
    vulns: list[str]
    tags: list[str]
    provider: str = "desconocido"
    proxy: bool = False


def summary(store: Store, scan: Scan, max_hosts: int) -> dict[str, object]:
    roots = store.entities(scan.id, EntityType.DOMAIN)
    root = roots[0].attributes if roots else {}

    def count(entity_type: EntityType) -> int:
        return len(store.entities(scan.id, entity_type))

    return {
        "counts": {
            "Subdominios": count(EntityType.SUBDOMAIN),
            "IPs": count(EntityType.IP),
            "ASN": count(EntityType.ASN),
            "Puertos": count(EntityType.PORT),
            "Certificados": count(EntityType.CERTIFICATE),
            "URLs archivadas": count(EntityType.URL),
        },
        "rdap": root.get("rdap"),
        "dns": root.get("dns"),
        "emails": root.get("emails_in_certificates"),
        "wayback_truncated": root.get("archived_urls_truncated", False),
        "max_hosts": max_hosts,
        "requests": [(run.label, run.requests) for run in scan.progress if run.requests],
        "mail_risk": _assessment(root).risk if isinstance(root.get("mail"), dict) else None,
        "edge": edge_overview(ScanIndex(store, scan.id)),
    }


def subdomains(store: Store, scan: Scan) -> dict[str, object]:
    ips: dict[str, list[str]] = defaultdict(list)
    for relation in store.relations(scan.id):
        if relation.type is RelationType.RESOLVES_TO:
            ips[relation.from_ref.value].append(relation.to_ref.value)
    index = ScanIndex(store, scan.id)
    subs = store.entities(scan.id, EntityType.SUBDOMAIN)
    return {
        "subdomains": subs,
        "edges": {
            sub.value: edge
            for sub in subs
            if (edge := index.edge(node_id(sub.type, sub.value))) is not None
        },
        "outside": {sub.value for sub in subs if index.outside_proxy(node_id(sub.type, sub.value))},
        "ips": {host: sorted(set(values)) for host, values in ips.items()},
        "first_seen": store.first_seen_anywhere(scan.id, EntityType.SUBDOMAIN),
    }


def ips(store: Store, scan: Scan) -> dict[str, object]:
    hosts: dict[str, set[str]] = defaultdict(set)
    asns: dict[str, set[str]] = defaultdict(set)
    ports: dict[str, set[int]] = defaultdict(set)
    orgs: dict[str, str] = {}
    for relation in store.relations(scan.id):
        source, target = relation.from_ref.value, relation.to_ref.value
        if relation.type is RelationType.RESOLVES_TO:
            hosts[target].add(source)
        elif relation.type is RelationType.BELONGS_TO_ASN:
            asns[source].add(target)
        elif relation.type is RelationType.OWNED_BY:
            orgs[source] = target
        elif relation.type is RelationType.EXPOSES_PORT:
            ports[source].add(int(target.rsplit(":", 1)[1]))

    index = ScanIndex(store, scan.id)
    rows = []
    for entity in store.entities(scan.id, EntityType.IP):
        ip = entity.value
        ip_asns = sorted(asns[ip])
        provider = ip_provider(index.ip_info(entity))
        rows.append(
            IpRow(
                ip=ip,
                hosts=sorted(hosts[ip]),
                asns=ip_asns,
                orgs=sorted({orgs[asn] for asn in ip_asns if asn in orgs}),
                ports=sorted(ports[ip]),
                vulns=_strings(entity.attributes.get("vulns")),
                tags=_strings(entity.attributes.get("tags")),
                provider=provider.name if provider else "desconocido",
                proxy=bool(provider and provider.proxy),
            )
        )
    return {"rows": rows}


def mail(store: Store, scan: Scan) -> dict[str, object]:
    roots = store.entities(scan.id, EntityType.DOMAIN)
    root = roots[0].attributes if roots else {}
    if not isinstance(root.get("mail"), dict):
        return {"assessment": None}
    return {
        "assessment": _assessment(root),
        "criteria": RISK_CRITERIA,
        "records": root["mail"],
        "allow_light": scan.allow_light,
    }


def web(store: Store, scan: Scan) -> dict[str, object]:
    hosts = [
        e
        for e in store.entities(scan.id)
        if e.type in {EntityType.DOMAIN, EntityType.SUBDOMAIN}
        and isinstance(e.attributes.get("http_headers"), dict)
    ]
    reports = [assess_host(e.value, e.attributes["http_headers"]) for e in hosts]  # type: ignore[arg-type]
    reports.sort(key=lambda r: (SEVERITY_ORDER[r.worst], r.host))
    return {"reports": reports, "allow_light": scan.allow_light, "Status": Status}


def _assessment(root: dict[str, object]) -> MailAssessment:
    data = root["mail"]
    policy = root.get("mta_sts_policy")
    return assess(
        data if isinstance(data, dict) else {},
        policy if isinstance(policy, dict) else None,
    )


def _strings(value: object) -> list[str]:
    return [str(item) for item in value] if isinstance(value, list) else []
