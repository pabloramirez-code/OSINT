"""Datos que necesita cada pestaña. Las plantillas solo pintan; aquí se agrega."""

import re
from collections import defaultdict
from dataclasses import dataclass, field

from reconmap.checks import SEVERITY_ORDER, Status
from reconmap.edge_assessment import ip_provider
from reconmap.headers_assessment import assess_host
from reconmap.insights import (
    ScanIndex,
    edge_overview,
    environment_kind,
    node_id,
    short_label,
)
from reconmap.mail_assessment import RISK_CRITERIA, MailAssessment, assess
from reconmap.models import Entity, EntityType, RelationType, Scan
from reconmap.report.diff import comparable_scans, diff_scans, host_cnames
from reconmap.store import Store
from reconmap.third_parties import ThirdParties, find_third_parties


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
        "third_parties": third_parties(store, scan),
        "changes": _changes_overview(store, scan),
    }


def third_parties(store: Store, scan: Scan) -> ThirdParties:
    roots = store.entities(scan.id, EntityType.DOMAIN)
    root_dns = roots[0].attributes.get("dns") if roots else None
    hosts = [*roots, *store.entities(scan.id, EntityType.SUBDOMAIN)]
    return find_third_parties(scan.target, root_dns, {h.value: host_cnames(h) for h in hosts})


def changes(store: Store, scan: Scan, against: str | None = None) -> dict[str, object]:
    """Comparación con un escaneo anterior del mismo dominio (por defecto, el último)."""
    options = comparable_scans(store, scan)
    previous = next((s for s in options if s.id == against), options[0] if options else None)
    return {
        "options": options,
        "previous": previous,
        "diff": diff_scans(store, previous, scan) if previous else None,
    }


def _changes_overview(store: Store, scan: Scan) -> dict[str, object] | None:
    options = comparable_scans(store, scan)
    if not options:
        return None
    diff = diff_scans(store, options[0], scan)
    return {
        "previous": options[0],
        "rows": [
            (c.label, len(c.added), len(c.removed), len(c.changed))
            for c in diff.changes
            if not c.empty
        ],
        "caveats": len(diff.caveats),
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
        "exposure": {
            sub.value: kind
            for sub in subs
            if sub.value in ips and (kind := environment_kind(sub.value, scan.target))
        },
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


CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")


@dataclass(frozen=True)
class CveRow:
    id: str
    cvss: float | None
    severity: str
    kev: bool
    published: str
    summary: str
    link: bool  # solo se enlaza a NVD si el identificador tiene formato de CVE
    affected: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class TechRow:
    label: str
    version: str | None
    cpe: str | None
    seen_on: list[str]
    lookup: str
    cves: list[CveRow]

    @property
    def max_cvss(self) -> float | None:
        scores = [c.cvss for c in self.cves if c.cvss is not None]
        return max(scores) if scores else None

    @property
    def kev(self) -> int:
        return sum(c.kev for c in self.cves)


def technologies(store: Store, scan: Scan) -> dict[str, object]:
    """Tecnologías detectadas y CVEs reportadas para su versión (NVD) o su IP (InternetDB)."""
    index = ScanIndex(store, scan.id)
    rows = []
    linked: set[str] = set()
    for entity in store.entities(scan.id, EntityType.TECHNOLOGY):
        nid = node_id(entity.type, entity.value)
        cves = index.neighbours(nid, RelationType.HAS_VULNERABILITY)
        linked.update(c.value for c in cves)
        attrs = entity.attributes
        version = attrs.get("version")
        lookup = str(attrs.get("cve_lookup") or ("sin versión" if not version else "pendiente"))
        rows.append(
            TechRow(
                label=short_label(entity),
                version=str(version) if version else None,
                cpe=str(attrs["cpe"]) if attrs.get("cpe") else None,
                seen_on=[
                    u.value
                    for u in index.neighbours(nid, RelationType.USES_TECHNOLOGY, incoming=True)
                ],
                lookup=lookup,
                cves=_cve_rows(index, cves),
            )
        )
    rows.sort(key=lambda r: (-r.kev, -(r.max_cvss or 0), r.label))
    by_ip = [
        c
        for c in store.entities(scan.id, EntityType.CVE)
        if c.attributes.get("internetdb") and c.value not in linked
    ]
    return {
        "rows": rows,
        "ip_cves": _cve_rows(index, by_ip, with_affected=True),
        "total_cves": len(store.entities(scan.id, EntityType.CVE)),
    }


def _cve_rows(index: ScanIndex, cves: list[Entity], with_affected: bool = False) -> list[CveRow]:
    rows = []
    for cve in cves:
        raw = cve.attributes.get("nvd")
        nvd = raw if isinstance(raw, dict) else {}
        score = nvd.get("cvss")
        affected = (
            [
                a.value
                for a in index.neighbours(
                    node_id(cve.type, cve.value), RelationType.HAS_VULNERABILITY, incoming=True
                )
            ]
            if with_affected
            else []
        )
        rows.append(
            CveRow(
                id=cve.value,
                cvss=float(score) if isinstance(score, int | float) else None,
                severity=str(nvd.get("severity") or "sin puntuación"),
                kev=nvd.get("kev") is True,
                published=str(nvd.get("published") or ""),
                summary=str(nvd.get("summary") or ""),
                link=bool(CVE_ID.match(cve.value)),
                affected=affected,
            )
        )
    rows.sort(key=lambda c: (not c.kev, -(c.cvss or 0), c.id))
    return rows


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
