"""Datos que necesita cada pestaña. Las plantillas solo pintan; aquí se agrega."""

from collections import defaultdict
from dataclasses import dataclass

from reconmap.mail_assessment import RISK_CRITERIA, MailAssessment, assess
from reconmap.models import EntityType, RelationType, Scan
from reconmap.store import Store


@dataclass(frozen=True)
class IpRow:
    ip: str
    hosts: list[str]
    asns: list[str]
    orgs: list[str]
    ports: list[int]
    vulns: list[str]
    tags: list[str]


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
    }


def subdomains(store: Store, scan: Scan) -> dict[str, object]:
    ips: dict[str, list[str]] = defaultdict(list)
    for relation in store.relations(scan.id):
        if relation.type is RelationType.RESOLVES_TO:
            ips[relation.from_ref.value].append(relation.to_ref.value)
    return {
        "subdomains": store.entities(scan.id, EntityType.SUBDOMAIN),
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

    rows = []
    for entity in store.entities(scan.id, EntityType.IP):
        ip = entity.value
        ip_asns = sorted(asns[ip])
        rows.append(
            IpRow(
                ip=ip,
                hosts=sorted(hosts[ip]),
                asns=ip_asns,
                orgs=sorted({orgs[asn] for asn in ip_asns if asn in orgs}),
                ports=sorted(ports[ip]),
                vulns=_strings(entity.attributes.get("vulns")),
                tags=_strings(entity.attributes.get("tags")),
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


def _assessment(root: dict[str, object]) -> MailAssessment:
    data = root["mail"]
    policy = root.get("mta_sts_policy")
    return assess(
        data if isinstance(data, dict) else {},
        policy if isinstance(policy, dict) else None,
    )


def _strings(value: object) -> list[str]:
    return [str(item) for item in value] if isinstance(value, list) else []
