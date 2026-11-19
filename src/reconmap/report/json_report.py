"""Informe JSON del escaneo en tres niveles.

- extended: todo (escaneo, entidades, relaciones y progreso por módulo).
- compact: una fila por host e IP ya aplanada (sin lista de relaciones), y del resto
  solo lo relevante: certificados por emisor, rutas sensibles del Wayback, correo.
- summary: lo más importante para un primer vistazo (recuentos, riesgo de correo y
  problemas agrupados).

Los valores externos se recortan y se dejan en una sola línea en compact y summary.
"""

import re
from collections import Counter, defaultdict
from datetime import datetime
from enum import StrEnum

from reconmap.checks import Check, Status
from reconmap.edge_assessment import ip_provider
from reconmap.insights import SENSITIVE_PATHS, ScanIndex, edge_overview, node_id
from reconmap.mail_assessment import assess
from reconmap.models import Entity, EntityType, RelationType, Scan
from reconmap.store import Store


class ReportLevel(StrEnum):
    EXTENDED = "extended"
    COMPACT = "compact"
    SUMMARY = "summary"


LEVEL_LABELS = {
    ReportLevel.EXTENDED: "extendido",
    ReportLevel.COMPACT: "comprimido",
    ReportLevel.SUMMARY: "resumen",
}
HOST_TYPES = (EntityType.DOMAIN, EntityType.SUBDOMAIN)
RELEVANT = (Status.FAIL, Status.WARN)
MAX_TEXT = 200
MAX_SUMMARY_GROUPS = 15
MAX_SUMMARY_HOSTS = 10
_WHITESPACE = re.compile(r"\s+")


def build_report(
    store: Store,
    scan_id: str,
    level: ReportLevel = ReportLevel.EXTENDED,
    now: datetime | None = None,
) -> dict[str, object] | None:
    scan = store.get_scan(scan_id)
    if scan is None:
        return None
    if level is ReportLevel.EXTENDED:
        return {
            "level": level.value,
            "scan": scan.model_dump(mode="json"),
            "entities": [e.model_dump(mode="json") for e in store.entities(scan_id)],
            "relations": [r.model_dump(mode="json") for r in store.relations(scan_id)],
            "findings": [],
        }
    view = _ScanView(scan, ScanIndex(store, scan_id, now=now))
    return view.compact() if level is ReportLevel.COMPACT else view.summary()


def report_filename(target: str, scan_id: str, level: ReportLevel) -> str:
    return f"reconmap-{target}-{scan_id}-{LEVEL_LABELS[level]}.json"


class _ScanView:
    """Vista aplanada de un escaneo, común a los niveles comprimido y resumen."""

    def __init__(self, scan: Scan, index: ScanIndex) -> None:
        self.scan = scan
        self.index = index
        by_type: dict[EntityType, list[Entity]] = defaultdict(list)
        for entity in index.entities.values():
            by_type[entity.type].append(entity)
        for entities in by_type.values():
            entities.sort(key=lambda e: e.value)
        self.by_type = by_type
        hosts = [e for t in HOST_TYPES for e in by_type[t]]
        self.nxdomain = [h for h in hosts if h.attributes.get("nxdomain")]
        self.hosts = [h for h in hosts if not h.attributes.get("nxdomain")]
        self.host_problems = {h.value: self._problems(h) for h in self.hosts}

    # Niveles

    def compact(self) -> dict[str, object]:
        return {
            "level": ReportLevel.COMPACT.value,
            "scan": self._scan_info(),
            "counts": self._counts(),
            "modules": self._modules(),
            "domain": self._domain(),
            "mail": self._mail(with_checks=True),
            "asns": {a.value: _clean(self._org_of(a)) for a in self.by_type[EntityType.ASN]},
            "hosts": {
                "columns": [
                    "host",
                    "ips",
                    "ip_provider",
                    "waf",
                    "cname",
                    "asn",
                    "ports",
                    "problems",
                ],
                "rows": [self._host_row(h) for h in self.hosts],
            },
            "waf": self._waf(),
            "nxdomain": [h.value for h in self.nxdomain],
            "ips": {
                "columns": ["ip", "asn", "provider", "ports", "cves", "tags", "hosts"],
                "rows": [self._ip_row(ip) for ip in self.by_type[EntityType.IP]],
            },
            "certificates": self._certificates(),
            "wayback": {
                "total": len(self.by_type[EntityType.URL]),
                "sensitive": self._sensitive_urls(),
            },
        }

    def summary(self) -> dict[str, object]:
        groups = self._problem_groups()
        mail = self._mail(with_checks=False)
        return {
            "level": ReportLevel.SUMMARY.value,
            "scan": self._scan_info(),
            "counts": self._counts(),
            "mail_risk": mail,
            "domain_expires": self._domain().get("expires"),
            "waf": self._waf(),
            "problems": {
                "fail": len(groups[Status.FAIL]),
                "warn": len(groups[Status.WARN]),
                "top_fail": groups[Status.FAIL][:MAX_SUMMARY_GROUPS],
                "top_warn": groups[Status.WARN][:MAX_SUMMARY_GROUPS],
            },
            "certificates_attention": sum(
                1
                for checks in self.host_problems.values()
                for c in checks
                if c.control == "Certificado"
            ),
            "sensitive_urls": len(self._sensitive_urls()),
            "module_errors": {
                p.module: _clean(p.error or f"{p.errors} errores")
                for p in self.scan.progress
                if p.errors or p.error
            },
        }

    # Bloques

    def _scan_info(self) -> dict[str, object]:
        scan = self.scan
        return {
            "id": scan.id,
            "target": scan.target,
            "date": scan.created_at.strftime("%Y-%m-%d"),
            "mode": "ligero" if scan.allow_light else "pasivo",
            "depth": scan.depth,
            "status": scan.status.value,
            "host_limit_reached": scan.host_limit_reached,
        }

    def _counts(self) -> dict[str, int]:
        return {
            "hosts": len(self.hosts) + len(self.nxdomain),
            "hosts_resolving": sum(1 for h in self.hosts if self._ips_of(h)),
            "hosts_nxdomain": len(self.nxdomain),
            "ips": len(self.by_type[EntityType.IP]),
            "asns": len(self.by_type[EntityType.ASN]),
            "ports": len(self.by_type[EntityType.PORT]),
            "certificates": len(self.by_type[EntityType.CERTIFICATE]),
            "urls": len(self.by_type[EntityType.URL]),
        }

    def _modules(self) -> dict[str, object]:
        return {
            "columns": ["module", "status", "results", "requests", "errors", "last_error"],
            "rows": [
                [p.module, p.status.value, p.results, p.requests, p.errors, _clean(p.error or "")]
                for p in self.scan.progress
            ],
        }

    def _domain(self) -> dict[str, object]:
        root = self._root()
        if root is None:
            return {}
        rdap = root.attributes.get("rdap")
        dns = root.attributes.get("dns")
        info: dict[str, object] = {}
        if isinstance(rdap, dict):
            info["registrar"] = _clean(str(rdap.get("registrar") or ""))
            info["expires"] = str(rdap.get("expires") or "")[:10] or None
        if isinstance(dns, dict):
            for record in ("NS", "MX", "CAA"):
                values = dns.get(record)
                if isinstance(values, list):
                    info[record.lower()] = [_clean(str(v)) for v in values]
        return info

    def _mail(self, with_checks: bool) -> dict[str, object] | None:
        root = self._root()
        mail = root.attributes.get("mail") if root else None
        if root is None or not isinstance(mail, dict):
            return None
        policy = root.attributes.get("mta_sts_policy")
        assessment = assess(mail, policy if isinstance(policy, dict) else None)
        result: dict[str, object] = {
            "risk": assessment.risk.value,
            "reasons": [_clean(r) for r in assessment.reasons],
        }
        if with_checks:
            result["checks"] = [
                [c.control, c.status.value, _clean(c.summary)] for c in assessment.checks
            ]
        return result

    def _host_row(self, host: Entity) -> list[object]:
        ips = self._ips_of(host)
        dns = host.attributes.get("dns")
        cname = dns.get("CNAME") if isinstance(dns, dict) else None
        asns = sorted({a.value for ip in ips for a in self._asns_of(ip)})
        ports = sorted({p for ip in ips for p in self._ports_of(ip)})
        edge = self.index.edge(node_id(host.type, host.value))
        waf = ""
        if edge is not None:
            waf = edge.label + (f" ({edge.confidence.value})" if edge.confidence else "")
        return [
            host.value,
            ", ".join(ip.value for ip in ips),
            edge.ip_label.removeprefix("IP de ") if edge else "",
            waf,
            ", ".join(_clean(str(c)) for c in cname) if isinstance(cname, list) else "",
            ", ".join(asns),
            ", ".join(map(str, ports)),
            [_problem_text(c) for c in self.host_problems[host.value]],
        ]

    def _ip_row(self, ip: Entity) -> list[object]:
        nid = node_id(ip.type, ip.value)
        hosts = self.index.neighbours(nid, RelationType.RESOLVES_TO, incoming=True)
        provider = ip_provider(self.index.ip_info(ip))
        return [
            ip.value,
            ", ".join(a.value for a in self._asns_of(ip)),
            _clean(provider.name) if provider else "",
            ", ".join(map(str, self._ports_of(ip))),
            ", ".join(_strings(ip.attributes.get("vulns"))),
            ", ".join(_strings(ip.attributes.get("tags"))),
            ", ".join(h.value for h in hosts),
        ]

    def _waf(self) -> dict[str, object]:
        overview = edge_overview(self.index)
        return {
            "note": "Posible WAF = el tráfico pasa por un proveedor que lo ofrece; no se "
            "comprueba si está activo",
            "domain": overview.root_label,
            "hosts_resolving": overview.hosts,
            "possible": dict(overview.possible),
            "not_checked": overview.unknown,
            "private_only": overview.private,
            "ip_providers": dict(overview.providers),
            "outside_proxy": overview.outside,
        }

    def _certificates(self) -> dict[str, object]:
        certificates = self.by_type[EntityType.CERTIFICATE]
        issuers = Counter(_issuer_name(c) for c in certificates)
        now = self.index.now.strftime("%Y-%m-%d")
        expired = sum(1 for c in certificates if str(c.attributes.get("not_after", ""))[:10] < now)
        return {
            "total": len(certificates),
            "expired": expired,
            "by_issuer": dict(issuers.most_common()),
            "attention": [
                [host, _clean(c.summary)]
                for host, checks in self.host_problems.items()
                for c in checks
                if c.control == "Certificado"
            ],
        }

    def _sensitive_urls(self) -> list[str]:
        return [
            _clean(u.value, 500)
            for u in self.by_type[EntityType.URL]
            if SENSITIVE_PATHS.search(u.value)
        ]

    def _problem_groups(self) -> dict[Status, list[dict[str, object]]]:
        """Agrupa problemas iguales de varios hosts: "Falta HSTS" en 30 hosts es una línea."""
        grouped: dict[tuple[Status, str, str], list[str]] = defaultdict(list)
        for host, checks in self.host_problems.items():
            for check in checks:
                grouped[(check.status, check.control, _clean(check.summary))].append(host)
        result: dict[Status, list[dict[str, object]]] = {s: [] for s in RELEVANT}
        for (status, control, summary), hosts in grouped.items():
            result[status].append(
                {
                    "control": control,
                    "summary": summary,
                    "hosts_total": len(hosts),
                    "hosts": hosts[:MAX_SUMMARY_HOSTS],
                }
            )
        for groups in result.values():
            groups.sort(key=lambda g: (-int(str(g["hosts_total"])), str(g["control"])))
        return result

    # Ayudas

    def _root(self) -> Entity | None:
        return self.index.entities.get(node_id(EntityType.DOMAIN, self.scan.target))

    def _problems(self, host: Entity) -> list[Check]:
        insights = self.index.insights(node_id(host.type, host.value))
        if insights is None:
            return []
        return [c for c in insights.problems if c.status in RELEVANT]

    def _ips_of(self, host: Entity) -> list[Entity]:
        return self.index.neighbours(node_id(host.type, host.value), RelationType.RESOLVES_TO)

    def _asns_of(self, ip: Entity) -> list[Entity]:
        return self.index.neighbours(node_id(ip.type, ip.value), RelationType.BELONGS_TO_ASN)

    def _org_of(self, asn: Entity) -> str:
        orgs = self.index.neighbours(node_id(asn.type, asn.value), RelationType.OWNED_BY)
        return ", ".join(o.value for o in orgs) or str(asn.attributes.get("holder") or "")

    def _ports_of(self, ip: Entity) -> list[int]:
        ports = self.index.neighbours(node_id(ip.type, ip.value), RelationType.EXPOSES_PORT)
        return sorted(int(p.value.rsplit(":", 1)[1]) for p in ports)


def _problem_text(check: Check) -> str:
    return f"{check.status.value} · {check.control}: {_clean(check.summary)}"


def _issuer_name(certificate: Entity) -> str:
    """Organización emisora ("Let's Encrypt", "Sectigo Limited"…); si no hay O, el CN."""
    issuer = str(certificate.attributes.get("issuer") or "")
    parts = dict(
        (key.strip(), value.strip().strip('"'))
        for part in issuer.split(",")
        if "=" in part
        for key, value in [part.split("=", 1)]
    )
    return _clean(parts.get("O") or parts.get("CN") or issuer or "desconocido", 80)


def _clean(text: str, limit: int = MAX_TEXT) -> str:
    """Una sola línea y longitud acotada: el texto de las fuentes no es fiable."""
    single = _WHITESPACE.sub(" ", text).strip()
    return single if len(single) <= limit else single[: limit - 1] + "…"


def _strings(value: object) -> list[str]:
    return [_clean(str(item), 80) for item in value] if isinstance(value, list) else []
