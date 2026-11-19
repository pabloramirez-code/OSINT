"""Problemas e información asociada de cada nodo del grafo.

Criterios objetivos y lenguaje prudente ("expuesto", "requiere verificación"): reconmap
observa y marca, no confirma vulnerabilidades. Base de las reglas de la Fase 4.
"""

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from reconmap.checks import SEVERITY_ORDER, Check, Status
from reconmap.edge_assessment import (
    PRIVATE,
    EdgeAssessment,
    IpInfo,
    WafStatus,
    assess_edge,
    ip_provider,
)
from reconmap.headers_assessment import assess_host
from reconmap.mail_assessment import Risk, assess
from reconmap.models import Entity, EntityType, Relation, RelationType, utcnow
from reconmap.store import Store

ADMIN_PORTS = {22: "SSH", 23: "Telnet", 445: "SMB", 3389: "RDP", 5900: "VNC"}
CRITICAL_ADMIN_PORTS = {23, 445}
DATABASE_PORTS = {
    1433: "SQL Server",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
}
SENSITIVE_PATHS = re.compile(
    r"(/\.git(/|$)|/\.env($|[?#])|backup\.(zip|tar|gz)|\.sql($|[?#])|wp-config|/phpmyadmin)",
    re.IGNORECASE,
)
EXPIRY_SOON = timedelta(days=15)

RELATION_LABELS = {
    RelationType.HAS_SUBDOMAIN: "subdominio",
    RelationType.RESOLVES_TO: "resuelve a",
    RelationType.BELONGS_TO_ASN: "red (ASN)",
    RelationType.OWNED_BY: "propietario",
    RelationType.EXPOSES_PORT: "puerto",
    RelationType.HAS_CERTIFICATE: "certificado",
    RelationType.ARCHIVED_URL: "URL archivada",
    RelationType.CNAME_TO: "alias de",
    RelationType.USES_TECHNOLOGY: "tecnología",
    RelationType.HAS_VULNERABILITY: "CVE",
}
TYPE_LABELS = {
    EntityType.DOMAIN: "Dominio",
    EntityType.SUBDOMAIN: "Subdominio",
    EntityType.IP: "IP",
    EntityType.ASN: "Sistema autónomo",
    EntityType.ORG: "Organización",
    EntityType.PORT: "Puerto",
    EntityType.CERTIFICATE: "Certificado",
    EntityType.URL: "URL archivada",
    EntityType.CANDIDATE: "Candidato",
    EntityType.TECHNOLOGY: "Tecnología",
    EntityType.CVE: "CVE",
}
MAX_RELATED = 40
MAX_SHORT_LABEL = 30
RELATED_ORDER = [
    RelationType.RESOLVES_TO,
    RelationType.CNAME_TO,
    RelationType.HAS_SUBDOMAIN,
    RelationType.BELONGS_TO_ASN,
    RelationType.OWNED_BY,
    RelationType.EXPOSES_PORT,
    RelationType.USES_TECHNOLOGY,
    RelationType.HAS_VULNERABILITY,
    RelationType.HAS_CERTIFICATE,
    RelationType.ARCHIVED_URL,
]
CVE_ADVICE = (
    "Reportada para la versión detectada, no confirmada: comprueba la versión real y si la "
    "distribución (Ubuntu, Debian…) ya aplicó el parche sin cambiar el número de versión."
)
HIGH_CVSS = 7.0

# Palabras del nombre del host (etiquetas separadas por "." "-" "_", sin números finales).
# Solo palabras completas: "des" o "pre" darían demasiados falsos positivos.
NON_PRODUCTION = frozenset(
    {
        "dev",
        "devel",
        "develop",
        "development",
        "desarrollo",
        "desa",
        "test",
        "testing",
        "tests",
        "qa",
        "uat",
        "staging",
        "stage",
        "stg",
        "preprod",
        "preproduccion",
        "sandbox",
        "demo",
        "beta",
        "old",
        "legacy",
        "backup",
        "bak",
        "tmp",
        "temp",
        "prueba",
        "pruebas",
        "poc",
        "lab",
        "labs",
    }
)
INTERNAL_TOOLS = frozenset(
    {
        "grafana", "prometheus", "alertmanager", "kibana", "elasticsearch", "jenkins",
        "gitlab", "sonarqube", "sonar", "argocd", "portainer", "phpmyadmin", "pma", "adminer",
        "pgadmin", "rancher", "k8s", "kubernetes", "traefik", "minio", "rabbitmq", "airflow",
        "jupyter", "vault", "consul", "nexus", "harbor", "zabbix", "nagios", "webmin",
    }
)  # fmt: skip
EXPOSURE_ADVICE = (
    "Suelen tener menos parches y controles que producción, y a veces datos reales. "
    "Comprueba si debe ser público; si no, restríngelo (VPN, lista de IPs o autenticación)."
)


@dataclass(frozen=True)
class NodeInsights:
    id: str
    type: str
    title: str
    problems: list[Check] = field(default_factory=list)
    info: list[tuple[str, str]] = field(default_factory=list)
    related: list[dict[str, str]] = field(default_factory=list)

    @property
    def worst(self) -> Status | None:
        relevant = [c.status for c in self.problems if c.status in {Status.FAIL, Status.WARN}]
        return min(relevant, key=SEVERITY_ORDER.__getitem__) if relevant else None

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "type": self.type,
            "type_label": TYPE_LABELS.get(EntityType(self.type), self.type),
            "title": self.title,
            "worst": self.worst,
            "problems": [c.__dict__ for c in self.problems],
            "info": [list(item) for item in self.info],
            "related": self.related,
        }


def node_id(entity_type: str, value: str) -> str:
    return f"{entity_type}:{value}"


class ScanIndex:
    """Índices de un escaneo para responder rápido por nodo."""

    def __init__(self, store: Store, scan_id: str, now: datetime | None = None) -> None:
        self.now = now or utcnow()
        self._edges: dict[str, EdgeAssessment | None] = {}
        self.entities = {node_id(e.type, e.value): e for e in store.entities(scan_id)}
        self.outgoing: dict[str, list[Relation]] = defaultdict(list)
        self.incoming: dict[str, list[Relation]] = defaultdict(list)
        for relation in store.relations(scan_id):
            source = node_id(relation.from_ref.type, relation.from_ref.value)
            target = node_id(relation.to_ref.type, relation.to_ref.value)
            if source in self.entities and target in self.entities:
                self.outgoing[source].append(relation)
                self.incoming[target].append(relation)

    def neighbours(self, nid: str, kind: RelationType, incoming: bool = False) -> list[Entity]:
        relations = (self.incoming if incoming else self.outgoing)[nid]
        refs = [r.from_ref if incoming else r.to_ref for r in relations if r.type is kind]
        return sorted(
            {
                node_id(r.type, r.value): self.entities[node_id(r.type, r.value)] for r in refs
            }.values(),
            key=lambda e: e.value,
        )

    def insights(self, nid: str) -> NodeInsights | None:
        entity = self.entities.get(nid)
        if entity is None:
            return None
        builder = {
            EntityType.IP: self._ip,
            EntityType.DOMAIN: self._host,
            EntityType.SUBDOMAIN: self._host,
            EntityType.PORT: self._port,
            EntityType.CERTIFICATE: self._certificate,
            EntityType.URL: self._url,
            EntityType.TECHNOLOGY: self._technology,
            EntityType.CVE: self._cve,
        }.get(entity.type, self._generic)
        problems, info = builder(nid, entity)
        info.append(("Fuentes", ", ".join(sorted(entity.sources)) or "—"))
        return NodeInsights(
            id=nid,
            type=entity.type,
            title=entity.value,
            problems=problems,
            info=info,
            related=self._related(nid),
        )

    # WAF y proveedor de la IP

    def ip_info(self, ip: Entity) -> IpInfo:
        nid = node_id(ip.type, ip.value)
        asns = self.neighbours(nid, RelationType.BELONGS_TO_ASN)
        orgs = [
            o.value
            for a in asns
            for o in self.neighbours(node_id(a.type, a.value), RelationType.OWNED_BY)
        ]
        holders = [str(a.attributes["holder"]) for a in asns if a.attributes.get("holder")]
        edge_range = ip.attributes.get("edge_range")
        found = edge_range if isinstance(edge_range, dict) else {}
        return IpInfo(
            ip=ip.value,
            asns=[a.value for a in asns],
            orgs=orgs or holders,
            tags=_strings(ip.attributes.get("tags")),
            range_provider=str(found["provider"]) if found.get("provider") else None,
            range_prefix=str(found["prefix"]) if found.get("prefix") else None,
        )

    def edge(self, nid: str) -> EdgeAssessment | None:
        """Posible WAF de un host (None si no resuelve o no es un host)."""
        if nid in self._edges:
            return self._edges[nid]
        host = self.entities.get(nid)
        result = None
        if host is not None and host.type in {EntityType.DOMAIN, EntityType.SUBDOMAIN}:
            raw_dns = host.attributes.get("dns")
            dns_records = raw_dns if isinstance(raw_dns, dict) else {}
            result = assess_edge(
                [self.ip_info(ip) for ip in self.neighbours(nid, RelationType.RESOLVES_TO)],
                cname=_strings(dns_records.get("CNAME")),
                ns=_strings(dns_records.get("NS")),
                http_headers=host.attributes.get("http_headers"),
            )
        self._edges[nid] = result
        return result

    def _target(self) -> str:
        roots = [e.value for e in self.entities.values() if e.type is EntityType.DOMAIN]
        return roots[0] if roots else ""

    def root_edge_provider(self) -> str | None:
        roots = [n for n, e in self.entities.items() if e.type is EntityType.DOMAIN]
        edge = self.edge(roots[0]) if roots else None
        return edge.waf_provider if edge and edge.status is WafStatus.POSSIBLE else None

    def outside_proxy(self, nid: str) -> bool:
        """El dominio raíz pasa por un proxy con WAF y este host (otro) no."""
        entity = self.entities.get(nid)
        if entity is None or entity.type is not EntityType.SUBDOMAIN:
            return False
        edge = self.edge(nid)
        return (
            edge is not None
            and edge.status is WafStatus.UNKNOWN
            and PRIVATE not in edge.ip_providers
            and self.root_edge_provider() is not None
        )

    # Por tipo

    def _ip(self, nid: str, ip: Entity) -> tuple[list[Check], list[tuple[str, str]]]:
        ports = sorted(
            int(p.value.rsplit(":", 1)[1]) for p in self.neighbours(nid, RelationType.EXPOSES_PORT)
        )
        vulns = _strings(ip.attributes.get("vulns"))
        tags = _strings(ip.attributes.get("tags"))
        problems = [check for port in ports if (check := port_check(port))]
        problems += [
            Check(
                "CVE",
                Status.WARN,
                f"{cve} reportada por Shodan InternetDB",
                "Requiere verificar la versión real del servicio antes de darla por buena.",
            )
            for cve in vulns
        ]
        provider = ip_provider(self.ip_info(ip))
        if provider and provider.proxy:
            problems.append(
                Check(
                    "Proveedor",
                    Status.INFO,
                    f"IP de {provider.name}, proveedor con WAF: los puertos son del proxy, "
                    "no necesariamente del servidor real",
                )
            )
        elif "cdn" in tags:
            problems.append(
                Check(
                    "CDN",
                    Status.INFO,
                    "IP de una CDN: los puertos son de la CDN, no necesariamente del servidor real",
                )
            )
        problems += self._technology_problems_through(nid)
        if not any(c.status in {Status.FAIL, Status.WARN} for c in problems):
            problems.insert(0, Check("IP", Status.OK, "Sin servicios sensibles ni CVEs conocidas"))

        asns = self.neighbours(nid, RelationType.BELONGS_TO_ASN)
        orgs = [
            o
            for a in asns
            for o in self.neighbours(node_id(a.type, a.value), RelationType.OWNED_BY)
        ]
        hosts = self.neighbours(nid, RelationType.RESOLVES_TO, incoming=True)
        info = [
            ("Red (ASN)", ", ".join(a.value for a in asns) or "—"),
            ("Organización", ", ".join(o.value for o in orgs) or "—"),
            ("Proveedor de la IP", provider.name if provider else "desconocido"),
            ("Prefijo", str(ip.attributes.get("prefix") or "—")),
            ("Hosts que apuntan aquí", ", ".join(h.value for h in hosts) or "—"),
            ("Puertos abiertos", ", ".join(map(str, ports)) or "ninguno conocido"),
            ("Etiquetas", ", ".join(tags) or "—"),
            ("Tecnologías", self._technology_labels(nid)),
        ]
        others = [
            h for h in _strings(ip.attributes.get("hostnames")) if h not in {e.value for e in hosts}
        ]
        if others:
            info.append(("Otros nombres en esta IP", ", ".join(others[:10])))
        return problems, info

    def _host(self, nid: str, host: Entity) -> tuple[list[Check], list[tuple[str, str]]]:
        problems: list[Check] = []
        attrs = host.attributes
        ips = self.neighbours(nid, RelationType.RESOLVES_TO)
        if attrs.get("nxdomain"):
            problems.append(
                Check(
                    "DNS",
                    Status.INFO,
                    "No resuelve en DNS: posible nombre antiguo visto en certificados o archivos",
                )
            )
        problems += self._certificate_problems(nid, resolves=bool(ips))
        problems += self._ip_problems_through(ips)
        seen = {c.summary for c in problems}
        problems += [c for c in self._technology_problems_through(nid) if c.summary not in seen]

        headers = attrs.get("http_headers")
        if isinstance(headers, dict):
            report = assess_host(host.value, headers)
            problems += [c for c in report.checks if c.status in {Status.FAIL, Status.WARN}]

        mail = attrs.get("mail")
        if isinstance(mail, dict):
            policy = attrs.get("mta_sts_policy")
            assessment = assess(mail, policy if isinstance(policy, dict) else None)
            status = {Risk.HIGH: Status.FAIL, Risk.MEDIUM: Status.WARN}.get(
                assessment.risk, Status.OK
            )
            problems.append(
                Check(
                    "Correo",
                    status,
                    f"Riesgo de suplantación {assessment.risk.upper()}",
                    " ".join(assessment.reasons),
                )
            )

        rdap = attrs.get("rdap")
        if isinstance(rdap, dict) and rdap.get("expires"):
            problems += _domain_expiry(str(rdap["expires"]), self.now)

        if not problems:
            problems.append(
                Check("Host", Status.OK, "Sin problemas detectados con los datos disponibles")
            )
        edge = self.edge(nid)
        exposure = environment_kind(host.value, self._target())
        if exposure and ips:
            kind, word = exposure
            private_only = edge is not None and edge.private
            behind = edge is not None and edge.status is WafStatus.POSSIBLE
            problems.append(
                Check(
                    kind,
                    Status.INFO if private_only else Status.WARN,
                    f"{kind} con nombre «{word}»"
                    + (" (solo IPs privadas)" if private_only else " accesible desde Internet"),
                    EXPOSURE_ADVICE
                    + (" Pasa por un posible WAF, pero sigue siendo público." if behind else ""),
                )
            )
        if edge is not None:
            problems.append(Check("WAF", Status.INFO, edge.label, "; ".join(edge.evidence)))
            if self.outside_proxy(nid):
                problems.append(
                    Check(
                        "Fuera del proxy",
                        Status.INFO,
                        "Posible origen o servicio fuera del proxy, verificar a mano",
                        f"El dominio principal pasa por {self.root_edge_provider()}, "
                        "pero este host resuelve a IPs que no son de ese proveedor.",
                    )
                )

        raw_dns = attrs.get("dns")
        dns_records = raw_dns if isinstance(raw_dns, dict) else {}
        info = [("IPs", ", ".join(i.value for i in ips) or "—")]
        info.append(("Tecnologías", self._technology_labels(nid)))
        if edge is not None:
            info.append(("Proveedor de la IP", ", ".join(edge.ip_providers) or "desconocido"))
            info.append(("WAF", edge.label))
            if edge.confidence:
                info.append(("Confianza", edge.confidence.value))
        cname = _strings(dns_records.get("CNAME"))
        if cname:
            info.append(("Alias (CNAME)", ", ".join(cname)))
        for record in ("MX", "NS"):
            values = _strings(dns_records.get(record))
            if values:
                info.append((record, ", ".join(values)))
        if attrs.get("wildcard"):
            info.append(("Certificado comodín", f"*.{host.value}"))
        if isinstance(rdap, dict):
            info.append(("Registrador", str(rdap.get("registrar") or "—")))
            info.append(("Caduca el dominio", str(rdap.get("expires") or "—")[:10]))
        info.append(("Visto por primera vez", host.first_seen.strftime("%Y-%m-%d %H:%M:%S")))
        return problems, info

    def _port(self, nid: str, port: Entity) -> tuple[list[Check], list[tuple[str, str]]]:
        number = int(port.value.rsplit(":", 1)[1])
        check = port_check(number)
        problems = [check] if check else [Check("Puerto", Status.OK, "Puerto de uso habitual")]
        ip = port.value.rsplit(":", 1)[0]
        return problems, [
            ("IP", ip),
            ("Puerto", str(number)),
            ("Servicio típico", _service(number)),
        ]

    def _certificate(self, nid: str, cert: Entity) -> tuple[list[Check], list[tuple[str, str]]]:
        not_after = _parse_date(cert.attributes.get("not_after"))
        problems = []
        if not_after and not_after < self.now:
            problems.append(
                Check("Certificado", Status.INFO, f"Caducado el {not_after:%Y-%m-%d} (histórico)")
            )
        elif not_after:
            problems.append(
                Check("Certificado", Status.OK, f"Vigente hasta el {not_after:%Y-%m-%d}")
            )
        hosts = self.neighbours(nid, RelationType.HAS_CERTIFICATE, incoming=True)
        return problems, [
            ("Emisor", str(cert.attributes.get("issuer") or "—")),
            ("Válido desde", str(cert.attributes.get("not_before") or "—")[:10]),
            ("Válido hasta", str(cert.attributes.get("not_after") or "—")[:10]),
            ("Hosts que cubre", ", ".join(h.value for h in hosts) or "—"),
        ]

    def _url(self, nid: str, url: Entity) -> tuple[list[Check], list[tuple[str, str]]]:
        problems = []
        if SENSITIVE_PATHS.search(url.value):
            problems.append(
                Check(
                    "Ruta sensible",
                    Status.WARN,
                    "Existió una ruta sensible en el histórico",
                    "Comprueba a mano si sigue accesible.",
                )
            )
        return problems, [("URL", url.value)]

    def _technology(self, nid: str, tech: Entity) -> tuple[list[Check], list[tuple[str, str]]]:
        attrs = tech.attributes
        cves = self.neighbours(nid, RelationType.HAS_VULNERABILITY)
        scores = [s for c in cves if (s := _cvss(c)) is not None]
        kev = [c for c in cves if _kev(c)]
        high = [c for c in cves if (_cvss(c) or 0) >= HIGH_CVSS]
        name = short_label(tech)
        problems: list[Check] = []
        if kev:
            problems.append(
                Check(
                    "CVE",
                    Status.FAIL,
                    f"{name}: {len(kev)} CVE en el catálogo KEV de CISA (explotadas activamente)",
                    CVE_ADVICE,
                )
            )
        if high:
            problems.append(
                Check(
                    "CVE",
                    Status.WARN,
                    f"{name}: {len(high)} CVE reportadas con CVSS ≥ 7 (máx. {max(scores):.1f})",
                    CVE_ADVICE,
                )
            )
        lookup = attrs.get("cve_lookup")
        if not attrs.get("version"):
            problems.append(Check("CVE", Status.INFO, "Sin versión: no se buscan CVEs"))
        elif lookup and lookup != "hecho":
            problems.append(Check("CVE", Status.INFO, f"CVEs {lookup}"))
        elif cves and not problems:
            problems.append(
                Check("CVE", Status.INFO, f"{len(cves)} CVE reportadas de gravedad baja o media")
            )
        elif not cves and lookup == "hecho":
            problems.append(Check("CVE", Status.OK, "Sin CVEs publicadas en NVD para esta versión"))
        users = self.neighbours(nid, RelationType.USES_TECHNOLOGY, incoming=True)
        severities: dict[str, int] = defaultdict(int)
        for cve in cves:
            severities[_severity(cve)] += 1
        return problems, [
            ("Producto", str(attrs.get("name") or tech.value)),
            ("Versión", str(attrs.get("version") or "desconocida")),
            ("CPE", str(attrs.get("cpe") or "—")),
            ("Visto en", ", ".join(u.value for u in users[:15]) or "—"),
            (
                "CVEs",
                ", ".join(f"{n} {sev}" for sev, n in sorted(severities.items())) or "ninguna",
            ),
        ]

    def _cve(self, nid: str, cve: Entity) -> tuple[list[Check], list[tuple[str, str]]]:
        nvd = cve.attributes.get("nvd")
        data = nvd if isinstance(nvd, dict) else {}
        score = _cvss(cve)
        if _kev(cve):
            check = Check(
                "KEV", Status.FAIL, "En el catálogo KEV de CISA: explotada activamente", CVE_ADVICE
            )
        elif score is not None and score >= HIGH_CVSS:
            check = Check("CVE", Status.WARN, f"CVSS {score:.1f} ({_severity(cve)})", CVE_ADVICE)
        else:
            text = f"CVSS {score:.1f}" if score is not None else "Sin puntuación de NVD"
            check = Check("CVE", Status.INFO, text, CVE_ADVICE)
        affected = self.neighbours(nid, RelationType.HAS_VULNERABILITY, incoming=True)
        sources = []
        if cve.attributes.get("internetdb"):
            sources.append("Shodan InternetDB (por IP)")
        if data:
            sources.append("NVD (por versión de la tecnología)")
        version = data.get("cvss_version") or "?"
        return [check], [
            ("CVSS", f"{score:.1f} (v{version})" if score is not None else "—"),
            ("Gravedad", _severity(cve)),
            ("Publicada", str(data.get("published") or "—")),
            ("Resumen", str(data.get("summary") or "—")),
            ("Afecta a", ", ".join(short_label(a) for a in affected[:15]) or "—"),
            ("Reportada por", ", ".join(sources) or "—"),
            ("Ficha", f"https://nvd.nist.gov/vuln/detail/{cve.value}"),
        ]

    def _technologies_of(self, nid: str) -> list[Entity]:
        return self.neighbours(nid, RelationType.USES_TECHNOLOGY)

    def _technology_labels(self, nid: str) -> str:
        return ", ".join(short_label(t) for t in self._technologies_of(nid)) or "—"

    def _technology_problems_through(self, nid: str) -> list[Check]:
        problems = []
        for tech in self._technologies_of(nid):
            tech_insights = self.insights(node_id(tech.type, tech.value))
            if tech_insights is not None:
                problems += [
                    c for c in tech_insights.problems if c.status in {Status.FAIL, Status.WARN}
                ]
        return problems

    def _generic(self, nid: str, entity: Entity) -> tuple[list[Check], list[tuple[str, str]]]:
        info = [(key, _text(value)) for key, value in sorted(entity.attributes.items())]
        return [], info

    # Ayudas

    def _certificate_problems(self, nid: str, resolves: bool) -> list[Check]:
        certificates = self.neighbours(nid, RelationType.HAS_CERTIFICATE)
        dates = [d for c in certificates if (d := _parse_date(c.attributes.get("not_after")))]
        if not dates or not resolves:
            return []
        latest = max(dates)
        if latest < self.now:
            return [
                Check(
                    "Certificado",
                    Status.WARN,
                    f"El certificado más reciente conocido caducó el {latest:%Y-%m-%d}",
                    "Verifica el certificado que sirve hoy (modo Ligero, pestaña Web).",
                )
            ]
        if latest - self.now < EXPIRY_SOON:
            return [
                Check(
                    "Certificado",
                    Status.WARN,
                    f"El certificado más reciente conocido caduca pronto: {latest:%Y-%m-%d}",
                    "Comprueba si ya se ha renovado; la renovación puede no estar aún registrada.",
                )
            ]
        return [Check("Certificado", Status.OK, f"Certificado vigente hasta {latest:%Y-%m-%d}")]

    def _ip_problems_through(self, ips: list[Entity]) -> list[Check]:
        problems = []
        for ip in ips:
            ip_insights = self.insights(node_id(ip.type, ip.value))
            if ip_insights is None:
                continue
            for check in ip_insights.problems:
                if check.status in {Status.FAIL, Status.WARN}:
                    problems.append(
                        Check(
                            check.control,
                            check.status,
                            f"{check.summary} (en {ip.value})",
                            check.advice,
                        )
                    )
        return problems

    def _related(self, nid: str) -> list[dict[str, str]]:
        """Vecinos ordenados por importancia: IPs y alias antes que certificados o URLs."""
        links = [(r, r.to_ref, "") for r in self.outgoing[nid]]
        links += [(r, r.from_ref, "← ") for r in self.incoming[nid]]
        related = {}
        for relation, ref, arrow in links:
            target = node_id(ref.type, ref.value)
            related[(target, relation.type, arrow)] = {
                "id": target,
                "label": short_label(self.entities[target]),
                "relation": arrow + RELATION_LABELS[relation.type],
                "rank": str(RELATED_ORDER.index(relation.type)),
            }
        ordered = sorted(related.values(), key=lambda r: (r["rank"], r["label"]))
        return [{k: v for k, v in r.items() if k != "rank"} for r in ordered[:MAX_RELATED]]


@dataclass(frozen=True)
class EdgeOverview:
    """Recuento de posible WAF y proveedores de IP de los hosts que resuelven."""

    possible: list[tuple[str, int]]
    unknown: int
    private: int
    providers: list[tuple[str, int]]
    outside: list[str]
    root_label: str | None

    @property
    def possible_total(self) -> int:
        return sum(n for _, n in self.possible)

    @property
    def hosts(self) -> int:
        return self.possible_total + self.unknown + self.private


def edge_overview(index: ScanIndex) -> EdgeOverview:
    possible: Counter[str] = Counter()
    providers: Counter[str] = Counter()
    unknown = private = 0
    root_label: str | None = None
    outside: list[str] = []
    for nid, entity in sorted(index.entities.items()):
        edge = index.edge(nid)
        if edge is None:
            continue
        if entity.type is EntityType.DOMAIN:
            root_label = edge.label
        providers.update(edge.ip_providers)
        if edge.status is WafStatus.POSSIBLE:
            possible[str(edge.waf_provider)] += 1
        elif edge.private:
            private += 1
        else:
            unknown += 1
        if index.outside_proxy(nid):
            outside.append(entity.value)
    return EdgeOverview(
        possible=possible.most_common(),
        unknown=unknown,
        private=private,
        providers=[(name, n) for name, n in providers.most_common() if name != PRIVATE],
        outside=outside,
        root_label=root_label,
    )


def environment_kind(host: str, target: str) -> tuple[str, str] | None:
    """("Entorno no productivo", "staging") para staging.ejemplo.com; None si no lo parece."""
    name = host.removesuffix(target).rstrip(".") if target else host
    words = [re.sub(r"\d+$", "", w) for w in re.split(r"[.\-_]", name.lower()) if w]
    for word in words:
        if word in NON_PRODUCTION:
            return "Entorno no productivo", word
    for word in words:
        if word in INTERNAL_TOOLS:
            return "Herramienta interna", word
    return None


def short_label(entity: Entity) -> str:
    """Etiqueta corta para el canvas; el valor completo se ve en el panel lateral."""
    if entity.type is EntityType.PORT:
        text = entity.value.rsplit(":", 1)[-1]
    elif entity.type is EntityType.CERTIFICATE:
        text = f"cert. {str(entity.attributes.get('not_after', ''))[:10]}".strip()
    elif entity.type is EntityType.TECHNOLOGY:
        name = str(entity.attributes.get("name") or entity.value)
        version = entity.attributes.get("version")
        text = f"{name} {version}" if version else name
    else:
        text = entity.value
    return text if len(text) <= MAX_SHORT_LABEL else text[: MAX_SHORT_LABEL - 1] + "…"


def port_check(port: int) -> Check | None:
    if port in DATABASE_PORTS:
        return Check(
            "Base de datos expuesta",
            Status.FAIL,
            f"{DATABASE_PORTS[port]} ({port}) accesible desde Internet",
            "Las bases de datos no deberían ser accesibles públicamente; limita el acceso por red.",
        )
    if port in ADMIN_PORTS:
        return Check(
            "Administración expuesta",
            Status.FAIL if port in CRITICAL_ADMIN_PORTS else Status.WARN,
            f"{ADMIN_PORTS[port]} ({port}) accesible desde Internet",
            "Restringe el acceso (VPN o lista de IPs) y comprueba que exige autenticación fuerte.",
        )
    return None


def _service(port: int) -> str:
    common = {
        80: "HTTP",
        443: "HTTPS",
        53: "DNS",
        25: "SMTP",
        8080: "HTTP alternativo",
        8443: "HTTPS alternativo",
    }
    return ADMIN_PORTS.get(port) or DATABASE_PORTS.get(port) or common.get(port, "—")


def _domain_expiry(expires: str, now: datetime) -> list[Check]:
    date = _parse_date(expires)
    if date is None:
        return []
    if date < now + timedelta(days=30):
        return [
            Check(
                "Registro",
                Status.WARN,
                f"El dominio caduca el {date:%Y-%m-%d}",
                "Renueva el dominio: si caduca, cualquiera podría registrarlo.",
            )
        ]
    return []


def _parse_date(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _cvss(cve: Entity) -> float | None:
    nvd = cve.attributes.get("nvd")
    score = nvd.get("cvss") if isinstance(nvd, dict) else None
    return float(score) if isinstance(score, int | float) else None


def _kev(cve: Entity) -> bool:
    nvd = cve.attributes.get("nvd")
    return isinstance(nvd, dict) and nvd.get("kev") is True


def _severity(cve: Entity) -> str:
    nvd = cve.attributes.get("nvd")
    severity = nvd.get("severity") if isinstance(nvd, dict) else None
    return str(severity) if severity else "sin puntuación"


def _strings(value: object) -> list[str]:
    return [str(item) for item in value] if isinstance(value, list) else []


def _text(value: object) -> str:
    text = ", ".join(map(str, value)) if isinstance(value, list) else str(value)
    return text if len(text) <= 300 else text[:299] + "…"
