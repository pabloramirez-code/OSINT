"""Problemas e información asociada de cada nodo del grafo.

Criterios objetivos y lenguaje prudente ("expuesto", "requiere verificación"): reconmap
observa y marca, no confirma vulnerabilidades. Base de las reglas de la Fase 4.
"""

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from reconmap.checks import SEVERITY_ORDER, Check, Status
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
    RelationType.HAS_CERTIFICATE,
    RelationType.ARCHIVED_URL,
]


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
        if "cdn" in tags:
            problems.append(
                Check(
                    "CDN",
                    Status.INFO,
                    "IP de una CDN: los puertos son de la CDN, no necesariamente del servidor real",
                )
            )
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
            ("Prefijo", str(ip.attributes.get("prefix") or "—")),
            ("Hosts que apuntan aquí", ", ".join(h.value for h in hosts) or "—"),
            ("Puertos abiertos", ", ".join(map(str, ports)) or "ninguno conocido"),
            ("Etiquetas", ", ".join(tags) or "—"),
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

        raw_dns = attrs.get("dns")
        dns_records = raw_dns if isinstance(raw_dns, dict) else {}
        info = [("IPs", ", ".join(i.value for i in ips) or "—")]
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


def short_label(entity: Entity) -> str:
    """Etiqueta corta para el canvas; el valor completo se ve en el panel lateral."""
    if entity.type is EntityType.PORT:
        text = entity.value.rsplit(":", 1)[-1]
    elif entity.type is EntityType.CERTIFICATE:
        text = f"cert. {str(entity.attributes.get('not_after', ''))[:10]}".strip()
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


def _strings(value: object) -> list[str]:
    return [str(item) for item in value] if isinstance(value, list) else []


def _text(value: object) -> str:
    text = ", ".join(map(str, value)) if isinstance(value, list) else str(value)
    return text if len(text) <= 300 else text[:299] + "…"
