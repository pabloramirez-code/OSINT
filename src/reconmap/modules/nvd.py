"""CVEs publicadas para una tecnología con versión exacta (NVD API 2.0, pasivo).

Consulta `cpeName`: NVD devuelve las CVEs cuyas configuraciones vulnerables incluyen esa
versión (también por rangos). Sin clave: 5 consultas cada 30 s; con `NVD_API_KEY`, 50.
Cada respuesta puede pesar cientos de KB: en caché solo se guarda lo que se usa.

Las CVEs son "reportadas para esa versión", no confirmadas: una distribución puede haber
corregido el fallo sin cambiar el número de versión.

This product uses the NVD API but is not endorsed or certified by the NVD.
"""

from datetime import timedelta

from reconmap.models import Contact, Entity, EntityType, ModuleResult, Relation, RelationType
from reconmap.modules.base import Context, ModuleError

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
METRIC_ORDER = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
MAX_SUMMARY = 400
KEY_NAME = "NVD_API_KEY"


class Nvd:
    name = "nvd"
    label = "NVD (CVEs)"
    description = "CVEs publicadas en NVD para las tecnologías detectadas con versión exacta"
    accepts = frozenset({EntityType.TECHNOLOGY})
    contact = Contact.PASSIVE
    requires_key: str | None = None  # la clave es opcional: solo acelera
    cache_ttl = timedelta(hours=24)
    timeout = 900.0  # el limitador puede hacer esperar varios minutos sin clave

    def __init__(self, has_key: bool = False, max_lookups: int = 20) -> None:
        self.rate_limit = 1.5 if has_key else 0.15
        self.max_lookups = max_lookups

    async def run(self, entity: Entity, ctx: Context) -> ModuleResult:
        cpe = entity.attributes.get("cpe")
        if not isinstance(cpe, str) or not cpe:
            return ModuleResult()  # sin versión no se buscan CVEs
        if ctx.counters[self.name] >= self.max_lookups:
            note: dict[str, object] = {
                "cve_lookup": f"no consultado: tope de {self.max_lookups} por escaneo"
            }
            return ModuleResult(entities=[_same(entity, note)])
        ctx.counters[self.name] += 1
        key = ctx.keys.get(KEY_NAME)
        data = await ctx.get_json(
            self,
            f"{NVD_URL}?cpeName={cpe}&resultsPerPage=2000",
            secret_headers={"apiKey": key} if key else None,
            reduce=reduce_nvd,
        )
        return parse_nvd(entity, data)


def reduce_nvd(data: object) -> object:
    """De la respuesta de NVD solo lo que se muestra; descarta CVEs rechazadas."""
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise ModuleError("Formato inesperado en la respuesta de NVD")
    cves = []
    for item in data["vulnerabilities"]:
        cve = item.get("cve") if isinstance(item, dict) else None
        if not isinstance(cve, dict) or cve.get("vulnStatus") == "Rejected" or not cve.get("id"):
            continue
        score, severity, version = _cvss(cve.get("metrics"))
        cves.append(
            {
                "id": str(cve["id"]).upper(),
                "published": str(cve.get("published") or "")[:10],
                "cvss": score,
                "severity": severity,
                "cvss_version": version,
                "kev": "cisaExploitAdd" in cve,
                "summary": _summary(cve.get("descriptions")),
            }
        )
    return {"total": data.get("totalResults", len(cves)), "cves": cves}


def parse_nvd(technology: Entity, data: object) -> ModuleResult:
    if not isinstance(data, dict) or not isinstance(data.get("cves"), list):
        raise ModuleError("Formato inesperado en la caché de NVD")
    entities = [_same(technology, {"cve_lookup": "hecho", "cve_total": len(data["cves"])})]
    relations = []
    for item in data["cves"]:
        if not isinstance(item, dict):
            continue
        attributes = {k: v for k, v in item.items() if k != "id"}
        cve = Entity(type=EntityType.CVE, value=str(item["id"]), attributes={"nvd": attributes})
        entities.append(cve)
        relations.append(
            Relation(from_ref=technology.ref, type=RelationType.HAS_VULNERABILITY, to_ref=cve.ref)
        )
    return ModuleResult(entities=entities, relations=relations)


def _same(entity: Entity, attributes: dict[str, object]) -> Entity:
    return Entity(type=entity.type, value=entity.value, attributes=attributes)


def _cvss(metrics: object) -> tuple[float | None, str | None, str | None]:
    """Puntuación de la métrica más moderna disponible, preferiendo la de NVD (Primary)."""
    if not isinstance(metrics, dict):
        return None, None, None
    for name in METRIC_ORDER:
        entries = metrics.get(name)
        if not isinstance(entries, list) or not entries:
            continue
        entry = next(
            (e for e in entries if isinstance(e, dict) and e.get("type") == "Primary"), entries[0]
        )
        data = entry.get("cvssData") if isinstance(entry, dict) else None
        if not isinstance(data, dict):
            continue
        score = data.get("baseScore")
        severity = data.get("baseSeverity") or entry.get("baseSeverity")  # v2: fuera de cvssData
        return (
            float(score) if isinstance(score, int | float) else None,
            str(severity).lower() if severity else None,
            str(data.get("version") or ""),
        )
    return None, None, None


def _summary(descriptions: object) -> str:
    if not isinstance(descriptions, list):
        return ""
    english = next(
        (d.get("value") for d in descriptions if isinstance(d, dict) and d.get("lang") == "en"),
        None,
    )
    text = " ".join(str(english or "").split())
    return text if len(text) <= MAX_SUMMARY else text[: MAX_SUMMARY - 1] + "…"
