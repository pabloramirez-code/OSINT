"""Qué ha cambiado entre dos escaneos del mismo dominio.

Compara conjuntos ya guardados (sin red): subdominios, hosts que resuelven, IPs, puertos,
tecnologías, CVEs, certificados, proveedores externos, posible WAF por host, riesgo de
correo y problemas (fail/warn) por host. Lo nuevo suele ser lo que nadie ha revisado.

Si los escaneos no son comparables del todo (modo, profundidad, fuentes con error) se
avisa: una diferencia puede deberse a eso y no a un cambio real.
"""

from dataclasses import dataclass, field

from reconmap.checks import Status
from reconmap.insights import ScanIndex, node_id, short_label
from reconmap.mail_assessment import assess
from reconmap.models import Entity, EntityType, RelationType, RunStatus, Scan, ScanStatus
from reconmap.store import Store
from reconmap.third_parties import find_third_parties

HOST_TYPES = (EntityType.DOMAIN, EntityType.SUBDOMAIN)
MAX_ITEMS = 200


@dataclass
class Change:
    label: str
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    changed: list[str] = field(default_factory=list)  # "x: antes → ahora"

    @property
    def empty(self) -> bool:
        return not (self.added or self.removed or self.changed)

    def as_dict(self, limit: int = MAX_ITEMS) -> dict[str, object]:
        return {
            "label": self.label,
            "added": self.added[:limit],
            "removed": self.removed[:limit],
            "changed": self.changed[:limit],
            "counts": [len(self.added), len(self.removed), len(self.changed)],
        }


@dataclass
class ScanDiff:
    previous: Scan
    current: Scan
    changes: list[Change]
    caveats: list[str]

    @property
    def has_changes(self) -> bool:
        return any(not c.empty for c in self.changes)

    def as_dict(self, limit: int = MAX_ITEMS) -> dict[str, object]:
        return {
            "previous": {
                "id": self.previous.id,
                "date": self.previous.created_at.strftime("%Y-%m-%d %H:%M"),
            },
            "caveats": self.caveats,
            "changes": [c.as_dict(limit) for c in self.changes if not c.empty],
        }


def comparable_scans(store: Store, scan: Scan) -> list[Scan]:
    """Escaneos terminados anteriores del mismo dominio, del más reciente al más antiguo."""
    history = store.list_scans(limit=1000)  # ya ordenada: más reciente primero
    ids = [s.id for s in history]
    if scan.id not in ids:
        return []
    older = history[ids.index(scan.id) + 1 :]
    return [s for s in older if s.target == scan.target and s.status is ScanStatus.DONE]


def diff_scans(store: Store, previous: Scan, current: Scan) -> ScanDiff:
    # list_scans no trae el progreso por módulo: hace falta para los avisos.
    previous = store.get_scan(previous.id) or previous
    current = store.get_scan(current.id) or current
    old = _Snapshot(store, previous)
    new = _Snapshot(store, current)
    changes = [
        _sets("Problemas (por host)", old.problems, new.problems),
        _sets("Hosts que resuelven", old.resolving, new.resolving),
        _sets("Subdominios conocidos", old.names, new.names),
        _sets("IPs", old.values(EntityType.IP), new.values(EntityType.IP)),
        _sets("Puertos abiertos", old.values(EntityType.PORT), new.values(EntityType.PORT)),
        _sets("Tecnologías", old.technologies, new.technologies),
        _sets("CVEs", old.values(EntityType.CVE), new.values(EntityType.CVE)),
        _sets("Certificados", old.certificates, new.certificates),
        _sets("Proveedores externos", old.third_parties, new.third_parties),
        _mapping("Posible WAF", old.waf, new.waf),
        _mapping("Riesgo de correo", old.mail, new.mail),
    ]
    return ScanDiff(previous, current, changes, _caveats(previous, current))


class _Snapshot:
    def __init__(self, store: Store, scan: Scan) -> None:
        self.index = ScanIndex(store, scan.id)
        self.scan = scan
        entities = list(self.index.entities.values())
        hosts = [e for e in entities if e.type in HOST_TYPES]
        self.by_type: dict[EntityType, list[Entity]] = {}
        for entity in entities:
            self.by_type.setdefault(entity.type, []).append(entity)
        self.names = {h.value for h in hosts if h.type is EntityType.SUBDOMAIN}
        self.resolving = {h.value for h in hosts if self._ips(h)}
        self.technologies = {short_label(t) for t in self.by_type.get(EntityType.TECHNOLOGY, [])}
        self.certificates = {
            self._certificate(c) for c in self.by_type.get(EntityType.CERTIFICATE, [])
        }
        self.problems: set[str] = set()
        self.waf: dict[str, str] = {}
        for host in hosts:
            nid = node_id(host.type, host.value)
            insights = self.index.insights(nid)
            if insights:
                self.problems |= {
                    f"{host.value}: {c.summary}"
                    for c in insights.problems
                    if c.status in {Status.FAIL, Status.WARN}
                }
            edge = self.index.edge(nid)
            if edge is not None:
                self.waf[host.value] = edge.label
        root = self.index.entities.get(node_id(EntityType.DOMAIN, scan.target))
        self.mail: dict[str, str] = {}
        self.third_parties: set[str] = set()
        if root is not None:
            mail = root.attributes.get("mail")
            if isinstance(mail, dict):
                policy = root.attributes.get("mta_sts_policy")
                risk = assess(mail, policy if isinstance(policy, dict) else None).risk
                self.mail[scan.target] = str(risk).upper()
            cnames = {h.value: host_cnames(h) for h in hosts}
            found = find_third_parties(scan.target, root.attributes.get("dns"), cnames)
            self.third_parties = {p.name for p in found.providers}

    def values(self, entity_type: EntityType) -> set[str]:
        return {e.value for e in self.by_type.get(entity_type, [])}

    def _ips(self, host: Entity) -> list[Entity]:
        return self.index.neighbours(node_id(host.type, host.value), RelationType.RESOLVES_TO)

    def _certificate(self, cert: Entity) -> str:
        hosts = self.index.neighbours(
            node_id(cert.type, cert.value), RelationType.HAS_CERTIFICATE, incoming=True
        )
        expires = str(cert.attributes.get("not_after") or "")[:10] or "?"
        names = ", ".join(h.value for h in hosts[:3]) + (" …" if len(hosts) > 3 else "")
        return f"{names or cert.value} (caduca {expires})"


def _sets(label: str, old: set[str], new: set[str]) -> Change:
    return Change(label, added=sorted(new - old), removed=sorted(old - new))


def _mapping(label: str, old: dict[str, str], new: dict[str, str]) -> Change:
    changed = [
        f"{key}: {old[key]} → {new[key]}"
        for key in sorted(old.keys() & new.keys())
        if old[key] != new[key]
    ]
    return Change(label, changed=changed)


def _caveats(previous: Scan, current: Scan) -> list[str]:
    notes = []
    if previous.mode != current.mode:
        notes.append(
            f"Modo distinto ({previous.mode.capitalize()} → {current.mode.capitalize()}): "
            "lo que aportan las cabeceras y las herramientas activas no es comparable."
        )
    if previous.depth != current.depth:
        notes.append(
            f"Profundidad distinta ({previous.depth} → {current.depth}): "
            "parte de los subdominios nuevos o desaparecidos puede deberse a eso."
        )
    failed = _failed_modules(previous) | _failed_modules(current)
    if failed:
        notes.append(
            "Fuentes con errores en alguno de los dos escaneos: "
            + ", ".join(sorted(failed))
            + ". Lo que "
            "dependa de ellas puede aparecer como cambio sin serlo."
        )
    new_sources = {p.label for p in current.progress} - {p.label for p in previous.progress}
    if new_sources:
        notes.append(
            "Fuentes que no existían en el escaneo anterior: "
            + ", ".join(sorted(new_sources))
            + ". Todo lo que aportan aparece como nuevo."
        )
    if previous.host_limit_reached or current.host_limit_reached:
        notes.append("Alguno de los dos escaneos alcanzó el tope de hosts.")
    return notes


def _failed_modules(scan: Scan) -> set[str]:
    return {p.label for p in scan.progress if p.errors or p.status is RunStatus.FAILED}


def host_cnames(host: Entity) -> list[str]:
    records = host.attributes.get("dns")
    return _strings(records.get("CNAME")) if isinstance(records, dict) else []


def _strings(value: object) -> list[str]:
    return [str(v) for v in value] if isinstance(value, list) else []
