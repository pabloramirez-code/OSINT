from reconmap.models import Entity, EntityType, ModuleResult, Relation, RelationType
from reconmap.normalize import InvalidDomainError, normalize_domain
from reconmap.scope import in_scope


def in_scope_name(raw: str, target: str) -> str | None:
    """Normaliza un nombre que viene de una fuente y lo devuelve solo si está en ámbito."""
    try:
        name = normalize_domain(raw).name
    except InvalidDomainError:
        return None
    return name if in_scope(name, target) else None


def subdomain_result(target: str, names: set[str]) -> ModuleResult:
    root = Entity(type=EntityType.DOMAIN, value=target)
    subs = [Entity(type=EntityType.SUBDOMAIN, value=name) for name in sorted(names - {target})]
    return ModuleResult(
        entities=subs,
        relations=[
            Relation(from_ref=root.ref, type=RelationType.HAS_SUBDOMAIN, to_ref=sub.ref)
            for sub in subs
        ],
    )
