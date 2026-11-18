from datetime import timedelta

from pydantic import BaseModel, ValidationError

from reconmap.models import Contact, Entity, EntityType, ModuleResult, Relation, RelationType
from reconmap.modules.base import Context, ModuleError
from reconmap.normalize import InvalidDomainError, normalize_domain
from reconmap.scope import in_scope


class InternetDbHost(BaseModel):
    ports: list[int] = []
    hostnames: list[str] = []
    cpes: list[str] = []
    tags: list[str] = []
    vulns: list[str] = []


class InternetDb:
    name = "internetdb"
    label = "Shodan InternetDB"
    accepts = frozenset({EntityType.IP})
    contact = Contact.PASSIVE
    requires_key: str | None = None
    cache_ttl = timedelta(hours=24)
    rate_limit = 1.0

    async def run(self, entity: Entity, ctx: Context) -> ModuleResult:
        if ":" in entity.value:
            return ModuleResult()
        data = await ctx.get_json(
            self, f"https://internetdb.shodan.io/{entity.value}", allow_not_found=True
        )
        return parse_internetdb(entity.value, ctx.target, data)


def parse_internetdb(ip: str, target: str, data: object) -> ModuleResult:
    """404 en InternetDB significa "sin datos", no error."""
    if data is None:
        return ModuleResult()
    try:
        host = InternetDbHost.model_validate(data)
    except ValidationError as exc:
        raise ModuleError("Formato inesperado en la respuesta de InternetDB") from exc

    address = Entity(
        type=EntityType.IP,
        value=ip,
        attributes={
            "ports": sorted(host.ports),
            "cpes": host.cpes,
            "tags": host.tags,
            "vulns": sorted(host.vulns),
            "hostnames": host.hostnames,
        },
    )
    entities = [address]
    relations = []
    for port in sorted(host.ports):
        exposed = Entity(type=EntityType.PORT, value=f"{ip}:{port}", attributes={"port": port})
        entities.append(exposed)
        relations.append(
            Relation(from_ref=address.ref, type=RelationType.EXPOSES_PORT, to_ref=exposed.ref)
        )
    for hostname in _in_scope_hostnames(host.hostnames, target):
        sub = Entity(type=EntityType.SUBDOMAIN, value=hostname)
        entities.append(sub)
        relations.append(
            Relation(from_ref=sub.ref, type=RelationType.RESOLVES_TO, to_ref=address.ref)
        )
    return ModuleResult(entities=entities, relations=relations)


def _in_scope_hostnames(hostnames: list[str], target: str) -> list[str]:
    """Los nombres ajenos se quedan como atributo de la IP: nunca se convierten en entidades."""
    names = []
    for hostname in hostnames:
        try:
            name = normalize_domain(hostname).name
        except InvalidDomainError:
            continue
        if in_scope(name, target) and name != target:
            names.append(name)
    return names
