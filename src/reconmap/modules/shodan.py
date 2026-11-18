from datetime import timedelta

from pydantic import BaseModel, ValidationError

from reconmap.models import Contact, Entity, EntityType, ModuleResult, Relation, RelationType
from reconmap.modules.base import Context, ModuleError
from reconmap.modules.internetdb import in_scope_hostnames


class ShodanHost(BaseModel):
    ports: list[int] = []
    hostnames: list[str] = []
    org: str | None = None
    isp: str | None = None
    os: str | None = None
    tags: list[str] = []


class Shodan:
    """Solo consultas por IP (no gastan créditos de búsqueda). Sin clave no se ejecuta."""

    name = "shodan"
    label = "Shodan"
    accepts = frozenset({EntityType.IP})
    contact = Contact.PASSIVE
    requires_key: str | None = "SHODAN_API_KEY"
    cache_ttl = timedelta(hours=24)
    rate_limit = 0.5

    async def run(self, entity: Entity, ctx: Context) -> ModuleResult:
        if ":" in entity.value:
            return ModuleResult()
        data = await ctx.get_json(
            self,
            f"https://api.shodan.io/shodan/host/{entity.value}?minify=true",
            secret_params={"key": ctx.key(self)},
            allow_not_found=True,
        )
        return parse_shodan(entity.value, ctx.target, data)


def parse_shodan(ip: str, target: str, data: object) -> ModuleResult:
    if data is None:
        return ModuleResult()
    try:
        host = ShodanHost.model_validate(data)
    except ValidationError as exc:
        raise ModuleError("Formato inesperado en la respuesta de Shodan") from exc

    address = Entity(
        type=EntityType.IP,
        value=ip,
        attributes={"shodan": host.model_dump(exclude={"ports"})},
    )
    ports = [
        Entity(type=EntityType.PORT, value=f"{ip}:{port}", attributes={"port": port})
        for port in sorted(host.ports)
    ]
    subdomains = [
        Entity(type=EntityType.SUBDOMAIN, value=name)
        for name in in_scope_hostnames(host.hostnames, target)
    ]
    return ModuleResult(
        entities=[address, *ports, *subdomains],
        relations=[
            *(
                Relation(from_ref=address.ref, type=RelationType.EXPOSES_PORT, to_ref=port.ref)
                for port in ports
            ),
            *(
                Relation(from_ref=sub.ref, type=RelationType.RESOLVES_TO, to_ref=address.ref)
                for sub in subdomains
            ),
        ],
    )
