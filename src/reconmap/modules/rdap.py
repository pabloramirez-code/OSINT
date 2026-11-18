from datetime import timedelta

from pydantic import BaseModel, Field, ValidationError

from reconmap.models import Contact, Entity, EntityType, ModuleResult
from reconmap.modules.base import Context, ModuleError


class RdapEvent(BaseModel):
    action: str = Field(alias="eventAction")
    date: str = Field(alias="eventDate")


class RdapEntity(BaseModel):
    roles: list[str] = []
    vcard: list[object] = Field(default=[], alias="vcardArray")


class RdapNameserver(BaseModel):
    name: str = Field(alias="ldhName")


class RdapDomain(BaseModel):
    entities: list[RdapEntity] = []
    events: list[RdapEvent] = []
    nameservers: list[RdapNameserver] = []
    status: list[str] = []


class Rdap:
    name = "rdap"
    label = "Registro (RDAP)"
    accepts = frozenset({EntityType.DOMAIN})
    contact = Contact.PASSIVE
    requires_key: str | None = None
    cache_ttl = timedelta(hours=24)
    rate_limit = 1.0

    async def run(self, entity: Entity, ctx: Context) -> ModuleResult:
        data = await ctx.get_json(self, f"https://rdap.org/domain/{entity.value}")
        return parse_rdap(entity.value, data)


def parse_rdap(target: str, data: object) -> ModuleResult:
    try:
        domain = RdapDomain.model_validate(data)
    except ValidationError as exc:
        raise ModuleError("Formato inesperado en la respuesta RDAP") from exc

    events = {event.action: event.date for event in domain.events}
    registrar = next(
        (_vcard_name(e.vcard) for e in domain.entities if "registrar" in e.roles), None
    )
    rdap = {
        "registrar": registrar,
        "registered": events.get("registration"),
        "expires": events.get("expiration"),
        "nameservers": sorted(ns.name.lower() for ns in domain.nameservers),
        "status": domain.status,
    }
    return ModuleResult(
        entities=[Entity(type=EntityType.DOMAIN, value=target, attributes={"rdap": rdap})]
    )


def _vcard_name(vcard: list[object]) -> str | None:
    """Solo se extrae el nombre (`fn`) del registrador: nunca datos de contacto (regla 2)."""
    if len(vcard) < 2 or not isinstance(vcard[1], list):
        return None
    for prop in vcard[1]:
        if isinstance(prop, list) and len(prop) == 4 and prop[0] == "fn":
            return str(prop[3]) or None
    return None
