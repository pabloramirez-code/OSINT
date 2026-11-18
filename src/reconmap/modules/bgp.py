from datetime import timedelta

from pydantic import BaseModel, ValidationError

from reconmap.models import Contact, Entity, EntityType, ModuleResult, Relation, RelationType
from reconmap.modules.base import Context, ModuleError

RIPESTAT = "https://stat.ripe.net/data"


class NetworkInfo(BaseModel):
    asns: list[str] = []
    prefix: str | None = None


class AsOverview(BaseModel):
    holder: str | None = None


class _Envelope[T](BaseModel):
    data: T


class Bgp:
    name = "bgp"
    label = "BGP (RIPEstat)"
    accepts = frozenset({EntityType.IP})
    contact = Contact.PASSIVE
    requires_key: str | None = None
    cache_ttl = timedelta(days=7)
    rate_limit = 4.0

    async def run(self, entity: Entity, ctx: Context) -> ModuleResult:
        raw = await ctx.get_json(self, f"{RIPESTAT}/network-info/data.json?resource={entity.value}")
        network = _parse(_Envelope[NetworkInfo], raw).data
        holders = {}
        for asn in network.asns:
            overview = await ctx.get_json(
                self, f"{RIPESTAT}/as-overview/data.json?resource=AS{asn}"
            )
            holders[asn] = _parse(_Envelope[AsOverview], overview).data.holder
        return build_bgp_result(entity.value, network, holders)


def build_bgp_result(ip: str, network: NetworkInfo, holders: dict[str, str | None]) -> ModuleResult:
    address = Entity(type=EntityType.IP, value=ip, attributes={"prefix": network.prefix})
    entities = [address]
    relations = []
    for asn in network.asns:
        holder = holders.get(asn)
        autonomous_system = Entity(
            type=EntityType.ASN, value=f"AS{asn}", attributes={"holder": holder}
        )
        entities.append(autonomous_system)
        relations.append(
            Relation(
                from_ref=address.ref, type=RelationType.BELONGS_TO_ASN, to_ref=autonomous_system.ref
            )
        )
        if holder:
            org = Entity(type=EntityType.ORG, value=holder)
            entities.append(org)
            relations.append(
                Relation(from_ref=autonomous_system.ref, type=RelationType.OWNED_BY, to_ref=org.ref)
            )
    return ModuleResult(entities=entities, relations=relations)


def _parse[T: BaseModel](model: type[T], data: object) -> T:
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        raise ModuleError("Formato inesperado en la respuesta de RIPEstat") from exc
