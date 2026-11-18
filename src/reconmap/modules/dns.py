import asyncio
from collections.abc import Awaitable, Callable
from datetime import timedelta

import dns.asyncresolver
import dns.exception
import dns.resolver

from reconmap.models import Contact, Entity, EntityType, ModuleResult, Relation, RelationType
from reconmap.modules.base import Context, ModuleError
from reconmap.normalize import InvalidDomainError, normalize_domain
from reconmap.scope import in_scope

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "CAA")

Resolve = Callable[[str, str], Awaitable[list[str]]]


async def resolve_with_dnspython(name: str, record_type: str) -> list[str]:
    answer = await dns.asyncresolver.resolve(name, record_type, lifetime=10)
    return [record.to_text() for record in answer]


class Dns:
    name = "dns"
    label = "DNS"
    accepts = frozenset({EntityType.DOMAIN, EntityType.SUBDOMAIN})
    contact = Contact.PASSIVE
    requires_key: str | None = None
    cache_ttl = timedelta(hours=1)
    rate_limit = 10.0

    def __init__(self, resolve: Resolve = resolve_with_dnspython) -> None:
        self._resolve = resolve

    async def run(self, entity: Entity, ctx: Context) -> ModuleResult:
        async def lookup_all() -> object:
            answers = await asyncio.gather(
                *(self._lookup(entity.value, t, ctx) for t in RECORD_TYPES)
            )
            return dict(zip(RECORD_TYPES, answers, strict=True))

        records = await ctx.cached(self, entity.value, lookup_all)
        if not isinstance(records, dict):
            raise ModuleError("Caché DNS corrupta")
        return build_dns_result(entity, records, ctx.target)

    async def _lookup(self, name: str, record_type: str, ctx: Context) -> list[str]:
        await ctx.throttle(self)
        try:
            return await self._resolve(name, record_type)
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return []
        except dns.resolver.NXDOMAIN as exc:
            raise ModuleError(f"NXDOMAIN: {name} no existe") from exc
        except dns.exception.Timeout as exc:
            raise ModuleError(f"Tiempo de espera agotado consultando {record_type}") from exc


def build_dns_result(entity: Entity, records: dict[str, list[str]], target: str) -> ModuleResult:
    host = Entity(type=entity.type, value=entity.value, attributes={"dns": records})
    entities = [host]
    relations = []

    for ip in records.get("A", []) + records.get("AAAA", []):
        address = Entity(type=EntityType.IP, value=ip)
        entities.append(address)
        relations.append(
            Relation(from_ref=host.ref, type=RelationType.RESOLVES_TO, to_ref=address.ref)
        )

    for alias in records.get("CNAME", []):
        try:
            alias_name = normalize_domain(alias).name
        except InvalidDomainError:
            continue
        if in_scope(alias_name, target):
            cname = Entity(type=EntityType.SUBDOMAIN, value=alias_name)
            entities.append(cname)
            relations.append(
                Relation(from_ref=host.ref, type=RelationType.CNAME_TO, to_ref=cname.ref)
            )

    return ModuleResult(entities=entities, relations=relations)
