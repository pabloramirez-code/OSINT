import asyncio
from collections.abc import Awaitable, Callable, Sequence
from datetime import timedelta

import dns.asyncresolver
import dns.exception
import dns.resolver

from reconmap.models import Contact, Entity, EntityType, ModuleResult, Relation, RelationType
from reconmap.modules.base import Context, ModuleError
from reconmap.normalize import InvalidDomainError, normalize_domain
from reconmap.scope import in_scope

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "CAA")
DNS_LIFETIME_SECONDS = 10.0

Resolve = Callable[[str, str], Awaitable[list[str]]]


class NxDomainError(ModuleError):
    pass


def make_resolver(servers: Sequence[str] = ()) -> Resolve:
    """Resolvedor DNS con un reintento ante timeout. Sin `servers` usa los del sistema;
    con ellos (RECONMAP_DNS_SERVERS) ignora la configuración del sistema."""
    resolver = dns.asyncresolver.Resolver(configure=not servers)
    if servers:
        resolver.nameservers = list(servers)

    async def resolve(name: str, record_type: str) -> list[str]:
        for attempt in range(2):
            try:
                answer = await resolver.resolve(name, record_type, lifetime=DNS_LIFETIME_SECONDS)
            except dns.exception.Timeout:
                if attempt:
                    raise
                continue
            return [record.to_text() for record in answer]
        raise AssertionError("unreachable")

    return resolve


class Dns:
    name = "dns"
    label = "DNS"
    accepts = frozenset({EntityType.DOMAIN, EntityType.SUBDOMAIN})
    contact = Contact.PASSIVE
    requires_key: str | None = None
    cache_ttl = timedelta(hours=1)
    rate_limit = 10.0

    def __init__(self, resolve: Resolve | None = None) -> None:
        self._resolve = resolve or make_resolver()

    async def run(self, entity: Entity, ctx: Context) -> ModuleResult:
        async def lookup_all() -> object:
            answers = await asyncio.gather(
                *(self._lookup(entity.value, t, ctx) for t in RECORD_TYPES)
            )
            return dict(zip(RECORD_TYPES, answers, strict=True))

        try:
            records = await ctx.cached(self, entity.value, lookup_all)
        except NxDomainError:
            if entity.type is EntityType.DOMAIN:
                raise
            return ModuleResult(
                entities=[
                    Entity(type=entity.type, value=entity.value, attributes={"nxdomain": True})
                ]
            )
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
            raise NxDomainError(f"NXDOMAIN: {name} no existe") from exc
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
