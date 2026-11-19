"""Rangos IP oficiales de proveedores con WAF (pasivo: listas públicas del proveedor).

- Cloudflare: https://www.cloudflare.com/ips-v4 y /ips-v6 (texto, un CIDR por línea).
- Fastly: https://api.fastly.com/public-ip-list (JSON `addresses` / `ipv6_addresses`).
- AWS: https://ip-ranges.amazonaws.com/ip-ranges.json; solo el servicio `CLOUDFRONT`
  (no `CLOUDFRONT_ORIGIN_FACING`, que son las IPs con las que CloudFront llama al origen).

Las listas se descargan una vez (caché de 24 h) y se guardan ya procesadas en memoria;
cada IP solo se compara contra ellas. Akamai no publica lista: se queda con el ASN.
"""

import asyncio
import ipaddress
import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import timedelta

from reconmap.edge_assessment import CLOUDFLARE, CLOUDFRONT, FASTLY
from reconmap.models import Contact, Entity, EntityType, ModuleResult
from reconmap.modules.base import Context, ModuleError

CLOUDFLARE_V4 = "https://www.cloudflare.com/ips-v4"
CLOUDFLARE_V6 = "https://www.cloudflare.com/ips-v6"
FASTLY_URL = "https://api.fastly.com/public-ip-list"
AWS_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
MEMORY_TTL_SECONDS = 24 * 3600
PARTIAL_TTL_SECONDS = 600  # si alguna lista falló, se reintenta antes

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class Ranges:
    networks: list[tuple[Network, str]]
    failed: list[str]

    def match(self, ip: str) -> tuple[str, str] | None:
        """(proveedor, prefijo) del rango más específico que contiene la IP."""
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return None
        best: tuple[Network, str] | None = None
        for network, provider in self.networks:
            if (
                address.version == network.version
                and address in network
                and (best is None or network.prefixlen > best[0].prefixlen)
            ):
                best = (network, provider)
        return (best[1], str(best[0])) if best else None


class EdgeRanges:
    name = "edge_ranges"
    label = "Rangos IP de CDN/WAF"
    description = "Listas oficiales de IPs de Cloudflare, Fastly y AWS CloudFront"
    accepts = frozenset({EntityType.IP})
    contact = Contact.PASSIVE
    requires_key: str | None = None
    cache_ttl = timedelta(hours=24)
    rate_limit = 2.0

    def __init__(self) -> None:
        self._ranges: Ranges | None = None
        self._loaded_at = 0.0
        self._lock = asyncio.Lock()

    async def run(self, entity: Entity, ctx: Context) -> ModuleResult:
        ranges = await self._load(ctx)
        found = ranges.match(entity.value)
        if found is None:
            return ModuleResult()
        provider, prefix = found
        return ModuleResult(
            entities=[
                Entity(
                    type=EntityType.IP,
                    value=entity.value,
                    attributes={"edge_range": {"provider": provider, "prefix": prefix}},
                )
            ]
        )

    async def _load(self, ctx: Context) -> Ranges:
        async with self._lock:
            ttl = (
                PARTIAL_TTL_SECONDS if self._ranges and self._ranges.failed else MEMORY_TTL_SECONDS
            )
            if self._ranges is not None and time.monotonic() - self._loaded_at < ttl:
                return self._ranges
            networks: list[tuple[Network, str]] = []
            failed = []
            for label, loader in (
                (CLOUDFLARE, self._cloudflare),
                (FASTLY, self._fastly),
                (CLOUDFRONT, self._aws),
            ):
                try:
                    networks += [(n, label) for n in await loader(ctx)]
                except ModuleError:
                    failed.append(label)
            if not networks:
                raise ModuleError("No se pudo descargar ninguna lista de rangos")
            self._ranges = Ranges(networks, failed)
            self._loaded_at = time.monotonic()
            return self._ranges

    async def _cloudflare(self, ctx: Context) -> list[Network]:
        text = (
            await ctx.get_text(self, CLOUDFLARE_V4) + "\n" + await ctx.get_text(self, CLOUDFLARE_V6)
        )
        return parse_cidrs(text.split())

    async def _fastly(self, ctx: Context) -> list[Network]:
        return parse_fastly(await ctx.get_json(self, FASTLY_URL))

    async def _aws(self, ctx: Context) -> list[Network]:
        return parse_aws_cloudfront(await ctx.get_json(self, AWS_URL))


def parse_cidrs(values: Sequence[object]) -> list[Network]:
    networks = []
    for value in values:
        try:
            networks.append(ipaddress.ip_network(str(value).strip(), strict=False))
        except ValueError:
            continue
    return networks


def parse_fastly(data: object) -> list[Network]:
    if not isinstance(data, dict):
        raise ModuleError("Formato inesperado en la lista de Fastly")
    values: list[object] = []
    for key in ("addresses", "ipv6_addresses"):
        items = data.get(key)
        if isinstance(items, list):
            values += items
    return parse_cidrs(values)


def parse_aws_cloudfront(data: object) -> list[Network]:
    if not isinstance(data, dict) or not isinstance(data.get("prefixes"), list):
        raise ModuleError("Formato inesperado en la lista de AWS")
    values: list[object] = []
    for key, field in (("prefixes", "ip_prefix"), ("ipv6_prefixes", "ipv6_prefix")):
        items = data.get(key)
        if isinstance(items, list):
            values += [
                p[field] for p in items if isinstance(p, dict) and p.get("service") == "CLOUDFRONT"
            ]
    return parse_cidrs(values)
