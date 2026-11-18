import asyncio
import re
from datetime import timedelta

import dns.exception
import dns.resolver

from reconmap.models import Contact, Entity, EntityType, ModuleResult
from reconmap.modules.base import Context, Module, ModuleError
from reconmap.modules.dns import Resolve, resolve_with_dnspython

# Selectores DKIM habituales (lista fija y acotada, ver CLAUDE.md Fase 2c).
DKIM_SELECTORS = (
    "google",
    "selector1",
    "selector2",
    "k1",
    "k2",
    "k3",
    "mandrill",
    "default",
    "dkim",
    "mail",
    "s1",
    "s2",
    "smtp",
    "zmail",
    "protonmail",
    "protonmail2",
    "protonmail3",
    "fm1",
    "fm2",
    "fm3",
)
MAX_SPF_DOMAINS = 20
SPF_LOOKUP_TERMS = ("a", "mx", "ptr")
SPF_LOOKUP_PREFIXES = ("a:", "a/", "mx:", "mx/", "ptr:", "exists:")
TXT_SEGMENT = re.compile(r'"((?:[^"\\]|\\.)*)"')
MAILTO_LOCAL_PART = re.compile(r"mailto:[^@,;\s]+@", re.IGNORECASE)


class Mail:
    """Configuración de correo del dominio, solo con consultas DNS."""

    name = "mail"
    label = "Correo (SPF, DMARC, DKIM…)"
    accepts = frozenset({EntityType.DOMAIN})
    contact = Contact.PASSIVE
    requires_key: str | None = None
    cache_ttl = timedelta(hours=1)
    rate_limit = 10.0

    def __init__(self, resolve: Resolve = resolve_with_dnspython) -> None:
        self._resolve = resolve

    async def run(self, entity: Entity, ctx: Context) -> ModuleResult:
        async def collect() -> object:
            return await self._collect(entity.value, ctx)

        data = await ctx.cached(self, entity.value, collect)
        return ModuleResult(
            entities=[Entity(type=EntityType.DOMAIN, value=entity.value, attributes={"mail": data})]
        )

    async def _collect(self, domain: str, ctx: Context) -> dict[str, object]:
        root_txt, mx, dmarc, mta_sts, tls_rpt, bimi, ds, *dkim = await asyncio.gather(
            self.txt(domain, ctx),
            self.query(domain, "MX", ctx),
            self.txt(f"_dmarc.{domain}", ctx),
            self.txt(f"_mta-sts.{domain}", ctx),
            self.txt(f"_smtp._tls.{domain}", ctx),
            self.txt(f"default._bimi.{domain}", ctx),
            self.query(domain, "DS", ctx),
            *(self.txt(f"{s}._domainkey.{domain}", ctx) for s in DKIM_SELECTORS),
        )
        spf = [r for r in root_txt if r.lower().startswith("v=spf1")]
        lookups = await self._spf_lookups(spf[0], ctx, {domain}) if len(spf) == 1 else 0
        return {
            "mx": mx,
            "spf": spf,
            "spf_lookups": lookups,
            "dmarc": [redact_mailto(r) for r in dmarc if r.lower().startswith("v=dmarc1")],
            "dkim": {
                selector: next(r for r in records if "p=" in r.lower())
                for selector, records in zip(DKIM_SELECTORS, dkim, strict=True)
                if any("p=" in r.lower() for r in records)
            },
            "dkim_selectors_tried": len(DKIM_SELECTORS),
            "mta_sts": [r for r in mta_sts if r.lower().startswith("v=stsv1")],
            "tls_rpt": [redact_mailto(r) for r in tls_rpt if r.lower().startswith("v=tlsrptv1")],
            "bimi": [r for r in bimi if r.lower().startswith("v=bimi1")],
            "dnssec": bool(ds),
        }

    async def query(self, name: str, record_type: str, ctx: Context) -> list[str]:
        return await dns_query(self, self._resolve, name, record_type, ctx)

    async def txt(self, name: str, ctx: Context) -> list[str]:
        return await dns_txt(self, self._resolve, name, ctx)

    async def _spf_lookups(self, record: str, ctx: Context, seen: set[str]) -> int:
        """Cuenta las consultas DNS que exige el SPF (RFC 7208 §4.6.4), siguiendo
        include/redirect. `seen` evita bucles y limita los dominios consultados."""
        count = 0
        for raw in record.split()[1:]:
            term = raw.lower().lstrip("+-~?")
            if term.startswith(("include:", "redirect=")):
                count += 1
                target = re.split(r"[:=]", term, maxsplit=1)[1]
                if target in seen or "%" in target or len(seen) >= MAX_SPF_DOMAINS:
                    continue
                seen.add(target)
                nested = [r for r in await self.txt(target, ctx) if r.lower().startswith("v=spf1")]
                if len(nested) == 1:
                    count += await self._spf_lookups(nested[0], ctx, seen)
            elif term in SPF_LOOKUP_TERMS or term.startswith(SPF_LOOKUP_PREFIXES):
                count += 1
        return count


async def dns_query(
    module: Module, resolve: Resolve, name: str, record_type: str, ctx: Context
) -> list[str]:
    """Consulta DNS con rate limit del módulo que la pide. Sin respuesta = lista vacía."""
    await ctx.throttle(module)
    try:
        return await resolve(name, record_type)
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.resolver.NXDOMAIN):
        return []
    except dns.exception.Timeout as exc:
        raise ModuleError(f"Tiempo de espera agotado consultando {record_type} de {name}") from exc


async def dns_txt(module: Module, resolve: Resolve, name: str, ctx: Context) -> list[str]:
    return [join_txt(record) for record in await dns_query(module, resolve, name, "TXT", ctx)]


def redact_mailto(record: str) -> str:
    """Oculta la parte local de las direcciones de informes (regla 2): mailto:***@dominio."""
    return MAILTO_LOCAL_PART.sub("mailto:***@", record)


def join_txt(record: str) -> str:
    """dnspython devuelve los TXT como segmentos entre comillas: "v=spf1 ..." "..."."""
    segments = TXT_SEGMENT.findall(record)
    return "".join(segments) if segments else record
