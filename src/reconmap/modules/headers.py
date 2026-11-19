import ssl
from datetime import timedelta

import httpx

from reconmap.config import HTTP_TIMEOUT_SECONDS, USER_AGENT
from reconmap.edge_assessment import EDGE_HEADERS
from reconmap.models import Contact, Entity, EntityType, ModuleResult, Relation, RelationType
from reconmap.modules.base import Context, ModuleError
from reconmap.modules.dns import Resolve, make_resolver
from reconmap.modules.mail import dns_query
from reconmap.technologies import TECH_HEADERS, from_http_headers

SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "server",
    "x-powered-by",
    "x-xss-protection",
)
MAX_HEADER_LENGTH = 1000
MAX_COOKIE_NAME_LENGTH = 64


class Headers:
    """Contacto ligero: como mucho 3 peticiones por host (HTTPS, HTTP y, si el certificado
    no es válido, HTTPS sin verificar). No sigue redirecciones ni lee el cuerpo."""

    name = "headers"
    label = "Cabeceras HTTP"
    description = (
        "Cabeceras de seguridad, paso de HTTP a HTTPS, certificado, cookies, tecnologías "
        "y proveedor de CDN/WAF de cada web"
    )
    accepts = frozenset({EntityType.DOMAIN, EntityType.SUBDOMAIN})
    contact = Contact.LIGHT
    requires_key: str | None = None
    cache_ttl = timedelta(hours=1)
    rate_limit = 2.0

    def __init__(self, resolve: Resolve | None = None, max_hosts: int = 50) -> None:
        self._resolve = resolve or make_resolver()
        self.max_hosts = max_hosts

    async def run(self, entity: Entity, ctx: Context) -> ModuleResult:
        if not await self._resolves(entity.value, ctx):
            return ModuleResult()
        if ctx.counters[self.name] >= self.max_hosts:
            data: object = {"skipped": f"Se alcanzó el tope de {self.max_hosts} hosts"}
        else:
            ctx.counters[self.name] += 1

            async def collect() -> object:
                return await self._collect(entity.value, ctx)

            data = await ctx.cached(self, entity.value, collect)
        host = Entity(type=entity.type, value=entity.value, attributes={"http_headers": data})
        technologies = [tech.entity() for tech in from_http_headers(data)]
        return ModuleResult(
            entities=[host, *technologies],
            relations=[
                Relation(from_ref=host.ref, type=RelationType.USES_TECHNOLOGY, to_ref=t.ref)
                for t in technologies
            ],
        )

    async def _resolves(self, host: str, ctx: Context) -> bool:
        """Sin IP no hay a quién preguntar: se comprueba por DNS (pasivo) antes de conectar."""
        for record_type in ("A", "AAAA"):
            try:
                if await dns_query(self, self._resolve, host, record_type, ctx):
                    return True
            except ModuleError:
                return False
        return False

    async def _collect(self, host: str, ctx: Context) -> dict[str, object]:
        https = await self._fetch(f"https://{host}/", ctx, verify=True)
        if "cert_error" in https:
            insecure = await self._fetch(f"https://{host}/", ctx, verify=False)
            https = {**insecure, "cert_error": https["cert_error"]}
        http = await self._fetch(f"http://{host}/", ctx, verify=True)
        return {"https": https, "http": http}

    async def _fetch(self, url: str, ctx: Context, verify: bool) -> dict[str, object]:
        await ctx.throttle(self)
        try:
            if verify:
                return await _head_of_response(ctx.http, url)
            async with httpx.AsyncClient(
                verify=False,  # noqa: S501 - decisión del usuario: leer cabeceras con certificado inválido
                timeout=HTTP_TIMEOUT_SECONDS,
                headers={"User-Agent": USER_AGENT},
            ) as insecure:
                return await _head_of_response(insecure, url)
        except httpx.ConnectError as exc:
            reason = certificate_error(exc)
            if verify and reason:
                return {"cert_error": reason}
            return {"error": "No responde"}
        except httpx.TimeoutException:
            return {"error": "Tiempo de espera agotado"}
        except httpx.HTTPError as exc:
            return {"error": f"Error de conexión ({type(exc).__name__})"}


async def _head_of_response(client: httpx.AsyncClient, url: str) -> dict[str, object]:
    """Lee estado y cabeceras sin descargar el cuerpo."""
    async with client.stream("GET", url, follow_redirects=False) as response:
        return {
            "status": response.status_code,
            "location": response.headers.get("location"),
            "headers": {
                name: response.headers[name][:MAX_HEADER_LENGTH]
                for name in (*SECURITY_HEADERS, *TECH_HEADERS)
                if name in response.headers
            },
            "edge_headers": sorted(name for name in EDGE_HEADERS if name in response.headers),
            "cookies": cookie_flags(response.headers.get_list("set-cookie")),
        }


def cookie_flags(raw_cookies: list[str]) -> list[dict[str, object]]:
    """Nombre y atributos de cada cookie; el valor nunca se guarda (puede ser una sesión)."""
    cookies = []
    for raw in raw_cookies:
        name = raw.split("=", 1)[0].strip()[:MAX_COOKIE_NAME_LENGTH]
        attributes = [part.strip().lower() for part in raw.split(";")[1:]]
        samesite = next((a.split("=", 1)[1] for a in attributes if a.startswith("samesite=")), None)
        cookies.append(
            {
                "name": name,
                "secure": "secure" in attributes,
                "httponly": "httponly" in attributes,
                "samesite": samesite,
            }
        )
    return cookies


def certificate_error(exc: BaseException) -> str | None:
    current: BaseException | None = exc
    while current is not None:
        if isinstance(current, ssl.SSLCertVerificationError):
            return getattr(current, "verify_message", None) or "certificado no verificable"
        current = current.__cause__ or current.__context__
    return "certificado no verificable" if "CERTIFICATE_VERIFY_FAILED" in str(exc) else None
