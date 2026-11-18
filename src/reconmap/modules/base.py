from collections import Counter
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Protocol

import httpx

from reconmap.cache import MISSING, Cache
from reconmap.models import Contact, Entity, EntityType, ModuleResult
from reconmap.ratelimit import RateLimiter


class ModuleError(Exception):
    """Fallo esperado de una fuente (HTTP 5xx, timeout, NXDOMAIN...). Se muestra en la interfaz."""


class Module(Protocol):
    name: str
    label: str
    accepts: frozenset[EntityType]
    contact: Contact
    requires_key: str | None
    cache_ttl: timedelta
    rate_limit: float

    async def run(self, entity: Entity, ctx: "Context") -> ModuleResult: ...


@dataclass
class Context:
    """Lo único que un módulo puede usar para salir a la red: siempre con caché y rate limit.

    Los `secret_*` (claves de API) se envían en la petición pero nunca forman parte de la
    clave de caché ni de los mensajes de error.
    """

    http: httpx.AsyncClient
    cache: Cache
    limiter: RateLimiter
    target: str
    keys: Mapping[str, str] = field(default_factory=dict)
    requests: Counter[str] = field(default_factory=Counter)

    def key(self, module: Module) -> str:
        if module.requires_key is None or module.requires_key not in self.keys:
            raise ModuleError(f"Falta la clave {module.requires_key}")
        return self.keys[module.requires_key]

    async def throttle(self, module: Module) -> None:
        await self.limiter.acquire(module.name, module.rate_limit)
        self.requests[module.name] += 1

    async def cached(
        self, module: Module, key: str, fetch: Callable[[], Awaitable[object]]
    ) -> object:
        cache_key = f"{module.name}:{key}"
        hit = self.cache.get(cache_key)
        if hit is not MISSING:
            return hit
        value = await fetch()
        self.cache.set(cache_key, value, module.cache_ttl)
        return value

    async def get_json(
        self,
        module: Module,
        url: str,
        *,
        secret_params: Mapping[str, str] | None = None,
        secret_headers: Mapping[str, str] | None = None,
        allow_not_found: bool = False,
    ) -> object:
        """Devuelve el JSON de `url`, o None si es 404 y `allow_not_found`."""

        async def fetch() -> object:
            response = await self._request(
                module, url, secret_params, secret_headers, allow_not_found
            )
            if response is None:
                return None
            try:
                data: object = response.json()
            except ValueError as exc:
                raise ModuleError("La respuesta no es JSON válido") from exc
            return data

        return await self.cached(module, url, fetch)

    async def get_text(
        self,
        module: Module,
        url: str,
        *,
        secret_params: Mapping[str, str] | None = None,
    ) -> str:
        async def fetch() -> object:
            response = await self._request(module, url, secret_params, None, False)
            return response.text if response is not None else ""

        text = await self.cached(module, url, fetch)
        return text if isinstance(text, str) else ""

    async def _request(
        self,
        module: Module,
        url: str,
        params: Mapping[str, str] | None,
        headers: Mapping[str, str] | None,
        allow_not_found: bool,
        retries: int = 1,
    ) -> httpx.Response | None:
        """Una petición, con un reintento ante 5xx o timeout (crt.sh y Wayback fallan a menudo)."""
        for attempt in range(retries + 1):
            last_attempt = attempt == retries
            await self.throttle(module)
            try:
                response = await self.http.get(url, params=params, headers=headers)
            except httpx.TimeoutException as exc:
                if last_attempt:
                    raise ModuleError("Tiempo de espera agotado") from exc
                continue
            except httpx.HTTPError as exc:
                raise ModuleError(f"Error de red ({type(exc).__name__})") from exc

            if response.status_code == 404 and allow_not_found:
                return None
            if response.status_code >= 500 and not last_attempt:
                continue
            if response.is_error:
                raise ModuleError(f"La fuente respondió HTTP {response.status_code}")
            return response
        raise AssertionError("unreachable")
