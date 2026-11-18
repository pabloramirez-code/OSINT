from collections import Counter
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Protocol

import httpx

from reconmap.cache import Cache
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
    """Lo único que un módulo puede usar para salir a la red: siempre con caché y rate limit."""

    http: httpx.AsyncClient
    cache: Cache
    limiter: RateLimiter
    target: str
    requests: Counter[str] = field(default_factory=Counter)

    async def throttle(self, module: Module) -> None:
        await self.limiter.acquire(module.name, module.rate_limit)
        self.requests[module.name] += 1

    async def cached(
        self, module: Module, key: str, fetch: Callable[[], Awaitable[object]]
    ) -> object:
        cache_key = f"{module.name}:{key}"
        hit = self.cache.get(cache_key)
        if hit is not None:
            return hit
        value = await fetch()
        self.cache.set(cache_key, value, module.cache_ttl)
        return value

    async def get_json(self, module: Module, url: str, retries: int = 1) -> object:
        async def fetch() -> object:
            for attempt in range(retries + 1):
                try:
                    return await self._fetch_json(module, url)
                except _TransientError as exc:
                    if attempt == retries:
                        raise ModuleError(str(exc)) from exc
            raise AssertionError("unreachable")

        return await self.cached(module, url, fetch)

    async def _fetch_json(self, module: Module, url: str) -> object:
        await self.throttle(module)
        try:
            response = await self.http.get(url)
            response.raise_for_status()
            data: object = response.json()
        except httpx.HTTPStatusError as exc:
            message = f"La fuente respondió HTTP {exc.response.status_code}"
            if exc.response.status_code >= 500:
                raise _TransientError(message) from exc
            raise ModuleError(message) from exc
        except httpx.TimeoutException as exc:
            raise _TransientError("Tiempo de espera agotado") from exc
        except httpx.HTTPError as exc:
            raise ModuleError(f"Error de red ({type(exc).__name__})") from exc
        except ValueError as exc:
            raise ModuleError("La respuesta no es JSON válido") from exc
        return data


class _TransientError(Exception):
    """Fallo que merece un reintento (5xx o timeout)."""
