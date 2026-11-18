import json
from collections.abc import AsyncIterator, Iterator
from datetime import timedelta
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from reconmap.models import Contact, Entity, EntityType, ModuleResult
from reconmap.modules.base import Context
from reconmap.ratelimit import RateLimiter
from reconmap.store import Store
from reconmap.web.app import create_app

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> object:
    data: object = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    return data


class FakeModule:
    """Módulo de prueba: devuelve subdominios `found` (relativos a la entidad), las entidades
    `extra`, o lanza `error`. Registra en `seen` cada entidad que procesa."""

    label = "Fuente falsa"
    cache_ttl = timedelta(minutes=1)
    rate_limit = 100.0

    def __init__(
        self,
        name: str = "fake",
        found: tuple[str, ...] = (),
        error: Exception | None = None,
        contact: Contact = Contact.PASSIVE,
        accepts: frozenset[EntityType] = frozenset({EntityType.DOMAIN}),
        extra: tuple[Entity, ...] = (),
        requires_key: str | None = None,
    ) -> None:
        self.name = name
        self.found = found
        self.error = error
        self.contact = contact
        self.accepts = accepts
        self.extra = extra
        self.requires_key = requires_key
        self.seen: list[str] = []

    @property
    def calls(self) -> int:
        return len(self.seen)

    async def run(self, entity: Entity, ctx: Context) -> ModuleResult:
        self.seen.append(entity.value)
        if self.error:
            raise self.error
        subs = [Entity(type=EntityType.SUBDOMAIN, value=f"{n}.{entity.value}") for n in self.found]
        return ModuleResult(entities=[*subs, *self.extra])


@pytest.fixture
def store() -> Iterator[Store]:
    store = Store(":memory:")
    yield store
    store.close()


@pytest.fixture
async def ctx(store: Store) -> AsyncIterator[Context]:
    async with httpx.AsyncClient() as http:
        yield Context(http, store.cache, RateLimiter(), target="example.com")


@pytest.fixture
def client(store: Store) -> Iterator[TestClient]:
    app = create_app(store=store, modules=[FakeModule(found=("www",))], keys={})
    with TestClient(app) as client:
        yield client
