import sqlite3
import threading
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import respx

from reconmap.cache import Cache
from reconmap.modules.base import Context, ModuleError
from reconmap.ratelimit import RateLimiter
from tests.conftest import FakeModule

URL = "https://source.test/data"


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 1, 1, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now


@respx.mock
async def test_request_is_cached_until_ttl_expires() -> None:
    clock = Clock()
    cache = Cache(sqlite3.connect(":memory:"), threading.Lock(), clock)
    route = respx.get(URL).respond(json={"ok": True})
    module = FakeModule()

    async with httpx.AsyncClient() as http:
        ctx = Context(http, cache, RateLimiter(), target="example.com")
        await ctx.get_json(module, URL)
        await ctx.get_json(module, URL)
        assert route.call_count == 1

        clock.now += module.cache_ttl + timedelta(seconds=1)
        await ctx.get_json(module, URL)
        assert route.call_count == 2


@respx.mock
async def test_errors_are_not_cached() -> None:
    cache = Cache(sqlite3.connect(":memory:"), threading.Lock())
    route = respx.get(URL)
    route.side_effect = [httpx.Response(404), httpx.Response(200, json=[1])]
    module = FakeModule()

    async with httpx.AsyncClient() as http:
        ctx = Context(http, cache, RateLimiter(), target="example.com")
        with pytest.raises(ModuleError):
            await ctx.get_json(module, URL)
        assert await ctx.get_json(module, URL) == [1]


@respx.mock
async def test_transient_error_is_retried_once() -> None:
    cache = Cache(sqlite3.connect(":memory:"), threading.Lock())
    route = respx.get(URL)
    route.side_effect = [httpx.Response(502), httpx.Response(200, json=[1])]

    async with httpx.AsyncClient() as http:
        ctx = Context(http, cache, RateLimiter(), target="example.com")
        assert await ctx.get_json(FakeModule(), URL) == [1]
        assert route.call_count == 2
