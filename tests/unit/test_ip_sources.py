import json
import sqlite3

import httpx
import pytest
import respx

from reconmap.models import Entity, EntityType, RelationType
from reconmap.modules.base import Context, ModuleError
from reconmap.modules.bgp import Bgp
from reconmap.modules.internetdb import InternetDb, parse_internetdb
from reconmap.modules.shodan import Shodan, parse_shodan
from reconmap.store import Store
from tests.conftest import load_fixture

IP = Entity(type=EntityType.IP, value="104.20.23.154")


def test_internetdb_ports_and_attributes() -> None:
    result = parse_internetdb(
        IP.value, "example.com", load_fixture("internetdb_104.20.23.154.json")
    )
    ports = {e.value for e in result.entities if e.type is EntityType.PORT}
    assert "104.20.23.154:443" in ports and len(ports) == 13
    assert result.entities[0].attributes["tags"] == ["pqc", "cdn"]


def test_internetdb_foreign_hostnames_are_not_entities() -> None:
    result = parse_internetdb(
        IP.value, "example.com", load_fixture("internetdb_104.20.23.154.json")
    )
    assert not [e for e in result.entities if e.type is EntityType.SUBDOMAIN]
    assert "infrastructure-services.dock.tech" in result.entities[0].attributes["hostnames"]  # type: ignore[operator]


def test_internetdb_in_scope_hostname_becomes_subdomain() -> None:
    data = {"ports": [], "hostnames": ["api.example.com", "evil.net"]}
    result = parse_internetdb(IP.value, "example.com", data)
    assert [e.value for e in result.entities if e.type is EntityType.SUBDOMAIN] == [
        "api.example.com"
    ]


@respx.mock
async def test_internetdb_404_means_no_data(ctx: Context) -> None:
    respx.get("https://internetdb.shodan.io/104.20.23.154").respond(
        404, json=load_fixture("internetdb_404.json")
    )
    assert (await InternetDb().run(IP, ctx)).entities == []


async def test_internetdb_skips_ipv6(ctx: Context) -> None:
    ipv6 = Entity(type=EntityType.IP, value="2606:4700:10::6814:179a")
    with respx.mock:
        assert (await InternetDb().run(ipv6, ctx)).entities == []


@respx.mock
async def test_bgp_builds_asn_and_org(ctx: Context) -> None:
    respx.get("https://stat.ripe.net/data/network-info/data.json?resource=104.20.23.154").respond(
        json=load_fixture("ripestat_network_info_104.20.23.154.json")
    )
    respx.get("https://stat.ripe.net/data/as-overview/data.json?resource=AS13335").respond(
        json=load_fixture("ripestat_as_overview_13335.json")
    )
    result = await Bgp().run(IP, ctx)
    values = {(e.type, e.value) for e in result.entities}
    assert (EntityType.ASN, "AS13335") in values
    assert (EntityType.ORG, "CLOUDFLARENET - Cloudflare, Inc.") in values
    assert {r.type for r in result.relations} == {
        RelationType.BELONGS_TO_ASN,
        RelationType.OWNED_BY,
    }
    assert result.entities[0].attributes["prefix"] == "104.20.16.0/20"


@respx.mock
async def test_bgp_unexpected_format(ctx: Context) -> None:
    respx.get(url__startswith="https://stat.ripe.net/").respond(json={"nope": 1})
    with pytest.raises(ModuleError):
        await Bgp().run(IP, ctx)


async def test_shodan_requires_key(ctx: Context) -> None:
    with pytest.raises(ModuleError, match="SHODAN_API_KEY"):
        await Shodan().run(IP, ctx)


@respx.mock
async def test_api_key_is_sent_but_never_cached(store: Store) -> None:
    route = respx.get(url__startswith="https://api.shodan.io/shodan/host/104.20.23.154").respond(
        json={"ports": [443]}
    )
    async with httpx.AsyncClient() as http:
        from reconmap.ratelimit import RateLimiter

        ctx = Context(
            http,
            store.cache,
            RateLimiter(),
            target="example.com",
            keys={"SHODAN_API_KEY": "s3cr3t"},
        )
        await Shodan().run(IP, ctx)

    assert route.calls.last.request.url.params["key"] == "s3cr3t"
    conn: sqlite3.Connection = store._conn
    dump = json.dumps([tuple(row) for row in conn.execute("SELECT * FROM cache")])
    assert "s3cr3t" not in dump


def test_shodan_real_fixture() -> None:
    result = parse_shodan(IP.value, "example.com", load_fixture("shodan_104.20.23.154.json"))
    ports = {e.value for e in result.entities if e.type is EntityType.PORT}
    assert len(ports) == 13 and "104.20.23.154:443" in ports
    shodan = result.entities[0].attributes["shodan"]
    assert isinstance(shodan, dict) and shodan["org"] == "Cloudflare, Inc."
    assert not [e for e in result.entities if e.type is EntityType.SUBDOMAIN]


def test_shodan_in_scope_hostname_becomes_subdomain() -> None:
    data = {"ports": [], "hostnames": ["mail.example.com", "other.org"]}
    result = parse_shodan(IP.value, "example.com", data)
    assert [e.value for e in result.entities if e.type is EntityType.SUBDOMAIN] == [
        "mail.example.com"
    ]


@respx.mock
async def test_shodan_404_means_no_data(store: Store) -> None:
    respx.get(url__startswith="https://api.shodan.io/shodan/host/").respond(404)
    async with httpx.AsyncClient() as http:
        from reconmap.ratelimit import RateLimiter

        ctx = Context(
            http, store.cache, RateLimiter(), target="example.com", keys={"SHODAN_API_KEY": "x"}
        )
        assert (await Shodan().run(IP, ctx)).entities == []


@respx.mock
async def test_plan_restriction_has_clear_message(store: Store) -> None:
    respx.get(url__startswith="https://api.shodan.io/shodan/host/").respond(
        403, json={"error": "Requires membership or higher to access"}
    )
    async with httpx.AsyncClient() as http:
        from reconmap.ratelimit import RateLimiter

        ctx = Context(
            http, store.cache, RateLimiter(), target="example.com", keys={"SHODAN_API_KEY": "x"}
        )
        with pytest.raises(ModuleError, match="plan no permite"):
            await Shodan().run(IP, ctx)
