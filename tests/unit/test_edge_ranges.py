import ipaddress

import httpx
import pytest
import respx

from reconmap.edge_assessment import IpInfo, WafStatus, assess_edge, ip_provider
from reconmap.models import Entity, EntityType
from reconmap.modules.base import Context, ModuleError
from reconmap.modules.edge_ranges import (
    AWS_URL,
    CLOUDFLARE_V4,
    CLOUDFLARE_V6,
    FASTLY_URL,
    EdgeRanges,
    parse_aws_cloudfront,
    parse_fastly,
)
from tests.conftest import FIXTURES, load_fixture

CLOUDFRONT_IP = "205.251.249.10"  # 205.251.249.0/24, servicio CLOUDFRONT en la fixture
ORIGIN_FACING_IP = "130.176.88.10"  # 130.176.88.0/21, CLOUDFRONT_ORIGIN_FACING
AMAZON_IP = "35.180.1.1"  # 35.180.0.0/16, EC2


def ip(value: str) -> Entity:
    return Entity(type=EntityType.IP, value=value)


def mock_lists() -> dict[str, respx.Route]:
    return {
        "cf4": respx.get(CLOUDFLARE_V4).respond(
            text=(FIXTURES / "cloudflare_ips-v4.txt").read_text(encoding="utf-8")
        ),
        "cf6": respx.get(CLOUDFLARE_V6).respond(
            text=(FIXTURES / "cloudflare_ips-v6.txt").read_text(encoding="utf-8")
        ),
        "fastly": respx.get(FASTLY_URL).respond(json=load_fixture("fastly_public-ip-list.json")),
        "aws": respx.get(AWS_URL).respond(json=load_fixture("aws_ip-ranges_recortado.json")),
    }


def provider_of(result_entities: list[Entity]) -> object:
    assert len(result_entities) == 1
    return result_entities[0].attributes["edge_range"]


def test_aws_only_cloudfront_service() -> None:
    networks = parse_aws_cloudfront(load_fixture("aws_ip-ranges_recortado.json"))
    assert ipaddress.ip_network("205.251.249.0/24") in networks
    assert ipaddress.ip_network("2600:9000:3000::/36") in networks
    assert ipaddress.ip_network("130.176.88.0/21") not in networks  # origin facing
    assert ipaddress.ip_network("35.180.0.0/16") not in networks  # EC2


def test_fastly_v4_and_v6() -> None:
    networks = parse_fastly(load_fixture("fastly_public-ip-list.json"))
    assert ipaddress.ip_network("151.101.0.0/16") in networks
    assert any(n.version == 6 for n in networks)


def test_unexpected_formats() -> None:
    with pytest.raises(ModuleError):
        parse_aws_cloudfront({"nope": 1})
    with pytest.raises(ModuleError):
        parse_fastly(["151.101.0.0/16"])


@respx.mock
async def test_marks_ips_in_official_ranges(ctx: Context) -> None:
    mock_lists()
    module = EdgeRanges()
    cases = {
        "104.20.44.74": ("Cloudflare", "104.16.0.0/13"),
        "2606:4700:10::6814:2c4a": ("Cloudflare", "2606:4700::/32"),
        "151.101.1.1": ("Fastly", "151.101.0.0/16"),
        CLOUDFRONT_IP: ("AWS CloudFront", "205.251.249.0/24"),
    }
    for value, (provider, prefix) in cases.items():
        result = await module.run(ip(value), ctx)
        assert provider_of(result.entities) == {"provider": provider, "prefix": prefix}


@respx.mock
async def test_ips_outside_ranges_get_nothing(ctx: Context) -> None:
    mock_lists()
    module = EdgeRanges()
    for value in (AMAZON_IP, ORIGIN_FACING_IP, "51.15.0.1", "10.0.0.1"):
        assert (await module.run(ip(value), ctx)).entities == []


@respx.mock
async def test_lists_are_downloaded_once(ctx: Context) -> None:
    routes = mock_lists()
    module = EdgeRanges()
    for value in ("104.20.44.74", "151.101.1.1", AMAZON_IP, CLOUDFRONT_IP):
        await module.run(ip(value), ctx)
    assert all(route.call_count == 1 for route in routes.values())


@respx.mock
async def test_one_failing_list_does_not_stop_the_others(ctx: Context) -> None:
    routes = mock_lists()
    routes["aws"].mock(side_effect=httpx.ConnectError("caída"))
    result = await EdgeRanges().run(ip("104.20.44.74"), ctx)
    assert provider_of(result.entities) == {"provider": "Cloudflare", "prefix": "104.16.0.0/13"}


@respx.mock
async def test_all_lists_failing_is_a_module_error(ctx: Context) -> None:
    respx.get(url__regex=r".*").mock(side_effect=httpx.ConnectError("sin red"))
    with pytest.raises(ModuleError):
        await EdgeRanges().run(ip("104.20.44.74"), ctx)


def test_official_range_makes_aws_ip_cloudfront() -> None:
    info = IpInfo(
        CLOUDFRONT_IP,
        asns=["AS16509"],
        orgs=["AMAZON-02 - Amazon.com, Inc."],
        range_provider="AWS CloudFront",
        range_prefix="205.251.249.0/24",
    )
    provider = ip_provider(info)
    assert provider is not None and provider.proxy
    edge = assess_edge([info])
    assert edge is not None
    assert edge.status is WafStatus.POSSIBLE
    assert edge.label == "Posible WAF · AWS CloudFront"
    assert any("rango oficial de AWS CloudFront" in e for e in edge.evidence)
