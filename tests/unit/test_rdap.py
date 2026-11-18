import pytest
import respx

from reconmap.models import Entity, EntityType
from reconmap.modules.base import Context, ModuleError
from reconmap.modules.rdap import Rdap, parse_rdap
from tests.conftest import load_fixture

ROOT = Entity(type=EntityType.DOMAIN, value="example.com")


def test_extracts_registrar_and_expiry() -> None:
    result = parse_rdap("example.com", load_fixture("rdap_example.com.json"))
    rdap = result.entities[0].attributes["rdap"]
    assert isinstance(rdap, dict)
    assert rdap["registrar"] == "RESERVED-Internet Assigned Numbers Authority"
    assert rdap["expires"] == "2027-08-13T04:00:00Z"
    assert rdap["nameservers"] == ["elliott.ns.cloudflare.com", "hera.ns.cloudflare.com"]


def test_no_contact_data_is_kept() -> None:
    result = parse_rdap("example.com", load_fixture("rdap_example.com.json"))
    assert "vcard" not in str(result.model_dump()).lower()


@respx.mock
async def test_follows_rdap_org_redirect(ctx: Context) -> None:
    respx.get("https://rdap.org/domain/example.com").respond(
        302, headers={"Location": "https://rdap.verisign.com/com/v1/domain/example.com"}
    )
    respx.get("https://rdap.verisign.com/com/v1/domain/example.com").respond(
        json=load_fixture("rdap_example.com.json")
    )
    ctx.http.follow_redirects = True
    result = await Rdap().run(ROOT, ctx)
    assert result.entities[0].attributes["rdap"]


@respx.mock
async def test_not_found_is_module_error(ctx: Context) -> None:
    respx.get("https://rdap.org/domain/example.com").respond(404)
    with pytest.raises(ModuleError, match="404"):
        await Rdap().run(ROOT, ctx)
