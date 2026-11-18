import httpx
import pytest
import respx

from reconmap.models import Entity, EntityType, RelationType
from reconmap.modules.base import Context, ModuleError
from reconmap.modules.crtsh import CrtSh, parse_crtsh
from reconmap.scope import in_scope
from tests.conftest import load_fixture

CRTSH_URL = "https://crt.sh/?q=%25.example.com&output=json"
ROOT = Entity(type=EntityType.DOMAIN, value="example.com")


def subdomains(data: object) -> set[str]:
    result = parse_crtsh("example.com", data)
    return {e.value for e in result.entities if e.type is EntityType.SUBDOMAIN}


def test_fixture_gives_unique_in_scope_subdomains_without_wildcards() -> None:
    found = subdomains(load_fixture("crtsh_example.com.json"))
    assert found == {
        "dev.example.com",
        "emudhra-lab.example.com",
        "m.example.com",
        "products.example.com",
        "support.example.com",
        "www.example.com",
    }
    assert all(in_scope(name, "example.com") and "*" not in name for name in found)


def test_emails_are_only_counted() -> None:
    result = parse_crtsh("example.com", load_fixture("crtsh_example.com.json"))
    root = next(e for e in result.entities if e.type is EntityType.DOMAIN)
    assert root.attributes["emails_in_certificates"] == 2
    assert all("@" not in e.value for e in result.entities)


def test_wildcard_is_stored_as_attribute() -> None:
    result = parse_crtsh("example.com", load_fixture("crtsh_example.com.json"))
    root = next(e for e in result.entities if e.type is EntityType.DOMAIN)
    assert root.attributes["wildcard"] is True


def test_certificates_keep_expiry_and_relations_are_unique() -> None:
    result = parse_crtsh("example.com", load_fixture("crtsh_example.com.json"))
    certificates = [e for e in result.entities if e.type is EntityType.CERTIFICATE]
    assert certificates and all(c.attributes["not_after"] for c in certificates)
    keys = [(r.from_ref, r.type, r.to_ref) for r in result.relations]
    assert len(keys) == len(set(keys))
    assert any(r.type is RelationType.HAS_SUBDOMAIN for r in result.relations)


def test_html_in_name_value_is_discarded() -> None:
    record = {
        "name_value": "<img src=x onerror=alert(1)>\nok.example.com",
        "serial_number": "01",
        "not_before": "2026-01-01T00:00:00",
        "not_after": "2027-01-01T00:00:00",
        "issuer_name": "C=XX, CN=<b>Test</b>",
    }
    assert subdomains([record]) == {"ok.example.com"}


def test_unexpected_format_is_module_error() -> None:
    with pytest.raises(ModuleError):
        parse_crtsh("example.com", {"error": "nope"})


@respx.mock
async def test_empty_response_gives_no_subdomains(ctx: Context) -> None:
    respx.get(CRTSH_URL).respond(json=[])
    result = await CrtSh().run(ROOT, ctx)
    assert [e for e in result.entities if e.type is not EntityType.DOMAIN] == []


@respx.mock
@pytest.mark.parametrize(
    "response",
    [httpx.Response(502), httpx.TimeoutException("timeout")],
    ids=["502", "timeout"],
)
async def test_server_errors_raise_module_error(
    ctx: Context, response: httpx.Response | Exception, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(CrtSh, "rate_limit", 100.0)
    route = respx.get(CRTSH_URL)
    if isinstance(response, Exception):
        route.side_effect = response
    else:
        route.respond(status_code=response.status_code)
    with pytest.raises(ModuleError):
        await CrtSh().run(ROOT, ctx)
    assert route.call_count == 2
