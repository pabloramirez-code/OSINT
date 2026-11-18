import httpx
import pytest
import respx

from reconmap.models import Entity, EntityType, RelationType
from reconmap.modules.base import Context, ModuleError
from reconmap.modules.certspotter import CertSpotter
from reconmap.modules.hackertarget import parse_hostsearch
from reconmap.modules.wayback import parse_cdx
from tests.conftest import FIXTURES, load_fixture

ROOT = Entity(type=EntityType.DOMAIN, value="example.com")


def values(entities: list[Entity], entity_type: EntityType) -> set[str]:
    return {e.value for e in entities if e.type is entity_type}


@respx.mock
async def test_certspotter_paginates_and_filters_scope(
    ctx: Context, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(CertSpotter, "rate_limit", 100.0)
    first_page = load_fixture("certspotter_example.com.json")

    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[] if "after" in request.url.params else first_page)

    route = respx.get(url__startswith="https://api.certspotter.com/v1/issuances").mock(
        side_effect=respond
    )
    result = await CertSpotter().run(ROOT, ctx)
    assert values(result.entities, EntityType.SUBDOMAIN) == {
        "emudhra-lab.example.com",
        "www.example.com",
    }
    assert route.call_count == 2


def test_hackertarget_fixture() -> None:
    text = (FIXTURES / "hackertarget_example.com.txt").read_text(encoding="utf-8")
    result = parse_hostsearch("example.com", text)
    assert values(result.entities, EntityType.SUBDOMAIN) == {"www.example.com"}
    assert any(
        r.type is RelationType.RESOLVES_TO and r.to_ref.value == "104.20.23.154"
        for r in result.relations
    )


def test_hackertarget_ignores_out_of_scope() -> None:
    result = parse_hostsearch("example.com", "a.example.com,1.1.1.1\nexample.com.evil.net,2.2.2.2")
    assert values(result.entities, EntityType.SUBDOMAIN) == {"a.example.com"}
    assert values(result.entities, EntityType.IP) == {"1.1.1.1"}


def test_hackertarget_quota_and_empty() -> None:
    with pytest.raises(ModuleError, match="Cuota"):
        parse_hostsearch("example.com", "API count exceeded - Increase Quota with Membership")
    assert parse_hostsearch("example.com", "No records found").entities == []


# Formato CDX documentado (output=json): la fila 0 es la cabecera. Fixture real pendiente:
# el Wayback Machine estaba caído (503) al preparar la Fase 2.
CDX = [
    ["original"],
    ["http://example.com/"],
    ["https://www.example.com/login?user=x&token=y"],
    ["http://old.example.com:80/backup.zip"],
    ["http://example.com.evil.net/"],
]


def test_wayback_keeps_full_urls_and_finds_hosts() -> None:
    result = parse_cdx("example.com", CDX, limit=1000)
    urls = values(result.entities, EntityType.URL)
    assert "https://www.example.com/login?user=x&token=y" in urls
    assert len(urls) == 4
    assert values(result.entities, EntityType.SUBDOMAIN) == {"www.example.com", "old.example.com"}


def test_wayback_marks_truncation() -> None:
    result = parse_cdx("example.com", CDX, limit=4)
    root = next(e for e in result.entities if e.type is EntityType.DOMAIN)
    assert root.attributes["archived_urls_truncated"] is True


def test_wayback_empty_and_bad_format() -> None:
    assert parse_cdx("example.com", [], limit=10).entities == []
    with pytest.raises(ModuleError):
        parse_cdx("example.com", {"html": "503"}, limit=10)
