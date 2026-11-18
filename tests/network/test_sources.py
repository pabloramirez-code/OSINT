import pytest

from reconmap.models import Entity, EntityType
from reconmap.modules.base import Context, Module
from reconmap.modules.bgp import Bgp
from reconmap.modules.certspotter import CertSpotter
from reconmap.modules.crtsh import CrtSh
from reconmap.modules.dns import Dns
from reconmap.modules.hackertarget import HackerTarget
from reconmap.modules.internetdb import InternetDb
from reconmap.modules.rdap import Rdap
from reconmap.modules.wayback import Wayback

pytestmark = pytest.mark.network

DOMAIN = Entity(type=EntityType.DOMAIN, value="example.com")
IP = Entity(type=EntityType.IP, value="104.20.23.154")

CASES: list[tuple[Module, Entity]] = [
    (CrtSh(), DOMAIN),
    (CertSpotter(), DOMAIN),
    (HackerTarget(), DOMAIN),
    (Dns(), DOMAIN),
    (Rdap(), DOMAIN),
    (Wayback(limit=20), DOMAIN),
    (InternetDb(), IP),
    (Bgp(), IP),
]


@pytest.mark.parametrize(("module", "entity"), CASES, ids=[m.name for m, _ in CASES])
async def test_real_source_answers(module: Module, entity: Entity, ctx: Context) -> None:
    ctx.http.follow_redirects = True
    result = await module.run(entity, ctx)
    assert result.entities
