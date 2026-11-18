import pytest

from reconmap.models import Entity, EntityType
from reconmap.modules.base import Context
from reconmap.modules.crtsh import CrtSh
from reconmap.modules.dns import Dns
from reconmap.modules.rdap import Rdap

pytestmark = pytest.mark.network

ROOT = Entity(type=EntityType.DOMAIN, value="example.com")


@pytest.mark.parametrize("module", [CrtSh(), Dns(), Rdap()], ids=lambda m: m.name)
async def test_real_source_answers(module: CrtSh | Dns | Rdap, ctx: Context) -> None:
    ctx.http.follow_redirects = True
    result = await module.run(ROOT, ctx)
    assert result.entities
