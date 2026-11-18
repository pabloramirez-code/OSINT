from reconmap.modules.base import Module
from reconmap.modules.crtsh import CrtSh
from reconmap.modules.dns import Dns
from reconmap.modules.rdap import Rdap


def default_modules() -> list[Module]:
    return [CrtSh(), Dns(), Rdap()]
