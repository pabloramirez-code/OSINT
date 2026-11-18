from reconmap.config import Settings
from reconmap.modules.base import Module
from reconmap.modules.bgp import Bgp
from reconmap.modules.certspotter import CertSpotter
from reconmap.modules.crtsh import CrtSh
from reconmap.modules.dns import Dns
from reconmap.modules.hackertarget import HackerTarget
from reconmap.modules.internetdb import InternetDb
from reconmap.modules.rdap import Rdap
from reconmap.modules.shodan import Shodan
from reconmap.modules.wayback import Wayback


def default_modules(settings: Settings | None = None) -> list[Module]:
    settings = settings or Settings()
    return [
        CrtSh(),
        CertSpotter(),
        HackerTarget(),
        Dns(),
        Rdap(),
        Wayback(limit=settings.wayback_limit),
        InternetDb(),
        Bgp(),
        Shodan(),
    ]
