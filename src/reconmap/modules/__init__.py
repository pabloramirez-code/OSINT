from reconmap.config import Settings
from reconmap.modules.base import Module
from reconmap.modules.bgp import Bgp
from reconmap.modules.certspotter import CertSpotter
from reconmap.modules.crtsh import CrtSh
from reconmap.modules.dns import Dns, make_resolver
from reconmap.modules.hackertarget import HackerTarget
from reconmap.modules.internetdb import InternetDb
from reconmap.modules.mail import Mail
from reconmap.modules.mta_sts import MtaSts
from reconmap.modules.rdap import Rdap
from reconmap.modules.wayback import Wayback


def default_modules(settings: Settings | None = None) -> list[Module]:
    settings = settings or Settings()
    resolve = make_resolver(settings.dns_servers)
    return [
        CrtSh(),
        CertSpotter(),
        HackerTarget(),
        Dns(resolve),
        Rdap(),
        Mail(resolve),
        MtaSts(resolve),
        Wayback(limit=settings.wayback_limit),
        InternetDb(),
        Bgp(),
    ]
