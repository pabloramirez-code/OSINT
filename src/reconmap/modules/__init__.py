from reconmap.config import Settings, api_keys
from reconmap.modules.active_tools import Gowitness, Httpx, Tlsx
from reconmap.modules.base import Module
from reconmap.modules.bgp import Bgp
from reconmap.modules.certspotter import CertSpotter
from reconmap.modules.crtsh import CrtSh
from reconmap.modules.dns import Dns, make_resolver
from reconmap.modules.edge_ranges import EdgeRanges
from reconmap.modules.hackertarget import HackerTarget
from reconmap.modules.headers import Headers
from reconmap.modules.internetdb import InternetDb
from reconmap.modules.mail import Mail
from reconmap.modules.mta_sts import MtaSts
from reconmap.modules.nvd import KEY_NAME as NVD_KEY
from reconmap.modules.nvd import Nvd
from reconmap.modules.rdap import Rdap
from reconmap.modules.wayback import Wayback


def default_modules(settings: Settings | None = None) -> list[Module]:
    settings = settings or Settings()
    resolve = make_resolver(settings.dns_servers)
    modules: list[Module] = [
        CrtSh(),
        CertSpotter(),
        HackerTarget(),
        Dns(resolve),
        Rdap(),
        Mail(resolve),
        MtaSts(resolve),
        Headers(resolve, max_hosts=settings.max_light_hosts),
        Wayback(limit=settings.wayback_limit),
        InternetDb(),
        Bgp(),
        EdgeRanges(),
        Nvd(has_key=NVD_KEY in api_keys(), max_lookups=settings.max_cve_lookups),
    ]
    # Modo Activo: el motor los salta si el escaneo no es Activo (casilla de autorización
    # marcada) o si hay lista blanca y el dominio no está en ella (regla 1).
    modules += [Tlsx(), Httpx(), Gowitness()]
    return modules
