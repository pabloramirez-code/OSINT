"""Tecnologías de un host o IP, sin leer el HTML (decisión del usuario, 2026-11-19).

Fuentes:
- CPE que Shodan InternetDB da por IP (pasivo; Shodan ya leyó esas páginas por su cuenta).
- Cabeceras `server`, `x-powered-by`, `x-aspnet-version`, `x-aspnetmvc-version`,
  `x-generator` y `x-redirect-by`, y nombres de cookie (modo Ligero).

Solo con versión exacta se buscan CVEs (módulo `nvd`): sin versión saldrían miles y casi
todas falsas. Aun con versión, una distribución (Ubuntu, Debian…) puede haber corregido el
fallo sin cambiar el número: toda CVE "requiere verificación".
"""

import re
from dataclasses import dataclass
from urllib.parse import unquote

from reconmap.models import Entity, EntityType

# Producto en cabeceras → (vendor, product, nombre) según el diccionario CPE de NVD.
# nginx está en NVD bajo el vendor f5 (comprobado: nginx:nginx:1.18.0 devuelve 0 CVEs).
HEADER_PRODUCTS: dict[str, tuple[str, str, str]] = {
    "nginx": ("f5", "nginx", "nginx"),
    "apache": ("apache", "http_server", "Apache HTTP Server"),
    "microsoft-iis": ("microsoft", "internet_information_services", "Microsoft IIS"),
    "php": ("php", "php", "PHP"),
    "openssl": ("openssl", "openssl", "OpenSSL"),
    "openresty": ("openresty", "openresty", "OpenResty"),
    "litespeed": ("litespeedtech", "litespeed_web_server", "LiteSpeed"),
    "express": ("expressjs", "express", "Express"),
    "asp.net": ("microsoft", "asp.net", "ASP.NET"),
    "istio-envoy": ("envoyproxy", "envoy", "Envoy"),
    "envoy": ("envoyproxy", "envoy", "Envoy"),
    "jetty": ("eclipse", "jetty", "Jetty"),
    "caddy": ("caddyserver", "caddy", "Caddy"),
    "gunicorn": ("gunicorn", "gunicorn", "Gunicorn"),
    "apache-coyote": ("apache", "tomcat", "Apache Tomcat"),
    "plesklin": ("plesk", "plesk", "Plesk"),
    "wordpress": ("wordpress", "wordpress", "WordPress"),
    "drupal": ("drupal", "drupal", "Drupal"),
    "joomla!": ("joomla", "joomla\\!", "Joomla!"),
}
# Proveedores de CDN/WAF: ya se muestran en la columna WAF, no son tecnologías del servidor.
EDGE_PRODUCTS = {"cloudflare", "cloudfront", "akamaighost", "amazons3", "sucuri/cloudproxy"}

TECH_HEADERS = (
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-redirect-by",
)
COOKIE_TECHNOLOGIES: dict[str, str | tuple[str, str, str]] = {
    "PHPSESSID": "php",
    "ASP.NET_SessionId": "asp.net",
    "laravel_session": ("laravel", "laravel", "Laravel"),
    "ci_session": ("codeigniter", "codeigniter", "CodeIgniter"),
    "wordpress_": "wordpress",
    "wp-settings-": "wordpress",
    "JSESSIONID": ("oracle", "java", "Java"),
}

NAMES_FROM_CPE = {
    ("f5", "nginx"): "nginx",
    ("apache", "http_server"): "Apache HTTP Server",
    ("openbsd", "openssh"): "OpenSSH",
    ("php", "php"): "PHP",
    ("mariadb", "mariadb"): "MariaDB",
    ("mysql", "mysql"): "MySQL",
    ("jquery", "jquery"): "jQuery",
    ("getbootstrap", "bootstrap"): "Bootstrap",
    ("wordpress", "wordpress"): "WordPress",
    ("microsoft", "internet_information_services"): "Microsoft IIS",
    ("canonical", "ubuntu_linux"): "Ubuntu",
    ("debian", "debian_linux"): "Debian",
    ("fortinet", "fortios"): "FortiOS",
    ("linux", "linux_kernel"): "Linux",
    ("proftpd", "proftpd"): "ProFTPD",
    ("postfix", "postfix"): "Postfix",
    ("rubyonrails", "rails"): "Ruby on Rails",
    ("ruby-lang", "ruby"): "Ruby",
    ("openresty", "openresty"): "OpenResty",
    ("plesk", "plesk"): "Plesk",
    ("prototypejs", "prototype"): "Prototype",
}

_TOKEN = re.compile(r"([A-Za-z][\w.!-]*)(?:/(\d[\w.+~-]*))?")
# OpenSSH: "8.9p1" → versión 8.9 + update p1 (así lo guarda NVD).
_OPENSSH_STYLE = re.compile(r"^(\d+(?:\.\d+)*)(p\d+)$")
# Resto: números y, como mucho, una letra final ("1.1.1f" en OpenSSL).
_VERSION = re.compile(r"^(\d+(?:\.\d+)*[a-z]?)(?![a-z])")
MAX_VALUE = 200


@dataclass(frozen=True)
class Technology:
    vendor: str
    product: str
    name: str
    version: str | None = None
    update: str | None = None  # p. ej. "p1" en OpenSSH 8.9p1
    part: str = "a"  # a = aplicación, o = sistema operativo
    searchable: bool = True  # False: nombre sin equivalente fiable en NVD (no se buscan CVEs)

    @property
    def key(self) -> str:
        """Valor de la entidad: identifica producto y versión, legible y estable."""
        version = self.version + (self.update or "") if self.version else "*"
        return f"{self.vendor}:{self.product}:{version}"

    @property
    def label(self) -> str:
        if not self.version:
            return self.name
        return f"{self.name} {self.version}{self.update or ''}"

    @property
    def cpe(self) -> str | None:
        """CPE 2.3 completo para NVD; None si no hay versión (no se buscan CVEs)."""
        if not self.version or not self.searchable:
            return None
        return (
            f"cpe:2.3:{self.part}:{self.vendor}:{self.product}:{self.version}:"
            f"{self.update or '*'}:*:*:*:*:*:*"
        )

    def entity(self) -> Entity:
        return Entity(
            type=EntityType.TECHNOLOGY,
            value=self.key,
            attributes={
                "name": self.name,
                "version": self.version + (self.update or "") if self.version else None,
                "cpe": self.cpe,
            },
        )


def normalize_version(raw: str | None) -> tuple[str | None, str | None]:
    """'10.11.19-MariaDB-0%2bdeb12u1' → ('10.11.19', None); '8.9p1' → ('8.9', 'p1')."""
    if not raw:
        return None, None
    text = unquote(raw)
    if openssh := _OPENSSH_STYLE.match(text):
        return openssh.group(1), openssh.group(2)
    match = _VERSION.match(text)
    return (match.group(1), None) if match else (None, None)


def without_redundant(technologies: list["Technology"]) -> list["Technology"]:
    """Quita "PHP" sin versión si ya está "PHP 8.1.2": es el mismo producto."""
    versioned = {(t.vendor, t.product) for t in technologies if t.version}
    return [t for t in technologies if t.version or (t.vendor, t.product) not in versioned]


def from_cpe(cpe: str) -> Technology | None:
    """'cpe:/a:apache:http_server:2.4.41' (CPE 2.2, como lo da InternetDB)."""
    if not cpe.startswith("cpe:/"):
        return None
    parts = cpe.removeprefix("cpe:/").split(":")
    if len(parts) < 3 or parts[0] not in {"a", "o"}:
        return None
    part, vendor, product = parts[0], unquote(parts[1]), unquote(parts[2])
    if (vendor, product) in {("cloudflare", "cloudflare"), ("amazon", "amazon_cloudfront")}:
        return None  # proveedor de CDN/WAF, no tecnología del servidor
    version, update = normalize_version(parts[3] if len(parts) > 3 else None)
    name = NAMES_FROM_CPE.get((vendor, product)) or product.replace("_", " ")
    return Technology(vendor, product, name, version, update, part)


def from_header(value: str) -> list[Technology]:
    """'Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f' → Apache 2.4.41, OpenSSL 1.1.1f.

    Los productos que no están en la tabla se ignoran: mejor no listar que inventar."""
    found = []
    for product, raw_version in _TOKEN.findall(value[:MAX_VALUE]):
        lowered = product.lower()
        if lowered in EDGE_PRODUCTS or lowered not in HEADER_PRODUCTS:
            continue
        vendor, cpe_product, name = HEADER_PRODUCTS[lowered]
        version, update = normalize_version(raw_version or None)
        found.append(Technology(vendor, cpe_product, name, version, update))
    return found


# Nombres de httpx -td (huellas de Wappalyzer) → (vendor, product) en NVD.
WAPPALYZER_PRODUCTS: dict[str, tuple[str, str]] = {
    "Nginx": ("f5", "nginx"),
    "Apache HTTP Server": ("apache", "http_server"),
    "IIS": ("microsoft", "internet_information_services"),
    "PHP": ("php", "php"),
    "OpenSSL": ("openssl", "openssl"),
    "OpenResty": ("openresty", "openresty"),
    "LiteSpeed": ("litespeedtech", "litespeed_web_server"),
    "WordPress": ("wordpress", "wordpress"),
    "Drupal": ("drupal", "drupal"),
    "Joomla": ("joomla", r"joomla\!"),
    "jQuery": ("jquery", "jquery"),
    "jQuery UI": ("jqueryui", "jquery_ui"),
    "Bootstrap": ("getbootstrap", "bootstrap"),
    "Moment.js": ("momentjs", "moment"),
    "Express": ("expressjs", "express"),
    "Apache Tomcat": ("apache", "tomcat"),
    "Varnish": ("varnish-software", "varnish_cache"),
    "Envoy": ("envoyproxy", "envoy"),
}


def from_wappalyzer(item: str) -> Technology:
    """'PHP:8.3.36' → PHP 8.3.36. Lo que no está en la tabla se muestra igual, sin CVEs."""
    name, _, raw_version = item.partition(":")
    name = name.strip()[:80]
    version, update = normalize_version(raw_version.strip() or None)
    if name in WAPPALYZER_PRODUCTS:
        vendor, product = WAPPALYZER_PRODUCTS[name]
        return Technology(vendor, product, name, version, update)
    slug = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_") or "desconocido"
    return Technology("wappalyzer", slug, name, version, update, searchable=False)


def from_http_headers(http_headers: object) -> list[Technology]:
    """Tecnologías vistas en la respuesta guardada por el módulo `headers`."""
    found: dict[str, Technology] = {}
    if not isinstance(http_headers, dict):
        return []
    for key in ("https", "http"):
        response = http_headers.get(key)
        if not isinstance(response, dict):
            continue
        headers = response.get("headers")
        if isinstance(headers, dict):
            for name in TECH_HEADERS:
                value = headers.get(name)
                if isinstance(value, str):
                    for tech in from_header(value):
                        found.setdefault(tech.key, tech)
        cookies = response.get("cookies")
        if isinstance(cookies, list):
            for cookie in cookies:
                name = str(cookie.get("name", "")) if isinstance(cookie, dict) else ""
                for prefix, product in COOKIE_TECHNOLOGIES.items():
                    if name.startswith(prefix):
                        tech = _cookie_technology(product)
                        found.setdefault(tech.key, tech)
    return sorted(without_redundant(list(found.values())), key=lambda t: t.key)


def _cookie_technology(product: str | tuple[str, str, str]) -> Technology:
    vendor, cpe_product, name = HEADER_PRODUCTS[product] if isinstance(product, str) else product
    return Technology(vendor, cpe_product, name)
