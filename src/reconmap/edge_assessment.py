"""¿Hay un posible WAF delante de un host? Evaluación pura, sin red.

De forma pasiva no se puede saber si un WAF está activo; sí se ve si el tráfico pasa por
un proveedor que lo ofrece (Cloudflare, Akamai, Imperva…). Por eso solo hay dos estados:
"Posible WAF · <proveedor>" o "No se ha podido comprobar si existe WAF". Nunca se
afirma "con WAF" ni "sin WAF".

Señales (de las fuentes que ya consulta reconmap, sin peticiones nuevas):
- Listas oficiales de rangos IP (Cloudflare, Fastly, AWS CloudFront; módulo
  `edge_ranges`), ASN y organización de cada IP (RIPEstat) y etiqueta `cdn`
  (Shodan InternetDB).
- CNAME hacia el proveedor (DNS).
- Cabecera `server` y nombres de cookie (solo en modo Ligero, de `headers`).
- NS del proveedor: solo se anota; tener el DNS en Cloudflare no implica que el
  tráfico pase por su proxy.
"""

import ipaddress
from dataclasses import dataclass, field
from enum import StrEnum


class WafStatus(StrEnum):
    POSSIBLE = "posible"
    UNKNOWN = "no_comprobado"


class Confidence(StrEnum):
    HIGH = "alta"
    MEDIUM = "media"


CLOUDFLARE = "Cloudflare"
AKAMAI = "Akamai"
IMPERVA = "Imperva"
FASTLY = "Fastly"
SUCURI = "Sucuri"
CLOUDFRONT = "AWS CloudFront"
FRONT_DOOR = "Azure Front Door"
AWS = "AWS"
PRIVATE = "red privada"

# Proveedores de proxy inverso que ofrecen WAF, por número de ASN.
PROXY_ASNS: dict[int, str] = {
    13335: CLOUDFLARE,
    209242: CLOUDFLARE,
    19551: IMPERVA,
    54113: FASTLY,
    30148: SUCURI,
    **dict.fromkeys(
        (16625, 16702, 20940, 21342, 21357, 21399, 31107, 31108, 31109, 31110, 32787, 33905,
         34164, 35993, 35994, 36183, 43639),
        AKAMAI,
    ),
}  # fmt: skip

# Hosting y nube: la IP es suya, pero un WAF delante (si lo hay) no se ve desde fuera.
HOSTING_ASNS: dict[int, str] = {
    16509: AWS,
    14618: AWS,
    8987: AWS,
    8075: "Microsoft Azure",
    15169: "Google",
    396982: "Google Cloud",
    19527: "Google",
    16276: "OVH",
    24940: "Hetzner",
    14061: "DigitalOcean",
    8560: "IONOS",
    63949: "Linode (Akamai Cloud)",
}

# Por nombre de la organización, si el ASN no está en las tablas.
PROXY_ORG_KEYWORDS = {
    "cloudflare": CLOUDFLARE,
    "incapsula": IMPERVA,
    "imperva": IMPERVA,
    "fastly": FASTLY,
    "sucuri": SUCURI,
}
HOSTING_ORG_KEYWORDS = {
    "amazon": AWS,
    "microsoft": "Microsoft Azure",
    "google": "Google",
    "ovh": "OVH",
    "hetzner": "Hetzner",
    "digitalocean": "DigitalOcean",
    "ionos": "IONOS",
}

CNAME_SUFFIXES = {
    ".cdn.cloudflare.net": CLOUDFLARE,
    ".edgekey.net": AKAMAI,
    ".edgesuite.net": AKAMAI,
    ".akamaiedge.net": AKAMAI,
    ".akamaized.net": AKAMAI,
    ".incapdns.net": IMPERVA,
    ".sucuri.net": SUCURI,
    ".cloudfront.net": CLOUDFRONT,
    ".azurefd.net": FRONT_DOOR,
    ".fastly.net": FASTLY,
    ".fastlylb.net": FASTLY,
}

SERVER_HEADERS = {
    "cloudflare": CLOUDFLARE,
    "akamaighost": AKAMAI,
    "sucuri/cloudproxy": SUCURI,
    "cloudfront": CLOUDFRONT,
}

# Prefijos de nombre de cookie. Los de appliances (F5, NetScaler, Barracuda) indican un
# posible WAF aunque la IP sea de un hosting: el equipo está delante del servidor.
COOKIE_PREFIXES = {
    "__cf_bm": CLOUDFLARE,
    "cf_clearance": CLOUDFLARE,
    "incap_ses_": IMPERVA,
    "visid_incap_": IMPERVA,
    "ak_bmsc": AKAMAI,
    "bm_sv": AKAMAI,
    "TS01": "F5 BIG-IP ASM",
    "citrix_ns_id": "Citrix NetScaler",
    "NSC_": "Citrix NetScaler",
    "barra_counter_session": "Barracuda",
}

NS_SUFFIXES = {".ns.cloudflare.com": CLOUDFLARE}

# Cabeceras propias de cada proveedor. `headers` guarda solo si aparecen, nunca su valor.
EDGE_HEADERS = {
    "cf-ray": CLOUDFLARE,
    "cf-cache-status": CLOUDFLARE,
    "x-iinfo": IMPERVA,
    "akamai-grn": AKAMAI,
    "x-akamai-transformed": AKAMAI,
    "x-sucuri-id": SUCURI,
    "x-sucuri-cache": SUCURI,
    "x-amz-cf-id": CLOUDFRONT,
    "x-amz-cf-pop": CLOUDFRONT,
    "x-azure-ref": FRONT_DOOR,
    "x-fastly-request-id": FASTLY,
}


@dataclass(frozen=True)
class IpInfo:
    ip: str
    asns: list[str] = field(default_factory=list)
    orgs: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    range_provider: str | None = None  # lista oficial de rangos (módulo edge_ranges)
    range_prefix: str | None = None


@dataclass(frozen=True)
class IpProvider:
    name: str
    proxy: bool  # proveedor de proxy inverso que ofrece WAF
    evidence: str


@dataclass(frozen=True)
class EdgeAssessment:
    status: WafStatus
    waf_provider: str | None
    ip_providers: list[str]
    confidence: Confidence | None
    evidence: list[str]

    @property
    def private(self) -> bool:
        """Todas sus IPs son privadas: no se llega desde Internet, no hay WAF que buscar."""
        return self.ip_providers == [PRIVATE]

    @property
    def label(self) -> str:
        if self.status is WafStatus.POSSIBLE:
            return f"Posible WAF · {self.waf_provider}"
        if self.private:
            return "No se ha podido comprobar si existe WAF (IP privada)"
        return "No se ha podido comprobar si existe WAF"

    @property
    def ip_label(self) -> str:
        if self.private:
            return "IP privada"
        if not self.ip_providers:
            return "IP sin proveedor conocido"
        return f"IP de {', '.join(self.ip_providers)}"

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "label": self.label,
            "ip_label": self.ip_label,
            "waf_provider": self.waf_provider,
            "ip_providers": self.ip_providers,
            "confidence": self.confidence.value if self.confidence else None,
            "evidence": self.evidence,
        }


def ip_provider(info: IpInfo) -> IpProvider | None:
    """Quién es el dueño de la IP y si es un proxy con WAF. None si no hay datos."""
    if not _is_global(info.ip):
        return IpProvider(PRIVATE, False, "dirección privada o reservada")
    if info.range_provider:
        return IpProvider(
            info.range_provider,
            True,
            f"rango oficial de {info.range_provider} ({info.range_prefix})",
        )
    for asn in info.asns:
        number = _asn_number(asn)
        if number in PROXY_ASNS:
            return IpProvider(PROXY_ASNS[number], True, f"{asn} ({PROXY_ASNS[number]})")
        if number in HOSTING_ASNS:
            name = HOSTING_ASNS[number]
            return IpProvider(name, False, f"{asn} ({name})")
    for org in info.orgs:
        lowered = org.lower()
        for keyword, name in PROXY_ORG_KEYWORDS.items():
            if keyword in lowered:
                return IpProvider(name, True, f"organización {org}")
        for keyword, name in HOSTING_ORG_KEYWORDS.items():
            if keyword in lowered:
                return IpProvider(name, False, f"organización {org}")
    if info.orgs:
        return IpProvider(org_name(info.orgs[0]), False, f"organización {info.orgs[0]}")
    return None


def assess_edge(
    ips: list[IpInfo],
    cname: list[str] | None = None,
    ns: list[str] | None = None,
    http_headers: object = None,
) -> EdgeAssessment | None:
    """None si el host no resuelve a ninguna IP (no hay nada que evaluar)."""
    if not ips:
        return None
    providers = [(info, ip_provider(info)) for info in ips]
    ip_names = sorted({p.name for _, p in providers if p})

    # Señal → IPs que la tienen (vacío si no es de una IP). Se agrupan para que un host
    # con 16 IPs de CloudFront muestre una línea, no dieciséis.
    found: dict[str, list[str]] = {}
    kinds: dict[str, set[str]] = {}  # proveedor → tipos de señal distintos

    def note(text: str, ip: str | None = None) -> None:
        ips_with_signal = found.setdefault(text, [])
        if ip and ip not in ips_with_signal:
            ips_with_signal.append(ip)

    def add(provider: str, kind: str, text: str, ip: str | None = None) -> None:
        kinds.setdefault(provider, set()).add(kind)
        note(text, ip)

    all_proxy = all(p is not None and p.proxy for _, p in providers)
    for info, provider in providers:
        if provider is None:
            note("sin datos de ASN ni organización", info.ip)
            continue
        if provider.proxy:
            add(provider.name, "ip", provider.evidence, info.ip)
        if "cdn" in info.tags:
            if provider.name == AWS:
                add(CLOUDFRONT, "cdn", "AWS con etiqueta cdn (CloudFront)", info.ip)
            elif provider.proxy:
                add(provider.name, "cdn", "etiqueta cdn de Shodan InternetDB", info.ip)
    for name in cname or []:
        if provider_name := _by_suffix(name, CNAME_SUFFIXES):
            add(provider_name, "cname", f"CNAME {name.rstrip('.')}")
    for server in _server_headers(http_headers):
        if provider_name := SERVER_HEADERS.get(server.lower()):
            add(provider_name, "header", f"Cabecera server: {server}")
    for header in _edge_header_names(http_headers):
        add(EDGE_HEADERS[header], "header", f"Cabecera {header}")
    for cookie in _cookie_names(http_headers):
        for prefix, provider_name in COOKIE_PREFIXES.items():
            if cookie.startswith(prefix):
                add(provider_name, "cookie", f"Cookie {cookie}")
    for name in ns or []:
        if provider_name := _by_suffix(name, NS_SUFFIXES):
            note(
                f"DNS gestionado por {provider_name} (no implica que el tráfico pase por su proxy)"
            )

    signals = {name: len(provider_kinds) for name, provider_kinds in kinds.items()}
    evidence = [_evidence_line(text, ips_with_signal) for text, ips_with_signal in found.items()]
    strong = {
        name
        for name, provider_kinds in kinds.items()
        if provider_kinds - {"ip"} or all_proxy  # la IP sola cuenta si todas son del proxy
    }
    if not strong:
        if any(p and p.proxy for _, p in providers):
            evidence.append("Solo parte de las IPs pertenecen a un proveedor con WAF")
        return EdgeAssessment(WafStatus.UNKNOWN, None, ip_names, None, evidence)

    best = max(strong, key=lambda name: (signals[name], name))
    if best == CLOUDFRONT and AWS in ip_names:
        ip_names = sorted({CLOUDFRONT if n == AWS else n for n in ip_names})
    confidence = Confidence.HIGH if signals[best] >= 2 else Confidence.MEDIUM
    return EdgeAssessment(WafStatus.POSSIBLE, best, ip_names, confidence, evidence)


def _evidence_line(text: str, ips: list[str]) -> str:
    if not ips:
        return text
    if len(ips) == 1:
        return f"IP {ips[0]}: {text}"
    return f"{len(ips)} IPs ({ips[0]}, …): {text}"


def org_name(holder: str) -> str:
    """'CLOUDFLARENET - Cloudflare, Inc.' → 'Cloudflare, Inc.'; 'OVH OVH SAS' → 'OVH SAS'."""
    if " - " in holder:
        return holder.split(" - ", 1)[1].strip()
    first, _, rest = holder.partition(" ")
    if rest and first.upper() == first and any(c.isalpha() for c in first):
        return rest.strip()
    return holder.strip()


def _is_global(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return True


def _asn_number(asn: str) -> int | None:
    digits = asn.upper().removeprefix("AS")
    return int(digits) if digits.isdigit() else None


def _by_suffix(name: str, table: dict[str, str]) -> str | None:
    host = "." + name.lower().rstrip(".")
    return next((provider for suffix, provider in table.items() if host.endswith(suffix)), None)


def _responses(http_headers: object) -> list[dict[str, object]]:
    if not isinstance(http_headers, dict):
        return []
    return [r for key in ("https", "http") if isinstance(r := http_headers.get(key), dict)]


def _server_headers(http_headers: object) -> list[str]:
    values = []
    for response in _responses(http_headers):
        headers = response.get("headers")
        if isinstance(headers, dict) and isinstance(server := headers.get("server"), str):
            values.append(server.strip())
    return sorted(set(values))


def _edge_header_names(http_headers: object) -> list[str]:
    names = []
    for response in _responses(http_headers):
        present = response.get("edge_headers")
        if isinstance(present, list):
            names += [str(n) for n in present if str(n) in EDGE_HEADERS]
    return sorted(set(names))


def _cookie_names(http_headers: object) -> list[str]:
    names = []
    for response in _responses(http_headers):
        cookies = response.get("cookies")
        if isinstance(cookies, list):
            names += [str(c["name"]) for c in cookies if isinstance(c, dict) and c.get("name")]
    return sorted(set(names))
