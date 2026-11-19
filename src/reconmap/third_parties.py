"""Proveedores externos de los que depende un dominio, a partir de DNS ya guardado.

Sin peticiones nuevas. Fuentes:
- TXT de verificación del dominio raíz (`MS=`, `google-site-verification=`…).
- `include:` del SPF (quién puede enviar correo en su nombre).
- MX (quién recibe su correo) y NS (quién gestiona su DNS).
- CNAME de los subdominios hacia servicios SaaS o de nube.

Los tokens de verificación nunca se muestran: solo el proveedor al que pertenecen. Lo que no
se reconoce se cuenta o se lista como "sin identificar", nunca se adivina.
"""

import re
from dataclasses import dataclass, field

MAIL = "Correo"
SENDING = "Envío de correo y marketing"
PRODUCTIVITY = "Productividad e identidad"
SECURITY = "Seguridad"
WEB = "Web, nube y hosting"
DNS = "DNS"
SUPPORT = "Atención al cliente y CRM"
OTHER = "Otros servicios"

# Prefijo del TXT (en minúsculas) → (proveedor, categoría).
TXT_PREFIXES: dict[str, tuple[str, str]] = {
    "ms=": ("Microsoft 365", PRODUCTIVITY),
    "msfpkey=": ("Microsoft Dynamics 365 Customer Voice", SUPPORT),
    "google-site-verification=": ("Google", PRODUCTIVITY),
    "amazonses:": ("Amazon SES", SENDING),
    "facebook-domain-verification=": ("Meta (Facebook)", SENDING),
    "apple-domain-verification=": ("Apple", PRODUCTIVITY),
    "atlassian-domain-verification=": ("Atlassian", PRODUCTIVITY),
    "adobe-idp-site-verification=": ("Adobe", PRODUCTIVITY),
    "adobe-sign-verification=": ("Adobe Acrobat Sign", PRODUCTIVITY),
    "docusign=": ("DocuSign", PRODUCTIVITY),
    "zoom_verify_": ("Zoom", PRODUCTIVITY),
    "dropbox-domain-verification=": ("Dropbox", PRODUCTIVITY),
    "slack-domain-verification=": ("Slack", PRODUCTIVITY),
    "webexdomainverification": ("Cisco Webex", PRODUCTIVITY),
    "cisco-ci-domain-verification=": ("Cisco", PRODUCTIVITY),
    "stripe-verification=": ("Stripe", OTHER),
    "hubspot-developer-verification=": ("HubSpot", SENDING),
    "brevo-code:": ("Brevo", SENDING),
    "sendinblue-code:": ("Brevo (Sendinblue)", SENDING),
    "mailru-verification": ("Mail.ru", OTHER),
    "yandex-verification": ("Yandex", OTHER),
    "globalsign-domain-verification=": ("GlobalSign", SECURITY),
    "sophos-domain-verification=": ("Sophos", SECURITY),
    "knowbe4-site-verification=": ("KnowBe4", SECURITY),
    "onetrust-domain-verification=": ("OneTrust", SECURITY),
    "teamviewer-sso-verification=": ("TeamViewer", PRODUCTIVITY),
    "citrix-verification-code=": ("Citrix", PRODUCTIVITY),
    "miro-verification=": ("Miro", PRODUCTIVITY),
    "openai-domain-verification=": ("OpenAI", PRODUCTIVITY),
    "anthropic-domain-verification": ("Anthropic", PRODUCTIVITY),
    "pinterest-site-verification=": ("Pinterest", SENDING),
}

# Sufijo de dominio → (proveedor, categoría). Se usa para SPF, MX, NS y CNAME.
SPF_SUFFIXES: dict[str, tuple[str, str]] = {
    "spf.protection.outlook.com": ("Microsoft 365", MAIL),
    "_spf.google.com": ("Google Workspace", MAIL),
    "amazonses.com": ("Amazon SES", SENDING),
    "mktomail.com": ("Marketo", SENDING),
    "servers.mcsv.net": ("Mailchimp", SENDING),
    "spf.mandrillapp.com": ("Mailchimp Transactional", SENDING),
    "sendgrid.net": ("SendGrid", SENDING),
    "mailgun.org": ("Mailgun", SENDING),
    "spf.brevo.com": ("Brevo", SENDING),
    "spf.sendinblue.com": ("Brevo (Sendinblue)", SENDING),
    "_spf.salesforce.com": ("Salesforce", SUPPORT),
    "zoho.com": ("Zoho", MAIL),
    "zoho.eu": ("Zoho", MAIL),
    "spf.mailjet.com": ("Mailjet", SENDING),
    "spf.mtasv.net": ("Postmark", SENDING),
    "hubspotemail.net": ("HubSpot", SENDING),
    "mail.zendesk.com": ("Zendesk", SUPPORT),
    "zendesk.com": ("Zendesk", SUPPORT),
    "freshdesk.com": ("Freshdesk", SUPPORT),
    "helpscoutemail.com": ("Help Scout", SUPPORT),
    "_spf.mx.cloudflare.net": ("Cloudflare Email Routing", MAIL),
    "messagingengine.com": ("Fastmail", MAIL),
    "spf.messagelabs.com": ("Broadcom Email Security", SECURITY),
    "pphosted.com": ("Proofpoint", SECURITY),
    "mimecast.com": ("Mimecast", SECURITY),
}
MX_SUFFIXES: dict[str, tuple[str, str]] = {
    "mail.protection.outlook.com": ("Microsoft 365", MAIL),
    "google.com": ("Google Workspace", MAIL),
    "googlemail.com": ("Google Workspace", MAIL),
    "pphosted.com": ("Proofpoint", SECURITY),
    "mimecast.com": ("Mimecast", SECURITY),
    "messagelabs.com": ("Broadcom Email Security", SECURITY),
    "barracudanetworks.com": ("Barracuda", SECURITY),
    "iphmx.com": ("Cisco Secure Email", SECURITY),
    "zoho.com": ("Zoho", MAIL),
    "zoho.eu": ("Zoho", MAIL),
    "mx.cloudflare.net": ("Cloudflare Email Routing", MAIL),
    "messagingengine.com": ("Fastmail", MAIL),
    "protonmail.ch": ("Proton Mail", MAIL),
    "ovh.net": ("OVH", MAIL),
    "ionos.es": ("IONOS", MAIL),
    "ionos.com": ("IONOS", MAIL),
}
NS_SUFFIXES: dict[str, tuple[str, str]] = {
    "ns.cloudflare.com": ("Cloudflare DNS", DNS),
    "awsdns": ("Amazon Route 53", DNS),
    "azure-dns.com": ("Azure DNS", DNS),
    "azure-dns.net": ("Azure DNS", DNS),
    "azure-dns.org": ("Azure DNS", DNS),
    "azure-dns.info": ("Azure DNS", DNS),
    "googledomains.com": ("Google Cloud DNS", DNS),
    "ns-cloud": ("Google Cloud DNS", DNS),
    "domaincontrol.com": ("GoDaddy", DNS),
    "ovh.net": ("OVH", DNS),
    "nsone.net": ("NS1", DNS),
    "ultradns": ("UltraDNS", DNS),
    "akam.net": ("Akamai Edge DNS", DNS),
    "dnsimple.com": ("DNSimple", DNS),
    "ui-dns": ("IONOS", DNS),
}
CNAME_SUFFIXES: dict[str, tuple[str, str]] = {
    "azurewebsites.net": ("Azure App Service", WEB),
    "cloudapp.azure.com": ("Microsoft Azure", WEB),
    "trafficmanager.net": ("Azure Traffic Manager", WEB),
    "azurefd.net": ("Azure Front Door", WEB),
    "blob.core.windows.net": ("Azure Blob Storage", WEB),
    "elb.amazonaws.com": ("AWS Elastic Load Balancing", WEB),
    "cloudfront.net": ("AWS CloudFront", WEB),
    "s3.amazonaws.com": ("Amazon S3", WEB),
    "s3-website": ("Amazon S3", WEB),
    "herokuapp.com": ("Heroku", WEB),
    "herokudns.com": ("Heroku", WEB),
    "github.io": ("GitHub Pages", WEB),
    "gitlab.io": ("GitLab Pages", WEB),
    "netlify.app": ("Netlify", WEB),
    "netlify.com": ("Netlify", WEB),
    "vercel-dns.com": ("Vercel", WEB),
    "pages.dev": ("Cloudflare Pages", WEB),
    "wpengine.com": ("WP Engine", WEB),
    "squarespace.com": ("Squarespace", WEB),
    "wixdns.net": ("Wix", WEB),
    "webflow.io": ("Webflow", WEB),
    "myshopify.com": ("Shopify", WEB),
    "ghost.io": ("Ghost", WEB),
    "zendesk.com": ("Zendesk", SUPPORT),
    "freshdesk.com": ("Freshdesk", SUPPORT),
    "atlassian.net": ("Atlassian", PRODUCTIVITY),
    "statuspage.io": ("Atlassian Statuspage", WEB),
    "hubspot.net": ("HubSpot", SENDING),
    "hs-sites.com": ("HubSpot", SENDING),
    "mktoweb.com": ("Marketo", SENDING),
    "mkto-": ("Marketo", SENDING),
    "pardot.com": ("Salesforce Pardot", SENDING),
    "force.com": ("Salesforce", SUPPORT),
    "clickdimensions.com": ("ClickDimensions", SENDING),
    "unbouncepages.com": ("Unbounce", SENDING),
    "sendgrid.net": ("SendGrid", SENDING),
    "readme.io": ("ReadMe", WEB),
    "gitbook.io": ("GitBook", WEB),
    "helpscoutdocs.com": ("Help Scout", SUPPORT),
    "fastly.net": ("Fastly", WEB),
    "edgekey.net": ("Akamai", WEB),
    "akamaiedge.net": ("Akamai", WEB),
    "cdn.cloudflare.net": ("Cloudflare", WEB),
}
CATEGORY_ORDER = (MAIL, SENDING, SECURITY, PRODUCTIVITY, SUPPORT, WEB, DNS, OTHER)
MAX_EVIDENCE = 6
# "x.elb.eu-west-1.amazonaws.com" → "x.elb.amazonaws.com": la región no identifica al servicio.
_AWS_REGION = re.compile(r"\.[a-z]{2}(?:-gov)?-[a-z]+-\d(?=\.amazonaws\.com$)")


@dataclass
class Provider:
    name: str
    category: str
    evidence: list[str] = field(default_factory=list)

    def add(self, text: str) -> None:
        if text not in self.evidence:
            self.evidence.append(text)


@dataclass
class ThirdParties:
    providers: list[Provider]
    unknown_spf: list[str]  # include: que no se reconocen (dominio, no secreto)
    unknown_mx: list[str]
    unknown_cname: list[str]
    unidentified_txt: int  # tokens TXT no reconocidos: solo el recuento

    def by_category(self) -> list[tuple[str, list[Provider]]]:
        groups = [
            (category, [p for p in self.providers if p.category == category])
            for category in CATEGORY_ORDER
        ]
        return [(category, items) for category, items in groups if items]

    def as_dict(self) -> dict[str, object]:
        return {
            "providers": [
                {"name": p.name, "category": p.category, "evidence": p.evidence[:MAX_EVIDENCE]}
                for p in self.providers
            ],
            "unknown_spf_includes": self.unknown_spf,
            "unknown_mx": self.unknown_mx,
            "unknown_cname_targets": self.unknown_cname,
            "unidentified_txt": self.unidentified_txt,
        }


def find_third_parties(target: str, root_dns: object, cnames: dict[str, list[str]]) -> ThirdParties:
    """`root_dns`: atributo `dns` del dominio raíz; `cnames`: host → destinos CNAME."""
    records = root_dns if isinstance(root_dns, dict) else {}
    found: dict[str, Provider] = {}

    def note(name: str, category: str, text: str) -> None:
        provider = found.setdefault(name, Provider(name, category))
        if CATEGORY_ORDER.index(category) < CATEGORY_ORDER.index(provider.category):
            provider.category = category  # Microsoft 365: Correo antes que Productividad
        provider.add(text)

    unidentified = 0
    unknown_spf: list[str] = []
    for raw in _strings(records.get("TXT")):
        text = _txt(raw)
        lowered = text.lower()
        if lowered.startswith("v=spf1"):
            for include in _spf_includes(text):
                match = _suffix(include, SPF_SUFFIXES)
                if match:
                    note(*match, f"SPF include:{include}")
                elif not _same_org(include, target) and include not in unknown_spf:
                    unknown_spf.append(include)
            continue
        if lowered.startswith(("v=dmarc1", "v=dkim1")):
            continue
        prefix = next((p for p in TXT_PREFIXES if lowered.startswith(p)), None)
        if prefix:
            name, category = TXT_PREFIXES[prefix]
            note(name, category, "TXT de verificación en el dominio")
        else:
            unidentified += 1

    unknown_mx: list[str] = []
    for raw in _strings(records.get("MX")):
        host = _host(raw.split()[-1])
        match = _suffix(host, MX_SUFFIXES)
        if match:
            note(*match, f"MX {host}")
        elif not _same_org(host, target):
            unknown_mx.append(host)

    for raw in _strings(records.get("NS")):
        host = _host(raw)
        match = _contains(host, NS_SUFFIXES)
        if match:
            note(*match, f"NS {host}")

    unknown_cname: list[str] = []
    for source, targets in sorted(cnames.items()):
        for raw in targets:
            host = _host(raw)
            match = _contains(_AWS_REGION.sub("", host), CNAME_SUFFIXES)
            if match:
                note(*match, f"{source} → {host}")
            elif not _same_org(host, target) and host not in unknown_cname:
                unknown_cname.append(host)

    providers = sorted(
        found.values(), key=lambda p: (CATEGORY_ORDER.index(p.category), p.name.lower())
    )
    return ThirdParties(providers, unknown_spf, unknown_mx, unknown_cname, unidentified)


def _txt(raw: str) -> str:
    """Un TXT puede venir partido en trozos ('"v=spf1 a" " -all"'): se concatenan tal cual
    (RFC 7208, sin añadir ni quitar espacios)."""
    return "".join(raw.strip().removeprefix('"').removesuffix('"').split('" "'))


def _spf_includes(spf: str) -> list[str]:
    includes = []
    for term in spf.split():
        lowered = term.lower().lstrip("+~?-")
        for prefix in ("include:", "redirect="):
            if lowered.startswith(prefix):
                includes.append(_host(lowered.removeprefix(prefix)))
    return includes


def _host(raw: str) -> str:
    return raw.strip().rstrip(".").lower()


def _suffix(host: str, table: dict[str, tuple[str, str]]) -> tuple[str, str] | None:
    for suffix, value in table.items():
        if host == suffix or host.endswith("." + suffix):
            return value
    return None


def _contains(host: str, table: dict[str, tuple[str, str]]) -> tuple[str, str] | None:
    """Para NS y CNAME: algunos patrones son fragmentos ('awsdns', 'mkto-')."""
    return _suffix(host, table) or next(
        (value for key, value in table.items() if key in host), None
    )


def _same_org(host: str, target: str) -> bool:
    return host == target or host.endswith("." + target)


def _strings(value: object) -> list[str]:
    return [str(v) for v in value] if isinstance(value, list) else []
