from datetime import timedelta
from urllib.parse import urlsplit

from reconmap.models import Contact, Entity, EntityType, ModuleResult, Relation, RelationType
from reconmap.modules.base import Context, ModuleError
from reconmap.modules.subdomains import in_scope_name, subdomain_result

CDX = "https://web.archive.org/cdx/search/cdx"


class Wayback:
    name = "wayback"
    label = "Wayback Machine"
    description = "URLs históricas archivadas y subdominios que aparecen en ellas"
    accepts = frozenset({EntityType.DOMAIN})
    contact = Contact.PASSIVE
    requires_key: str | None = None
    cache_ttl = timedelta(days=7)
    rate_limit = 0.5

    def __init__(self, limit: int = 1000) -> None:
        self.limit = limit

    async def run(self, entity: Entity, ctx: Context) -> ModuleResult:
        url = (
            f"{CDX}?url=*.{entity.value}/*&output=json&fl=original"
            f"&collapse=urlkey&limit={self.limit}"
        )
        return parse_cdx(entity.value, await ctx.get_json(self, url), self.limit)


def parse_cdx(target: str, data: object, limit: int) -> ModuleResult:
    """Formato CDX JSON: la primera fila es la cabecera (["original"]) y el resto, URLs."""
    if data in (None, []):
        return ModuleResult()
    if not isinstance(data, list) or not all(isinstance(row, list) and row for row in data):
        raise ModuleError("Formato inesperado en la respuesta del Wayback Machine")

    urls = sorted({str(row[0]) for row in data[1:]})
    root = Entity(
        type=EntityType.DOMAIN,
        value=target,
        attributes={"archived_urls": len(urls), "archived_urls_truncated": len(urls) >= limit},
    )
    hosts = {name for url in urls if (name := in_scope_name(urlsplit(url).hostname or "", target))}

    result = subdomain_result(target, hosts)
    result.entities.append(root)
    for url in urls:
        archived = Entity(type=EntityType.URL, value=url)
        result.entities.append(archived)
        result.relations.append(
            Relation(from_ref=root.ref, type=RelationType.ARCHIVED_URL, to_ref=archived.ref)
        )
    return result
