from datetime import timedelta

from reconmap.models import Contact, Entity, EntityType, ModuleResult, Relation, RelationType
from reconmap.modules.base import Context, ModuleError
from reconmap.modules.subdomains import in_scope_name, subdomain_result


class HackerTarget:
    name = "hackertarget"
    label = "HackerTarget"
    accepts = frozenset({EntityType.DOMAIN})
    contact = Contact.PASSIVE
    requires_key: str | None = None
    cache_ttl = timedelta(hours=24)
    rate_limit = 0.5

    async def run(self, entity: Entity, ctx: Context) -> ModuleResult:
        key = ctx.keys.get("HACKERTARGET_API_KEY")
        text = await ctx.get_text(
            self,
            f"https://api.hackertarget.com/hostsearch/?q={entity.value}",
            secret_params={"apikey": key} if key else None,
        )
        return parse_hostsearch(entity.value, text)


def parse_hostsearch(target: str, text: str) -> ModuleResult:
    """Formato: una línea `host,ip` por resultado. Los errores llegan como texto plano."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if lines and "," not in lines[0]:
        if "api count exceeded" in lines[0].lower():
            raise ModuleError("Cuota diaria de HackerTarget agotada")
        if "no records found" in lines[0].lower():
            return ModuleResult()
        raise ModuleError("Respuesta inesperada de HackerTarget")

    resolved: dict[str, set[str]] = {}
    for line in lines:
        host, _, ip = line.partition(",")
        name = in_scope_name(host, target)
        if name:
            resolved.setdefault(name, set()).update({ip.strip()} if ip.strip() else set())

    result = subdomain_result(target, set(resolved))
    for name, ips in resolved.items():
        host_ref = Entity(
            type=EntityType.SUBDOMAIN if name != target else EntityType.DOMAIN, value=name
        )
        for ip in sorted(ips):
            address = Entity(type=EntityType.IP, value=ip)
            result.entities.append(address)
            result.relations.append(
                Relation(from_ref=host_ref.ref, type=RelationType.RESOLVES_TO, to_ref=address.ref)
            )
    return result
