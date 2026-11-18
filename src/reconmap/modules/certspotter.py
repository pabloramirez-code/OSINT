from datetime import timedelta

from pydantic import BaseModel, TypeAdapter, ValidationError

from reconmap.models import Contact, Entity, EntityType, ModuleResult
from reconmap.modules.base import Context, ModuleError
from reconmap.modules.subdomains import in_scope_name, subdomain_result

API = "https://api.certspotter.com/v1/issuances"
MAX_PAGES = 5


class Issuance(BaseModel):
    id: str
    dns_names: list[str] = []


ISSUANCES = TypeAdapter(list[Issuance])


class CertSpotter:
    name = "certspotter"
    label = "Cert Spotter"
    accepts = frozenset({EntityType.DOMAIN})
    contact = Contact.PASSIVE
    requires_key: str | None = None
    cache_ttl = timedelta(hours=24)
    rate_limit = 0.5

    async def run(self, entity: Entity, ctx: Context) -> ModuleResult:
        key = ctx.keys.get("CERTSPOTTER_API_KEY")
        headers = {"Authorization": f"Bearer {key}"} if key else None
        names: set[str] = set()
        after = ""
        for _ in range(MAX_PAGES):
            url = f"{API}?domain={entity.value}&include_subdomains=true&expand=dns_names{after}"
            page = parse_issuances(await ctx.get_json(self, url, secret_headers=headers))
            if not page:
                break
            names |= {
                name
                for issuance in page
                for raw in issuance.dns_names
                if (name := in_scope_name(raw, entity.value))
            }
            after = f"&after={page[-1].id}"
        return subdomain_result(entity.value, names)


def parse_issuances(data: object) -> list[Issuance]:
    try:
        return ISSUANCES.validate_python(data)
    except ValidationError as exc:
        raise ModuleError("Formato inesperado en la respuesta de Cert Spotter") from exc
