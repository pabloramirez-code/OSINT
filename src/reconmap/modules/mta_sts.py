from datetime import timedelta

from reconmap.models import Contact, Entity, EntityType, ModuleResult
from reconmap.modules.base import Context, ModuleError
from reconmap.modules.dns import Resolve, make_resolver
from reconmap.modules.mail import dns_txt


class MtaSts:
    """Descarga la política MTA-STS (RFC 8461). Contacto ligero: solo con autorización y
    solo si el dominio publica el registro `_mta-sts`."""

    name = "mta_sts"
    label = "Política MTA-STS"
    description = "Descarga la política MTA-STS publicada por el dominio"
    accepts = frozenset({EntityType.DOMAIN})
    contact = Contact.LIGHT
    requires_key: str | None = None
    cache_ttl = timedelta(hours=1)
    rate_limit = 1.0

    def __init__(self, resolve: Resolve | None = None) -> None:
        self._resolve = resolve or make_resolver()

    async def run(self, entity: Entity, ctx: Context) -> ModuleResult:
        records = await dns_txt(self, self._resolve, f"_mta-sts.{entity.value}", ctx)
        if not any(r.lower().startswith("v=stsv1") for r in records):
            return ModuleResult()

        url = f"https://mta-sts.{entity.value}/.well-known/mta-sts.txt"
        try:
            policy = parse_policy(await ctx.get_text(self, url, follow_redirects=False))
        except ModuleError as exc:
            policy = {"error": str(exc)}
        return ModuleResult(
            entities=[
                Entity(
                    type=EntityType.DOMAIN,
                    value=entity.value,
                    attributes={"mta_sts_policy": policy},
                )
            ]
        )


def parse_policy(text: str) -> dict[str, object]:
    """Formato `clave: valor` por línea; `mx` puede repetirse."""
    policy: dict[str, object] = {"mx": []}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if not sep:
            continue
        key, value = key.strip().lower(), value.strip()
        if key == "mx":
            mx = policy["mx"]
            if isinstance(mx, list):
                mx.append(value)
        elif key in {"version", "mode", "max_age"}:
            policy[key] = value
    if policy.get("version") != "STSv1":
        policy["error"] = "La política no declara version: STSv1"
    return policy
