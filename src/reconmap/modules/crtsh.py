from datetime import timedelta

from pydantic import BaseModel, TypeAdapter, ValidationError

from reconmap.models import (
    Contact,
    Entity,
    EntityType,
    ModuleResult,
    Relation,
    RelationType,
)
from reconmap.modules.base import Context, ModuleError
from reconmap.normalize import InvalidDomainError, normalize_domain
from reconmap.scope import in_scope


class CrtShRecord(BaseModel):
    name_value: str
    serial_number: str
    not_before: str
    not_after: str
    issuer_name: str


RECORDS = TypeAdapter(list[CrtShRecord])


class CrtSh:
    name = "crtsh"
    label = "Certificate Transparency (crt.sh)"
    description = "Subdominios y certificados de los registros públicos de Certificate Transparency"
    accepts = frozenset({EntityType.DOMAIN})
    contact = Contact.PASSIVE
    requires_key: str | None = None
    cache_ttl = timedelta(hours=24)
    rate_limit = 0.2

    async def run(self, entity: Entity, ctx: Context) -> ModuleResult:
        data = await ctx.get_json(self, f"https://crt.sh/?q=%25.{entity.value}&output=json")
        return parse_crtsh(entity.value, data)


def parse_crtsh(target: str, data: object) -> ModuleResult:
    try:
        records = RECORDS.validate_python(data)
    except ValidationError as exc:
        raise ModuleError("Formato inesperado en la respuesta de crt.sh") from exc

    root = Entity(type=EntityType.DOMAIN, value=target)
    hosts: dict[str, Entity] = {target: root}
    certificates: dict[str, Entity] = {}
    relations: list[Relation] = []
    emails: set[str] = set()

    for record in records:
        names = _in_scope_names(target, record.name_value, emails)
        if not names:
            continue
        certificate = certificates.setdefault(
            record.serial_number,
            Entity(
                type=EntityType.CERTIFICATE,
                value=record.serial_number,
                attributes={
                    "not_before": record.not_before,
                    "not_after": record.not_after,
                    "issuer": record.issuer_name,
                },
            ),
        )
        for name, wildcard in names:
            host = hosts.setdefault(name, Entity(type=EntityType.SUBDOMAIN, value=name))
            if wildcard:
                host.attributes["wildcard"] = True
            relations.append(
                Relation(
                    from_ref=host.ref, type=RelationType.HAS_CERTIFICATE, to_ref=certificate.ref
                )
            )

    relations += [
        Relation(from_ref=root.ref, type=RelationType.HAS_SUBDOMAIN, to_ref=host.ref)
        for name, host in hosts.items()
        if name != target
    ]
    root.attributes["emails_in_certificates"] = len(emails)
    return ModuleResult(
        entities=[*hosts.values(), *certificates.values()],
        relations=list({(r.from_ref, r.type, r.to_ref): r for r in relations}.values()),
    )


def _in_scope_names(target: str, name_value: str, emails: set[str]) -> list[tuple[str, bool]]:
    names = []
    for line in name_value.splitlines():
        candidate = line.strip()
        if "@" in candidate:
            emails.add(candidate.lower())
            continue
        try:
            domain = normalize_domain(candidate)
        except InvalidDomainError:
            continue
        if in_scope(domain.name, target):
            names.append((domain.name, domain.wildcard))
    return names
