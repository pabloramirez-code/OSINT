"""Módulos del modo Activo: tlsx, httpx y gowitness (Docker).

Se ejecutan por lotes al final del escaneo (`batch = True`): una sola vez, con todos los
hosts que resuelven, validados con `safe_hosts`. El motor solo los lanza si el escaneo es
Activo y el dominio está en la lista blanca (regla 1).

Lo que se guarda es una selección de campos: nunca cuerpos, cabeceras completas ni valores
de cookies (gowitness los escribe en su JSON; ese archivo se borra tras leerlo).
"""

import json
import re
import shutil
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlparse

from reconmap.config import USER_AGENT
from reconmap.models import (
    Contact,
    Entity,
    EntityType,
    ModuleResult,
    Relation,
    RelationType,
    utcnow,
)
from reconmap.modules.base import Context, ModuleError
from reconmap.modules.docker_tools import (
    GOWITNESS_IMAGE,
    HTTPX_IMAGE,
    TLSX_IMAGE,
    ToolRun,
    run_container,
    safe_hosts,
)
from reconmap.normalize import InvalidDomainError, normalize_domain
from reconmap.scope import in_scope
from reconmap.technologies import from_wappalyzer

HOSTS = frozenset({EntityType.DOMAIN, EntityType.SUBDOMAIN})
MAX_TEXT = 200
MAX_FOREIGN_NAMES = 20
CHROME_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/128.0.0.0 Safari/537.36 reconmap/0.2"
)
SCREENSHOT_NAME = re.compile(r"^[A-Za-z0-9._-]+\.jpe?g$")


class _ActiveTool:
    accepts = HOSTS
    contact = Contact.ACTIVE
    requires_key: str | None = None
    cache_ttl = timedelta(0)
    rate_limit = 1.0
    batch = True
    timeout = 900.0
    name = ""
    label = ""

    async def run(self, entity: Entity, ctx: Context) -> ModuleResult:
        return await self.run_batch([entity], ctx)

    async def run_batch(self, hosts: list[Entity], ctx: Context) -> ModuleResult:
        names = safe_hosts([h.value for h in hosts], ctx.target, ctx.allowlist)
        if not names:
            return ModuleResult()
        ctx.requests[self.name] += len(names)
        result = await self._execute(names, ctx)
        return result

    async def _execute(self, names: list[str], ctx: Context) -> ModuleResult:
        raise NotImplementedError

    def _record(self, ctx: Context, run: ToolRun, hosts: int) -> Entity:
        """Qué se ejecutó y cuándo, en el dominio raíz: la pestaña Activo lo muestra."""
        return Entity(
            type=EntityType.DOMAIN,
            value=ctx.target,
            attributes={
                f"active_run_{self.name}": {
                    "command": run.command,
                    "seconds": run.seconds,
                    "hosts": hosts,
                    "at": utcnow().isoformat(timespec="seconds"),
                }
            },
        )


class Tlsx(_ActiveTool):
    name = "tlsx"
    label = "tlsx (certificado real)"
    description = "Certificado que sirve hoy cada host: emisor, caducidad, nombres y fallos"
    timeout = 600.0
    ARGS = (
        "-json", "-silent", "-nc", "-duc", "-ex", "-ss", "-mm", "-un",
        "-p", "443", "-c", "5", "-timeout", "10", "-retry", "1",
    )  # fmt: skip

    async def _execute(self, names: list[str], ctx: Context) -> ModuleResult:
        run = await run_container(TLSX_IMAGE, list(self.ARGS), names, self.timeout)
        result = parse_tlsx(run.stdout, ctx.target, names)
        result.entities.append(self._record(ctx, run, len(names)))
        return result


class Httpx(_ActiveTool):
    name = "httpx"
    label = "httpx (web y tecnologías)"
    description = "Qué hosts sirven web hoy: estado, título, servidor y tecnologías del HTML"
    ARGS = (
        "-json", "-silent", "-nc", "-duc", "-sc", "-title", "-server", "-td", "-ip",
        "-cname", "-cdn", "-ct", "-cl", "-location", "-ob", "-t", "3", "-rl", "5",
        "-timeout", "10", "-retries", "1", "-random-agent=false",
        "-H", f"User-Agent: {USER_AGENT}",
    )  # fmt: skip

    async def _execute(self, names: list[str], ctx: Context) -> ModuleResult:
        run = await run_container(HTTPX_IMAGE, list(self.ARGS), names, self.timeout)
        result = parse_httpx(run.stdout, ctx.target, names)
        result.entities.append(self._record(ctx, run, len(names)))
        return result


class Gowitness(_ActiveTool):
    name = "gowitness"
    label = "gowitness (capturas)"
    description = "Captura de pantalla de cada web (solo HTTPS)"
    ARGS = (
        "scan", "file", "-f", "-", "--no-http", "-p", "443", "-t", "2", "-T", "30", "-q",
        "--skip-html", "--skip-network-logs", "--screenshot-format", "jpeg",
        "-s", "/out/shots", "--write-jsonl", "--write-jsonl-file", "/out/gowitness.jsonl",
        "--chrome-user-agent", CHROME_UA,
    )  # fmt: skip

    async def _execute(self, names: list[str], ctx: Context) -> ModuleResult:
        if ctx.data_dir is None or not ctx.scan_id:
            raise ModuleError("Sin carpeta de datos para guardar las capturas")
        folder = screenshot_dir(ctx.data_dir, ctx.scan_id)
        raw = folder / "raw"
        try:
            run = await run_container(
                GOWITNESS_IMAGE, list(self.ARGS), names, self.timeout, mount=raw
            )
            jsonl = raw / "gowitness.jsonl"
            text = jsonl.read_text(encoding="utf-8", errors="replace") if jsonl.exists() else ""
            result = parse_gowitness(text, ctx.target, names, raw / "shots", folder)
        finally:
            # El JSON de gowitness incluye cabeceras y valores de cookies: no se conserva.
            shutil.rmtree(raw, ignore_errors=True)
        result.entities.append(self._record(ctx, run, len(names)))
        return result


def screenshot_dir(data_dir: Path, scan_id: str) -> Path:
    if not re.fullmatch(r"[0-9a-f]{12}", scan_id):
        raise ModuleError("Identificador de escaneo no válido")
    return data_dir / "capturas" / scan_id


# Lectura de la salida (funciones puras, probadas con salida real en tests/fixtures/)


def _lines(stdout: str) -> list[dict[str, object]]:
    rows = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
        except ValueError:
            continue
        if isinstance(data, dict):
            rows.append(data)
    return rows


def _strings(value: object) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _clean(value: object, limit: int = MAX_TEXT) -> str:
    text = " ".join(str(value or "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _host_entity(host: str) -> Entity:
    return Entity(type=EntityType.SUBDOMAIN, value=host)


def _root_or_sub(host: str, target: str) -> Entity:
    kind = EntityType.DOMAIN if host == target else EntityType.SUBDOMAIN
    return Entity(type=kind, value=host)


def parse_tlsx(stdout: str, target: str, names: list[str]) -> ModuleResult:
    entities: list[Entity] = []
    relations: list[Relation] = []
    root = Entity(type=EntityType.DOMAIN, value=target)
    for row in _lines(stdout):
        host = str(row.get("host") or "")
        if host not in names:
            continue
        sans = _strings(row.get("subject_an"))
        in_scope_names, foreign = _split_names(sans, target)
        issues = [
            label
            for key, label in (
                ("expired", "caducado"),
                ("self_signed", "autofirmado"),
                ("mismatched", "el nombre no coincide"),
                ("untrusted", "no confiable"),
            )
            if row.get(key) is True
        ]
        issuer_org = row.get("issuer_org")
        tls = {
            "ip": _clean(row.get("ip"), 60),
            "tls_version": _clean(row.get("tls_version"), 20),
            "cipher": _clean(row.get("cipher"), 80),
            "subject_cn": _clean(row.get("subject_cn")),
            "issuer": _clean(
                ", ".join(map(str, issuer_org)) if isinstance(issuer_org, list) else ""
            )
            or _clean(row.get("issuer_cn")),
            "not_after": _clean(row.get("not_after"), 30),
            "names": in_scope_names[:50],
            "foreign_names": foreign[:MAX_FOREIGN_NAMES],
            "issues": issues,
        }
        host_entity = _root_or_sub(host, target)
        entities.append(Entity(type=host_entity.type, value=host, attributes={"tls_live": tls}))
        serial = re.sub(r"[^0-9a-f]", "", str(row.get("serial") or "").lower())
        if serial:
            cert = Entity(
                type=EntityType.CERTIFICATE,
                value=serial,
                attributes={
                    "not_after": tls["not_after"],
                    "issuer": _clean(row.get("issuer_dn")),
                    "live": True,
                },
            )
            entities.append(cert)
            relations.append(
                Relation(
                    from_ref=host_entity.ref, type=RelationType.HAS_CERTIFICATE, to_ref=cert.ref
                )
            )
        for name in in_scope_names:
            if name not in names and name != target:
                sub = _host_entity(name)
                entities.append(sub)
                relations.append(
                    Relation(from_ref=root.ref, type=RelationType.HAS_SUBDOMAIN, to_ref=sub.ref)
                )
    return ModuleResult(entities=entities, relations=relations)


def _split_names(names: list[str], target: str) -> tuple[list[str], list[str]]:
    """Nombres del certificado: los del ámbito pueden ser subdominios; el resto solo texto."""
    inside: list[str] = []
    outside: list[str] = []
    for raw in names:
        try:
            name = normalize_domain(raw).name
        except InvalidDomainError:
            continue
        (inside if in_scope(name, target) else outside).append(name)
    return sorted(set(inside)), sorted(set(outside))


def parse_httpx(stdout: str, target: str, names: list[str]) -> ModuleResult:
    entities: list[Entity] = []
    relations: list[Relation] = []
    for row in _lines(stdout):
        host = str(row.get("input") or "")
        if host not in names:
            continue
        tech_items = _strings(row.get("tech"))
        probe = {
            "url": _clean(row.get("url")),
            "status_code": row.get("status_code")
            if isinstance(row.get("status_code"), int)
            else None,
            "title": _clean(row.get("title")),
            "webserver": _clean(row.get("webserver"), 100),
            "content_type": _clean(row.get("content_type"), 100),
            "location": _clean(row.get("location")),
            "cdn": _clean(row.get("cdn_name"), 40) if row.get("cdn") else "",
            "ip": _clean(row.get("host_ip"), 60),
            "tech": [_clean(t, 100) for t in tech_items],
        }
        base = _root_or_sub(host, target)
        host_entity = Entity(type=base.type, value=host, attributes={"http_probe": probe})
        entities.append(host_entity)
        for item in tech_items:
            tech = from_wappalyzer(item).entity()
            entities.append(tech)
            relations.append(
                Relation(
                    from_ref=host_entity.ref, type=RelationType.USES_TECHNOLOGY, to_ref=tech.ref
                )
            )
    return ModuleResult(entities=entities, relations=relations)


def parse_gowitness(
    text: str, target: str, names: list[str], shots: Path, folder: Path
) -> ModuleResult:
    """Copia cada captura como `<host>.jpeg` (nombre controlado por reconmap)."""
    entities = []
    for row in _lines(text):
        host = (urlparse(str(row.get("url") or "")).hostname or "").lower()
        if host not in names:
            continue
        info = {
            "status": _clean(row.get("response_code"), 10),
            "title": _clean(row.get("title")),
            "final_url": _clean(row.get("final_url")),
            "failed": str(row.get("failed")).lower() == "true",
            "file": "",
        }
        source_name = str(row.get("file_name") or "")
        source = shots / source_name
        if SCREENSHOT_NAME.match(source_name) and source.is_file():
            folder.mkdir(parents=True, exist_ok=True)
            target_name = f"{host}.jpeg"
            shutil.copyfile(source, folder / target_name)
            info["file"] = target_name
        kind = _root_or_sub(host, target).type
        entities.append(Entity(type=kind, value=host, attributes={"screenshot": info}))
    return ModuleResult(entities=entities)
