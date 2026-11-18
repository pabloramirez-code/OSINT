import asyncio
import logging

import httpx

from reconmap.config import HTTP_TIMEOUT_SECONDS, MODULE_TIMEOUT_SECONDS, USER_AGENT
from reconmap.models import Contact, Entity, EntityType, RunStatus, ScanStatus, utcnow
from reconmap.modules.base import Context, Module, ModuleError
from reconmap.ratelimit import RateLimiter
from reconmap.store import Store

log = logging.getLogger(__name__)


class ContactNotAllowedError(Exception):
    pass


class Engine:
    def __init__(self, store: Store, modules: list[Module]) -> None:
        forbidden = [m.name for m in modules if m.contact is Contact.ACTIVE]
        if forbidden:
            raise ContactNotAllowedError(f"Módulos activos no permitidos: {forbidden}")
        self.store = store
        self.modules = modules
        self.limiter = RateLimiter()

    def create_scan(self, target: str, depth: int = 1, allow_light: bool = False) -> str:
        scan = self.store.create_scan(target, depth, allow_light)
        self.store.start_module_runs(scan.id, [(m.name, m.label) for m in self.modules])
        return scan.id

    async def run(self, scan_id: str) -> None:
        scan = self.store.get_scan(scan_id)
        if scan is None:
            raise ValueError(f"Escaneo inexistente: {scan_id}")
        self.store.update_scan(scan_id, status=ScanStatus.RUNNING, started_at=utcnow())
        status = ScanStatus.FAILED
        try:
            root = Entity(type=EntityType.DOMAIN, value=scan.target)
            self.store.upsert_entity(scan_id, root, "input")
            async with httpx.AsyncClient(
                timeout=HTTP_TIMEOUT_SECONDS,
                follow_redirects=True,
                headers={"User-Agent": USER_AGENT},
            ) as http:
                ctx = Context(http, self.store.cache, self.limiter, target=scan.target)
                outcomes = await asyncio.gather(
                    *(
                        self._run_module(scan_id, m, root, ctx, scan.allow_light)
                        for m in self.modules
                    )
                )
            if any(outcomes) or not self.modules:
                status = ScanStatus.DONE
        except Exception:
            log.exception("El escaneo %s ha fallado", scan_id)
        finally:
            self.store.update_scan(scan_id, status=status, finished_at=utcnow())

    async def _run_module(
        self, scan_id: str, module: Module, entity: Entity, ctx: Context, allow_light: bool
    ) -> bool:
        if entity.type not in module.accepts:
            self.store.update_module_run(scan_id, module.name, status=RunStatus.SKIPPED)
            return False
        if module.contact is Contact.LIGHT and not allow_light:
            self.store.update_module_run(
                scan_id,
                module.name,
                status=RunStatus.SKIPPED,
                error="Requiere autorización de contacto ligero",
            )
            return False

        self.store.update_module_run(scan_id, module.name, status=RunStatus.RUNNING, total=1)
        try:
            result = await asyncio.wait_for(module.run(entity, ctx), MODULE_TIMEOUT_SECONDS)
        except Exception as exc:
            message = str(exc) if isinstance(exc, ModuleError) else _unexpected(exc)
            self.store.update_module_run(
                scan_id,
                module.name,
                status=RunStatus.FAILED,
                error=message,
                requests=ctx.requests[module.name],
            )
            return False

        self.store.save_result(scan_id, module.name, result)
        self.store.update_module_run(
            scan_id,
            module.name,
            status=RunStatus.DONE,
            done=1,
            results=len({e.ref for e in result.entities} - {entity.ref}),
            requests=ctx.requests[module.name],
        )
        return True


def _unexpected(exc: Exception) -> str:
    if isinstance(exc, TimeoutError):
        return "El módulo superó el tiempo máximo"
    log.exception("Error inesperado en un módulo", exc_info=exc)
    return f"Error inesperado ({type(exc).__name__})"
