import asyncio
import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from reconmap.config import (
    HTTP_TIMEOUT_SECONDS,
    MODULE_TIMEOUT_SECONDS,
    USER_AGENT,
    active_allowed,
)
from reconmap.models import (
    Contact,
    Entity,
    EntityRef,
    EntityType,
    ModuleProgress,
    RelationType,
    RunStatus,
    Scan,
    ScanStatus,
    utcnow,
)
from reconmap.modules.base import Context, Module, ModuleError
from reconmap.ratelimit import RateLimiter
from reconmap.scope import in_scope
from reconmap.store import Store

log = logging.getLogger(__name__)

WORKERS = 8


class ContactNotAllowedError(Exception):
    pass


@dataclass
class _ScanState:
    scan: Scan
    queue: asyncio.Queue[tuple[Entity, int]] = field(default_factory=asyncio.Queue)
    visited: set[EntityRef] = field(default_factory=set)
    hosts: int = 0
    host_limit_reached: bool = False
    progress: dict[str, ModuleProgress] = field(default_factory=dict)


class Engine:
    """Procesa entidades en cola: cada una pasa por los módulos que la aceptan y lo que
    descubren se reencola si está en ámbito y no supera la profundidad ni el tope de hosts."""

    def __init__(
        self,
        store: Store,
        modules: list[Module],
        keys: Mapping[str, str] | None = None,
        max_hosts: int = 300,
        active_allowlist: tuple[str, ...] = (),
        data_dir: Path | None = None,
    ) -> None:
        self.active_allowlist = active_allowlist
        self.data_dir = data_dir
        self.store = store
        self.modules = modules
        self.keys = dict(keys or {})
        self.max_hosts = max_hosts
        self.limiter = RateLimiter()

    def create_scan(
        self, target: str, depth: int = 1, allow_light: bool = False, allow_active: bool = False
    ) -> str:
        if allow_active and not active_allowed(target, self.active_allowlist):
            raise ContactNotAllowedError(f"{target} no está en la lista blanca del modo Activo")
        scan = self.store.create_scan(target, depth, allow_light, allow_active)
        self.store.start_module_runs(scan.id, [(m.name, m.label) for m in self.modules])
        return scan.id

    def skip_reason(self, module: Module, scan: Scan) -> str | None:
        if module.contact is Contact.LIGHT and not scan.allow_light:
            return "Requiere autorización de contacto ligero"
        if module.contact is Contact.ACTIVE and not (
            scan.allow_active and active_allowed(scan.target, self.active_allowlist)
        ):
            return "Requiere modo Activo y dominio en la lista blanca"
        if module.requires_key and module.requires_key not in self.keys:
            return f"Falta {module.requires_key}"
        return None

    async def run(self, scan_id: str) -> None:
        scan = self.store.get_scan(scan_id)
        if scan is None:
            raise ValueError(f"Escaneo inexistente: {scan_id}")
        self.store.update_scan(scan_id, status=ScanStatus.RUNNING, started_at=utcnow())
        status = ScanStatus.FAILED
        try:
            state = _ScanState(scan)
            runnable = self._prepare_modules(state)
            root = Entity(type=EntityType.DOMAIN, value=scan.target)
            self.store.upsert_entity(scan_id, root, "input")
            state.visited.add(root.ref)
            state.queue.put_nowait((root, 0))

            async with httpx.AsyncClient(
                timeout=HTTP_TIMEOUT_SECONDS,
                follow_redirects=True,
                headers={"User-Agent": USER_AGENT},
            ) as http:
                ctx = Context(
                    http,
                    self.store.cache,
                    self.limiter,
                    target=scan.target,
                    keys=self.keys,
                    scan_id=scan.id,
                    allowlist=self.active_allowlist,
                    data_dir=self.data_dir,
                )
                workers = [
                    asyncio.create_task(self._worker(state, runnable, ctx)) for _ in range(WORKERS)
                ]
                await state.queue.join()
                # Fase final: módulos por lotes (modo Activo), una vez con todos los hosts.
                # Lo que descubren vuelve a la cola normal (DNS, NVD…).
                for module in runnable:
                    if getattr(module, "batch", False):
                        await self._run_batch(state, module, ctx)
                        await state.queue.join()
                for worker in workers:
                    worker.cancel()

            status = self._finish_modules(state, runnable)
        except Exception:
            log.exception("El escaneo %s ha fallado", scan_id)
        finally:
            self.store.update_scan(scan_id, status=status, finished_at=utcnow())

    def _prepare_modules(self, state: _ScanState) -> list[Module]:
        runnable = []
        for module in self.modules:
            reason = self.skip_reason(module, state.scan)
            if reason:
                self.store.update_module_run(
                    state.scan.id, module.name, status=RunStatus.SKIPPED, error=reason
                )
            else:
                runnable.append(module)
                state.progress[module.name] = ModuleProgress(module=module.name, label=module.label)
        return runnable

    def _finish_modules(self, state: _ScanState, runnable: list[Module]) -> ScanStatus:
        any_success = not runnable
        for module in runnable:
            progress = state.progress[module.name]
            failed = progress.total > 0 and progress.errors == progress.total
            any_success = any_success or not failed
            self._save_progress(
                state, module.name, status=RunStatus.FAILED if failed else RunStatus.DONE
            )
        if state.host_limit_reached:
            self.store.update_scan(state.scan.id, host_limit_reached=True)
        return ScanStatus.DONE if any_success else ScanStatus.FAILED

    async def _worker(self, state: _ScanState, modules: list[Module], ctx: Context) -> None:
        while True:
            entity, depth = await state.queue.get()
            try:
                applicable = [
                    m
                    for m in modules
                    if entity.type in m.accepts and not getattr(m, "batch", False)
                ]
                await asyncio.gather(
                    *(self._run_module(state, m, entity, depth, ctx) for m in applicable)
                )
            finally:
                state.queue.task_done()

    async def _run_module(
        self, state: _ScanState, module: Module, entity: Entity, depth: int, ctx: Context
    ) -> None:
        progress = state.progress[module.name]
        progress.total += 1
        self._save_progress(state, module.name, status=RunStatus.RUNNING)
        try:
            timeout = getattr(module, "timeout", MODULE_TIMEOUT_SECONDS)
            result = await asyncio.wait_for(module.run(entity, ctx), timeout)
        except Exception as exc:
            progress.errors += 1
            progress.error = str(exc) if isinstance(exc, ModuleError) else _unexpected(module, exc)
        else:
            self.store.save_result(state.scan.id, module.name, result)
            progress.results += len({e.ref for e in result.entities} - {entity.ref})
            for found in result.entities:
                self._enqueue(state, found, depth)
        finally:
            progress.done += 1
            progress.requests = ctx.requests[module.name]
            self._save_progress(state, module.name)

    async def _run_batch(self, state: _ScanState, module: Module, ctx: Context) -> None:
        resolving = {
            (r.from_ref.type, r.from_ref.value)
            for r in self.store.relations(state.scan.id)
            if r.type is RelationType.RESOLVES_TO
        }
        hosts = [
            e
            for e in self.store.entities(state.scan.id)
            if e.type in module.accepts and (e.type, e.value) in resolving
        ]
        progress = state.progress[module.name]
        progress.total = len(hosts)
        self._save_progress(state, module.name, status=RunStatus.RUNNING)
        try:
            timeout = getattr(module, "timeout", MODULE_TIMEOUT_SECONDS)
            run_batch = module.run_batch  # type: ignore[attr-defined]
            result = await asyncio.wait_for(run_batch(hosts, ctx), timeout)
        except Exception as exc:
            progress.errors = max(1, len(hosts))
            progress.error = str(exc) if isinstance(exc, ModuleError) else _unexpected(module, exc)
        else:
            self.store.save_result(state.scan.id, module.name, result)
            given = {e.ref for e in hosts} | {
                Entity(type=EntityType.DOMAIN, value=state.scan.target).ref
            }
            progress.results = len({e.ref for e in result.entities} - given)
            for found in result.entities:
                self._enqueue(state, found, 0)
        finally:
            progress.done = progress.total
            progress.requests = ctx.requests[module.name]
            self._save_progress(state, module.name)

    def _enqueue(self, state: _ScanState, entity: Entity, depth: int) -> None:
        """Las IPs se procesan a la profundidad del host que las resolvió; los subdominios
        en ámbito cuentan un salto más. Nada fuera de ámbito se reencola (regla 3)."""
        if entity.ref in state.visited:
            return
        if entity.type in {EntityType.IP, EntityType.TECHNOLOGY}:
            next_depth = depth  # una tecnología no es un salto: se consulta su CVE y ya
        elif entity.type is EntityType.SUBDOMAIN and in_scope(entity.value, state.scan.target):
            next_depth = depth + 1
        else:
            return
        if next_depth > state.scan.depth:
            return
        if entity.type is EntityType.SUBDOMAIN:
            if state.hosts >= self.max_hosts:
                state.host_limit_reached = True
                return
            state.hosts += 1
        state.visited.add(entity.ref)
        state.queue.put_nowait((entity, next_depth))

    def _save_progress(self, state: _ScanState, module: str, **extra: object) -> None:
        progress = state.progress[module]
        self.store.update_module_run(
            state.scan.id,
            module,
            done=progress.done,
            total=progress.total,
            results=progress.results,
            requests=progress.requests,
            errors=progress.errors,
            error=progress.error,
            **extra,
        )


def _unexpected(module: Module, exc: Exception) -> str:
    if isinstance(exc, TimeoutError):
        return "El módulo superó el tiempo máximo"
    # Sin traceback: podría incluir URLs con claves de API.
    log.error("Error inesperado en %s: %s", module.name, type(exc).__name__)
    return f"Error inesperado ({type(exc).__name__})"
