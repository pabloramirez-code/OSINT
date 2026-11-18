import asyncio
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated

import uvicorn
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader
from starlette.exceptions import HTTPException

from reconmap.config import Settings
from reconmap.engine import Engine
from reconmap.models import EntityType, RelationType, Scan
from reconmap.modules import default_modules
from reconmap.modules.base import Module
from reconmap.normalize import InvalidDomainError, normalize_domain
from reconmap.report.json_report import build_report
from reconmap.store import Store

WEB_DIR = Path(__file__).parent
TABS = {"summary", "subdomains", "json"}

templates = Jinja2Templates(
    env=Environment(loader=FileSystemLoader(WEB_DIR / "templates"), autoescape=True)
)


def create_app(store: Store | None = None, modules: list[Module] | None = None) -> FastAPI:
    store = store or Store(Settings().db_path)
    store.fail_interrupted_scans()
    engine = Engine(store, default_modules() if modules is None else modules)
    running: set[asyncio.Task[None]] = set()

    app = FastAPI(title="reconmap")
    app.mount("/static", StaticFiles(directory=WEB_DIR / "static"), name="static")

    def render(
        request: Request,
        name: str,
        context: Mapping[str, object] | None = None,
        status_code: int = 200,
    ) -> HTMLResponse:
        page: dict[str, object] = {
            "history": store.list_scans(),
            "busy": store.active_scan() is not None,
        }
        page.update(context or {})
        return templates.TemplateResponse(request, name, page, status_code=status_code)

    def form_error(
        request: Request, status_code: int, message: str, value: str = ""
    ) -> HTMLResponse:
        context = {"message": message, "value": value[:100]}
        return render(request, "partials/form_error.html", context, status_code)

    def get_scan(scan_id: str) -> Scan:
        scan = store.get_scan(scan_id)
        if scan is None:
            raise HTTPException(404, "Ese escaneo no existe")
        return scan

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException) -> Response:
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
        context = {"code": exc.status_code, "message": exc.detail}
        return render(request, "error.html", context, exc.status_code)

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> HTMLResponse:
        return render(request, "index.html")

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/scans")
    async def create_scan(
        request: Request,
        domain: Annotated[str, Form()] = "",
        depth: Annotated[str, Form()] = "1",
    ) -> Response:
        try:
            target = normalize_domain(domain).name
        except InvalidDomainError:
            return form_error(request, 422, "No es un dominio válido", domain)
        if depth not in {"1", "2", "3"}:
            return form_error(request, 422, "La profundidad debe ser 1, 2 o 3", depth)
        if store.active_scan() is not None:
            return form_error(request, 429, "Ya hay un escaneo en marcha; espera a que termine")

        scan_id = engine.create_scan(target, depth=int(depth))
        task = asyncio.create_task(engine.run(scan_id))
        running.add(task)
        task.add_done_callback(running.discard)

        url = f"/scans/{scan_id}"
        if request.headers.get("HX-Request"):
            return Response(headers={"HX-Redirect": url})
        return RedirectResponse(url, status_code=303)

    @app.get("/scans/{scan_id}", response_class=HTMLResponse)
    async def scan_page(request: Request, scan_id: str) -> HTMLResponse:
        return render(request, "scan.html", {"scan": get_scan(scan_id)})

    @app.get("/scans/{scan_id}/progress", response_class=HTMLResponse)
    async def scan_progress(request: Request, scan_id: str) -> HTMLResponse:
        context = {"scan": get_scan(scan_id), "oob": True}
        return render(request, "partials/progress.html", context)

    @app.get("/scans/{scan_id}/tabs/{tab}", response_class=HTMLResponse)
    async def scan_tab(request: Request, scan_id: str, tab: str) -> HTMLResponse:
        scan = get_scan(scan_id)
        if tab not in TABS:
            raise HTTPException(404, "Pestaña desconocida")
        context = {"scan": scan, **tab_context(store, scan, tab)}
        return render(request, f"partials/tab_{tab}.html", context)

    @app.get("/api/scans/{scan_id}/report")
    async def scan_report(scan_id: str) -> JSONResponse:
        report = build_report(store, scan_id)
        if report is None:
            raise HTTPException(404, "Ese escaneo no existe")
        filename = f"reconmap-{get_scan(scan_id).target}-{scan_id}.json"
        return JSONResponse(
            report, headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )

    return app


def tab_context(store: Store, scan: Scan, tab: str) -> dict[str, object]:
    if tab == "summary":
        roots = store.entities(scan.id, EntityType.DOMAIN)
        root = roots[0].attributes if roots else {}
        return {
            "counts": {
                "Subdominios": len(store.entities(scan.id, EntityType.SUBDOMAIN)),
                "IPs": len(store.entities(scan.id, EntityType.IP)),
                "Certificados": len(store.entities(scan.id, EntityType.CERTIFICATE)),
            },
            "rdap": root.get("rdap"),
            "dns": root.get("dns"),
            "emails": root.get("emails_in_certificates"),
        }
    if tab == "subdomains":
        ips: dict[str, list[str]] = {}
        for relation in store.relations(scan.id):
            if relation.type is RelationType.RESOLVES_TO:
                ips.setdefault(relation.from_ref.value, []).append(relation.to_ref.value)
        return {
            "subdomains": store.entities(scan.id, EntityType.SUBDOMAIN),
            "ips": ips,
            "first_seen": store.first_seen_anywhere(scan.id, EntityType.SUBDOMAIN),
        }
    return {}


def main() -> None:
    settings = Settings()
    uvicorn.run(create_app, factory=True, host=settings.host, port=settings.port)
