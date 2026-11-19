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

from reconmap.config import KNOWN_KEYS, Settings, api_keys, load_env_file
from reconmap.engine import Engine
from reconmap.insights import ScanIndex
from reconmap.models import Scan
from reconmap.modules import default_modules
from reconmap.modules.base import Module
from reconmap.normalize import InvalidDomainError, normalize_domain
from reconmap.report.graph import build_graph
from reconmap.report.json_report import ReportLevel, build_report, report_filename
from reconmap.store import Store
from reconmap.web import views

WEB_DIR = Path(__file__).parent
TABS = {"summary", "subdomains", "ips", "tech", "graph", "mail", "web", "json"}

templates = Jinja2Templates(
    env=Environment(loader=FileSystemLoader(WEB_DIR / "templates"), autoescape=True)
)


def create_app(
    store: Store | None = None,
    modules: list[Module] | None = None,
    keys: Mapping[str, str] | None = None,
) -> FastAPI:
    settings = Settings()
    keys = api_keys() if keys is None else keys
    store = store or Store(settings.db_path)
    store.fail_interrupted_scans()
    engine = Engine(
        store,
        default_modules(settings) if modules is None else modules,
        keys=keys,
        max_hosts=settings.max_hosts,
    )
    running: set[asyncio.Task[None]] = set()

    app = FastAPI(title="reconmap")
    app.mount("/static", StaticFiles(directory=WEB_DIR / "static"), name="static")

    def render(
        request: Request,
        name: str,
        context: Mapping[str, object] | None = None,
        status_code: int = 200,
    ) -> HTMLResponse:
        active = store.active_scan()
        page: dict[str, object] = {
            "active_scan": active,
            "busy": active is not None,
            "project_count": store.count_targets(),
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

    def module_cards() -> list[dict[str, object]]:
        any_scan = Scan(id="-", target="-", allow_light=True)
        return [
            {
                "label": m.label,
                "description": m.description,
                "contact": m.contact,
                "accepts": sorted(m.accepts),
                "requires_key": m.requires_key,
                "skip_reason": engine.skip_reason(m, any_scan),
            }
            for m in engine.modules
        ]

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> HTMLResponse:
        context = {
            "modules": module_cards(),
            "max_hosts": settings.max_hosts,
            "recent": views.projects(store, limit=40)[:4],
        }
        return render(request, "index.html", context)

    @app.get("/projects", response_class=HTMLResponse)
    async def projects_page(request: Request) -> HTMLResponse:
        return render(request, "projects.html", {"projects": views.projects(store)})

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/scans")
    async def create_scan(
        request: Request,
        domain: Annotated[str, Form()] = "",
        depth: Annotated[str, Form()] = "1",
        authorized: Annotated[str, Form()] = "",
    ) -> Response:
        try:
            target = normalize_domain(domain).name
        except InvalidDomainError:
            return form_error(request, 422, "No es un dominio válido", domain)
        if depth not in {"1", "2", "3"}:
            return form_error(request, 422, "La profundidad debe ser 1, 2 o 3", depth)
        if store.active_scan() is not None:
            return form_error(request, 429, "Ya hay un escaneo en marcha; espera a que termine")

        scan_id = engine.create_scan(target, depth=int(depth), allow_light=authorized == "1")
        task = asyncio.create_task(engine.run(scan_id))
        running.add(task)
        task.add_done_callback(running.discard)

        url = f"/scans/{scan_id}"
        if request.headers.get("HX-Request"):
            return Response(headers={"HX-Redirect": url})
        return RedirectResponse(url, status_code=303)

    @app.get("/scans/{scan_id}", response_class=HTMLResponse)
    async def scan_page(request: Request, scan_id: str, tab: str = "summary") -> HTMLResponse:
        context = {"scan": get_scan(scan_id), "initial_tab": tab if tab in TABS else "summary"}
        return render(request, "scan.html", context)

    @app.get("/scans/{scan_id}/progress", response_class=HTMLResponse)
    async def scan_progress(request: Request, scan_id: str) -> HTMLResponse:
        context = {"scan": get_scan(scan_id), "oob": True}
        return render(request, "partials/progress.html", context)

    @app.get("/scans/{scan_id}/tabs/{tab}", response_class=HTMLResponse)
    async def scan_tab(request: Request, scan_id: str, tab: str) -> HTMLResponse:
        scan = get_scan(scan_id)
        if tab not in TABS:
            raise HTTPException(404, "Pestaña desconocida")
        context = {"scan": scan, **tab_context(scan, tab)}
        return render(request, f"partials/tab_{tab}.html", context)

    def tab_context(scan: Scan, tab: str) -> dict[str, object]:
        if tab == "summary":
            return views.summary(store, scan, settings.max_hosts)
        if tab == "subdomains":
            return views.subdomains(store, scan)
        if tab == "ips":
            return views.ips(store, scan)
        if tab == "tech":
            return views.technologies(store, scan)
        if tab == "mail":
            return views.mail(store, scan)
        if tab == "web":
            return views.web(store, scan)
        return {}

    @app.get("/settings", response_class=HTMLResponse)
    async def settings_page(request: Request) -> HTMLResponse:
        configured = {name: name in keys for name in KNOWN_KEYS}
        context = {"modules": module_cards(), "configured": configured}
        return render(request, "settings.html", context)

    @app.get("/api/scans/{scan_id}/graph")
    async def scan_graph(scan_id: str) -> JSONResponse:
        get_scan(scan_id)
        return JSONResponse(build_graph(store, scan_id))

    @app.get("/api/scans/{scan_id}/node")
    async def scan_node(scan_id: str, id: str) -> JSONResponse:
        get_scan(scan_id)
        insights = ScanIndex(store, scan_id).insights(id)
        if insights is None:
            raise HTTPException(404, "Ese nodo no existe en el escaneo")
        return JSONResponse(insights.as_dict())

    @app.get("/api/scans/{scan_id}/report")
    async def scan_report(scan_id: str, level: ReportLevel = ReportLevel.EXTENDED) -> JSONResponse:
        report = build_report(store, scan_id, level)
        if report is None:
            raise HTTPException(404, "Ese escaneo no existe")
        filename = report_filename(get_scan(scan_id).target, scan_id, level)
        return JSONResponse(
            report, headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )

    return app


def main() -> None:
    load_env_file()
    settings = Settings()
    uvicorn.run(create_app, factory=True, host=settings.host, port=settings.port)


if __name__ == "__main__":
    main()
