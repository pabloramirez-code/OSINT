import asyncio
import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from reconmap.config import Settings, api_keys, load_env_file
from reconmap.engine import Engine
from reconmap.models import EntityType
from reconmap.modules import default_modules
from reconmap.normalize import InvalidDomainError, normalize_domain
from reconmap.report.json_report import build_report
from reconmap.store import Store

app = typer.Typer(help="reconmap: reconocimiento pasivo de infraestructura (CLI de depuración).")
console = Console()


@app.callback()
def main() -> None:
    pass


@app.command()
def scan(
    domain: str,
    depth: Annotated[int, typer.Option(min=1, max=3, help="Profundidad de recursión")] = 1,
    json_out: Annotated[Path | None, typer.Option("--json", help="Guardar el informe JSON")] = None,
) -> None:
    """Escanea un dominio con los módulos pasivos y muestra el resultado."""
    try:
        target = normalize_domain(domain).name
    except InvalidDomainError as exc:
        console.print(f"[red]{exc}[/red]", markup=True, highlight=False)
        raise typer.Exit(2) from exc

    load_env_file()
    settings = Settings()
    store = Store(settings.db_path)
    engine = Engine(store, default_modules(settings), keys=api_keys(), max_hosts=settings.max_hosts)
    scan_id = engine.create_scan(target, depth=depth)
    with console.status(f"Escaneando {target}…"):
        asyncio.run(engine.run(scan_id))

    result = store.get_scan(scan_id)
    if result is None:
        raise typer.Exit(1)
    table = Table(
        "Módulo", "Estado", "Hecho", "Resultados", "Peticiones", "Errores", "Último error"
    )
    for run in result.progress:
        table.add_row(
            run.label,
            run.status,
            f"{run.done}/{run.total}",
            str(run.results),
            str(run.requests),
            str(run.errors),
            run.error or "",
        )
    console.print(table)
    subdomains = store.entities(scan_id, EntityType.SUBDOMAIN)
    console.print(f"{len(subdomains)} subdominios · estado: {result.status}")

    if json_out:
        json_out.write_text(
            json.dumps(build_report(store, scan_id), indent=2, ensure_ascii=False), encoding="utf-8"
        )
        console.print(f"Informe guardado en {json_out}")
