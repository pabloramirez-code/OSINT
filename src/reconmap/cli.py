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
from reconmap.report.compare import compare as compare_subdomains
from reconmap.report.json_report import ReportLevel, build_report
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
    level: Annotated[
        ReportLevel, typer.Option(help="Nivel del informe: extended, compact o summary")
    ] = ReportLevel.EXTENDED,
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
        _write_report(json_out, build_report(store, scan_id, level))


@app.command()
def report(
    scan: Annotated[str, typer.Argument(help="Id del escaneo o dominio (usa su último escaneo)")],
    out: Annotated[Path, typer.Option("--out", "-o", help="Archivo JSON de salida")],
    level: Annotated[
        ReportLevel, typer.Option(help="Nivel del informe: extended, compact o summary")
    ] = ReportLevel.SUMMARY,
) -> None:
    """Genera el informe JSON de un escaneo ya hecho."""
    store = Store(Settings().db_path)
    scan_id = _resolve_scan(store, scan)
    if scan_id is None:
        console.print(f"[red]No hay ningún escaneo «{scan}»[/red]", markup=True, highlight=False)
        raise typer.Exit(1)
    _write_report(out, build_report(store, scan_id, level))


def _resolve_scan(store: Store, scan: str) -> str | None:
    if store.get_scan(scan) is not None:
        return scan
    try:
        target = normalize_domain(scan).name
    except InvalidDomainError:
        return None
    matches = [s for s in store.list_scans(limit=1000) if s.target == target]
    return max(matches, key=lambda s: s.created_at).id if matches else None


def _write_report(path: Path, data: dict[str, object] | None) -> None:
    path.write_text(json.dumps(data, indent=1, ensure_ascii=False), encoding="utf-8")
    console.print(f"Informe guardado en {path} ({path.stat().st_size // 1024} KB)")


@app.command()
def compare(
    report: Annotated[Path, typer.Argument(help="Informe JSON de reconmap (--json)")],
    other: Annotated[
        Path, typer.Argument(help="Subdominios de la otra herramienta, uno por línea")
    ],
    tool: Annotated[str, typer.Option(help="Nombre de la otra herramienta")] = "otra herramienta",
    markdown: Annotated[Path | None, typer.Option(help="Guardar el resultado en Markdown")] = None,
) -> None:
    """Compara los subdominios de reconmap con los de otra herramienta (amass, SpiderFoot…)."""
    result = compare_subdomains(
        json.loads(report.read_text(encoding="utf-8")),
        other.read_text(encoding="utf-8", errors="replace"),
        tool,
    )
    table = Table("", "Subdominios")
    table.add_row("Solo reconmap", str(len(result.only_reconmap)))
    table.add_row(f"Solo {tool}", str(len(result.only_other)))
    table.add_row("En ambas", str(len(result.both)))
    console.print(table)
    if markdown:
        markdown.write_text(result.to_markdown(), encoding="utf-8")
        console.print(f"Comparación guardada en {markdown}")


if __name__ == "__main__":
    app()
