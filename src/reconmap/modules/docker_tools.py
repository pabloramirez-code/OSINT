"""Lanzar herramientas del modo Activo en Docker (regla 1, nivel `active`).

Seguridad:
- `create_subprocess_exec` con lista de argumentos: nunca una shell, así que un nombre de
  host no puede inyectar comandos.
- Los hosts se validan antes (normalizados, en ámbito y en la lista blanca) y llegan a la
  herramienta por la entrada estándar, uno por línea, en UTF-8 sin BOM.
- Imágenes fijadas por digest y `--pull never`: nada se descarga ni cambia sin que se sepa.
- Tiempo máximo por ejecución; si se supera, el contenedor se mata.
"""

import asyncio
import os
import shlex
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from reconmap.config import active_allowed
from reconmap.modules.base import ModuleError
from reconmap.normalize import InvalidDomainError, normalize_domain
from reconmap.scope import in_scope

# Versiones comprobadas el 2026-11-19 (salida real guardada en tests/fixtures/).
TLSX_IMAGE = (  # v1.5.0
    "projectdiscovery/tlsx@sha256:6ee6a07c5a633149d5e0482c6df654c9975be97bb7733ec91faaa72a7940295b"
)
HTTPX_IMAGE = (  # v1.12.0
    "projectdiscovery/httpx@sha256:f8275a7c6aaec187249df9eaf4ad9196f4677adfc6a51a47b4aaa1d4db4f8ffc"
)
GOWITNESS_IMAGE = (
    "ghcr.io/sensepost/gowitness@sha256:"
    "39bbbcd07b37c523de3f1447cb8046cb586e91ed3b0c80436922a403ffeddc1c"
)  # v3.2.2
MAX_STDERR = 300
# Modo "local" (dentro del contenedor de reconmap, ver Dockerfile): los mismos programas,
# copiados de esas imágenes, se ejecutan directamente. Así reconmap no necesita controlar
# Docker desde dentro (montar docker.sock daría control total del equipo anfitrión).
# httpx-toolkit: "httpx" es también el CLI del paquete httpx de Python (mismo nombre).
BINARIES = {TLSX_IMAGE: "tlsx", HTTPX_IMAGE: "httpx-toolkit", GOWITNESS_IMAGE: "gowitness"}
RUNNER_ENV = "RECONMAP_TOOLS_RUNNER"


@dataclass(frozen=True)
class ToolRun:
    command: str  # tal cual se ejecutó, para mostrarlo en la interfaz
    returncode: int
    stdout: str
    stderr: str
    seconds: float


def safe_hosts(hosts: list[str], target: str, allowlist: tuple[str, ...]) -> list[str]:
    """Solo nombres válidos, del ámbito del objetivo y, si la hay, de la lista blanca."""
    safe = []
    for host in hosts:
        try:
            name = normalize_domain(host).name
        except InvalidDomainError:
            continue
        if name == host and in_scope(name, target) and active_allowed(name, allowlist):
            safe.append(name)
    return sorted(set(safe))


def docker_available() -> bool:
    return shutil.which("docker") is not None


def runner() -> str:
    """ "docker" (por defecto, en el equipo) o "local" (binarios dentro del contenedor)."""
    return "local" if os.environ.get(RUNNER_ENV, "").strip().lower() == "local" else "docker"


def _local_command(image: str, args: list[str], mount: Path | None) -> list[str]:
    binary = shutil.which(BINARIES[image])
    if binary is None:
        raise ModuleError(f"No se encuentra {BINARIES[image]} (modo local)")
    if mount is not None:
        mount.mkdir(parents=True, exist_ok=True)
        out = str(mount.resolve())
        args = [out + a[len("/out") :] if a == "/out" or a.startswith("/out/") else a for a in args]
    return [binary, *args]


async def run_container(
    image: str,
    args: list[str],
    hosts: list[str],
    timeout: float,
    mount: Path | None = None,
) -> ToolRun:
    """`docker run --rm -i --pull never [-v mount:/out] image args…` con los hosts por stdin.

    En modo local ejecuta el binario equivalente con los mismos argumentos."""
    if runner() == "local":
        command = _local_command(image, args, mount)
    else:
        if not docker_available():
            raise ModuleError("Docker no está instalado o no está en el PATH")
        command = ["docker", "run", "--rm", "-i", "--pull", "never"]
        if mount is not None:
            mount.mkdir(parents=True, exist_ok=True)
            command += ["-v", f"{mount.resolve()}:/out"]
        command += [image, *args]
    started = time.monotonic()
    process = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(("\n".join(hosts) + "\n").encode("utf-8")), timeout
        )
    except TimeoutError as exc:
        process.kill()
        await process.wait()
        raise ModuleError(f"La herramienta superó el tiempo máximo ({timeout:.0f} s)") from exc
    run = ToolRun(
        command=shlex.join(command),
        returncode=process.returncode or 0,
        stdout=stdout.decode("utf-8", errors="replace"),
        stderr=stderr.decode("utf-8", errors="replace")[-MAX_STDERR:],
        seconds=round(time.monotonic() - started, 1),
    )
    if run.returncode != 0:
        if "Unable to find image" in run.stderr or "No such image" in run.stderr:
            raise ModuleError(f"Falta la imagen de Docker: docker pull {image}")
        if "daemon" in run.stderr.lower() or "docker api" in run.stderr.lower():
            raise ModuleError("Docker no está arrancado (abre Docker Desktop)")
        raise ModuleError(f"La herramienta terminó con error {run.returncode}: {run.stderr}")
    return run
