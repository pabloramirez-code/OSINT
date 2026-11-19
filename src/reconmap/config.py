import os
from dataclasses import dataclass, field
from pathlib import Path

USER_AGENT = "reconmap/0.2 (passive infrastructure recon)"
HTTP_TIMEOUT_SECONDS = 30.0
MODULE_TIMEOUT_SECONDS = 120.0

KNOWN_KEYS = (
    "VIRUSTOTAL_API_KEY",
    "CERTSPOTTER_API_KEY",
    "HACKERTARGET_API_KEY",
    "NVD_API_KEY",
)


def _env_int(name: str, default: int) -> int:
    return int(os.environ.get(name, default))


@dataclass(frozen=True)
class Settings:
    db_path: Path = field(
        default_factory=lambda: Path(os.environ.get("RECONMAP_DB", "reconmap.db"))
    )
    data_dir: Path = field(
        default_factory=lambda: Path(os.environ.get("RECONMAP_DATA_DIR", "data"))
    )
    # Solo local por defecto (regla 7). En el contenedor se escucha en 0.0.0.0, pero
    # compose.yaml publica el puerto solo en 127.0.0.1 del equipo.
    host: str = field(default_factory=lambda: os.environ.get("RECONMAP_HOST", "127.0.0.1"))
    port: int = 8000
    max_hosts: int = field(default_factory=lambda: _env_int("RECONMAP_MAX_HOSTS", 300))
    max_light_hosts: int = field(default_factory=lambda: _env_int("RECONMAP_MAX_LIGHT_HOSTS", 50))
    wayback_limit: int = field(default_factory=lambda: _env_int("RECONMAP_WAYBACK_LIMIT", 1000))
    max_cve_lookups: int = field(default_factory=lambda: _env_int("RECONMAP_MAX_CVE_LOOKUPS", 20))
    # Modo Activo (regla 1): si se rellena, solo estos dominios y sus subdominios.
    # Vacía: cualquier dominio, siempre con la casilla de autorización marcada.
    active_allowlist: tuple[str, ...] = field(
        default_factory=lambda: tuple(
            name.strip().lower().rstrip(".")
            for name in os.environ.get("RECONMAP_ACTIVE_ALLOWLIST", "").split(",")
            if name.strip()
        )
    )
    dns_servers: tuple[str, ...] = field(
        default_factory=lambda: tuple(
            server.strip()
            for server in os.environ.get("RECONMAP_DNS_SERVERS", "").split(",")
            if server.strip()
        )
    )


def load_env_file(path: Path = Path(".env")) -> None:
    """Lee `.env` (KEY=valor) sin pisar variables ya definidas en el entorno."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


def api_keys() -> dict[str, str]:
    return {name: os.environ[name] for name in KNOWN_KEYS if os.environ.get(name)}


def in_allowlist(target: str, allowlist: tuple[str, ...]) -> bool:
    """El dominio está en la lista blanca o es subdominio de uno que lo está."""
    return any(target == name or target.endswith("." + name) for name in allowlist)


def active_allowed(target: str, allowlist: tuple[str, ...]) -> bool:
    """Modo Activo (regla 1): sin lista blanca, cualquier dominio (con la casilla de
    autorización marcada en ese escaneo); con lista blanca, solo esos dominios."""
    return not allowlist or in_allowlist(target, allowlist)
