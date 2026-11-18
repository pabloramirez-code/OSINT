import os
from dataclasses import dataclass, field
from pathlib import Path

USER_AGENT = "reconmap/0.1 (passive infrastructure recon)"
HTTP_TIMEOUT_SECONDS = 30.0
MODULE_TIMEOUT_SECONDS = 120.0


@dataclass(frozen=True)
class Settings:
    db_path: Path = field(
        default_factory=lambda: Path(os.environ.get("RECONMAP_DB", "reconmap.db"))
    )
    host: str = "127.0.0.1"
    port: int = 8000
