"""Semáforo común a las evaluaciones (correo, cabeceras web…)."""

from dataclasses import dataclass
from enum import StrEnum


class Status(StrEnum):
    OK = "ok"
    WARN = "warn"
    FAIL = "fail"
    INFO = "info"


SEVERITY_ORDER = {Status.FAIL: 0, Status.WARN: 1, Status.INFO: 2, Status.OK: 3}


@dataclass(frozen=True)
class Check:
    control: str
    status: Status
    summary: str
    advice: str = ""
