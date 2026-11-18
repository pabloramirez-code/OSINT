"""Evaluación de las cabeceras HTTP de un host según OWASP Secure Headers. Función pura."""

import re
from dataclasses import dataclass, field

from reconmap.checks import SEVERITY_ORDER, Check, Status

HSTS_MIN_SECONDS = 15_552_000  # 180 días
HSTS_RECOMMENDED_SECONDS = 31_536_000  # 1 año
VERSION = re.compile(r"\d+\.\d+")


@dataclass(frozen=True)
class HostReport:
    host: str
    checks: list[Check] = field(default_factory=list)
    note: str | None = None

    @property
    def worst(self) -> Status:
        if not self.checks:
            return Status.INFO
        return min((c.status for c in self.checks), key=SEVERITY_ORDER.__getitem__)

    def count(self, status: Status) -> int:
        return sum(c.status is status for c in self.checks)


def assess_host(host: str, data: dict[str, object]) -> HostReport:
    if "skipped" in data:
        return HostReport(host, note=f"No analizado: {data['skipped']}.")
    https = _dict(data.get("https"))
    http = _dict(data.get("http"))
    checks = [*_check_transport(https, http)]
    if isinstance(https.get("status"), int):
        checks += _check_https_response(https)
    return HostReport(host, checks)


def _check_transport(https: dict[str, object], http: dict[str, object]) -> list[Check]:
    checks = []
    if "cert_error" in https:
        checks.append(
            Check(
                "Certificado",
                Status.FAIL,
                f"Certificado no válido: {https['cert_error']}",
                "Renueva el certificado o corrige su nombre o cadena de confianza.",
            )
        )
    elif "status" in https:
        checks.append(Check("Certificado", Status.OK, "Certificado HTTPS válido"))
    else:
        checks.append(Check("HTTPS", Status.INFO, f"No responde por HTTPS ({https.get('error')})"))

    status = http.get("status")
    location = str(http.get("location") or "")
    if not isinstance(status, int):
        checks.append(Check("HTTP → HTTPS", Status.OK, "No acepta conexiones HTTP sin cifrar"))
    elif 300 <= status < 400 and location.lower().startswith("https://"):
        checks.append(Check("HTTP → HTTPS", Status.OK, "HTTP redirige a HTTPS"))
    elif 300 <= status < 400:
        checks.append(
            Check(
                "HTTP → HTTPS",
                Status.WARN,
                "HTTP redirige, pero no a HTTPS",
                "Redirige directamente a la versión https://.",
            )
        )
    elif 200 <= status < 300:
        checks.append(
            Check(
                "HTTP → HTTPS",
                Status.FAIL,
                "Sirve contenido sin cifrar por HTTP",
                "Redirige todo el tráfico HTTP a HTTPS (301).",
            )
        )
    else:
        checks.append(
            Check("HTTP → HTTPS", Status.WARN, f"HTTP responde {status} sin redirigir a HTTPS")
        )
    return checks


def _check_https_response(https: dict[str, object]) -> list[Check]:
    headers = {str(k).lower(): str(v) for k, v in _dict(https.get("headers")).items()}
    checks = _check_hsts(headers.get("strict-transport-security"))
    status = https["status"]
    if isinstance(status, int) and 300 <= status < 400:
        target = https.get("location") or "otra dirección"
        checks.append(
            Check(
                "Redirección",
                Status.INFO,
                f"Redirige a {target}: el resto de cabeceras se evalúa en el destino",
            )
        )
        return checks
    checks += [
        _check_csp(headers.get("content-security-policy")),
        _check_clickjacking(headers.get("x-frame-options"), headers.get("content-security-policy")),
        _check_nosniff(headers.get("x-content-type-options")),
        _check_referrer(headers.get("referrer-policy")),
    ]
    if "permissions-policy" not in headers:
        checks.append(
            Check(
                "Permissions-Policy",
                Status.INFO,
                "Sin Permissions-Policy (limita cámara, micrófono, geolocalización…)",
            )
        )
    checks += _check_disclosure(headers)
    xss = headers.get("x-xss-protection", "").strip()
    if xss.startswith("1"):
        checks.append(
            Check(
                "X-XSS-Protection",
                Status.INFO,
                "Cabecera obsoleta activada",
                "OWASP recomienda quitarla o ponerla a 0 y confiar en CSP.",
            )
        )
    checks += _check_cookies(_list(https.get("cookies")))
    return checks


def _check_hsts(value: str | None) -> list[Check]:
    if value is None:
        return [
            Check(
                "HSTS",
                Status.WARN,
                "Sin HSTS: un atacante en la red puede forzar la versión sin cifrar",
                "Añade Strict-Transport-Security: max-age=31536000; includeSubDomains",
            )
        ]
    match = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.IGNORECASE)
    max_age = int(match.group(1)) if match else 0
    checks = []
    if max_age < HSTS_MIN_SECONDS:
        checks.append(
            Check(
                "HSTS",
                Status.WARN,
                f"max-age demasiado corto ({max_age} s)",
                "Usa al menos 31536000 (un año).",
            )
        )
    else:
        checks.append(Check("HSTS", Status.OK, f"Activo (max-age {max_age} s)"))
    if "includesubdomains" not in value.lower():
        checks.append(Check("HSTS", Status.INFO, "No incluye subdominios (includeSubDomains)"))
    return checks


def _check_csp(value: str | None) -> Check:
    if value is None:
        return Check(
            "CSP",
            Status.WARN,
            "Sin Content-Security-Policy: no hay segunda barrera contra XSS",
            "Define una CSP empezando por default-src 'self'.",
        )
    lowered = value.lower()
    weak = [token for token in ("'unsafe-inline'", "'unsafe-eval'") if token in lowered]
    if re.search(r"(default|script)-src[^;]*\s\*(\s|;|$)", lowered):
        weak.append("comodín *")
    if weak:
        return Check(
            "CSP",
            Status.WARN,
            f"CSP presente pero débil ({', '.join(weak)})",
            "Sustituye unsafe-inline por nonces o hashes.",
        )
    return Check("CSP", Status.OK, "Content-Security-Policy presente")


def _check_clickjacking(xfo: str | None, csp: str | None) -> Check:
    if csp and "frame-ancestors" in csp.lower():
        return Check("Clickjacking", Status.OK, "Protegido con CSP frame-ancestors")
    if xfo and xfo.strip().lower() in {"deny", "sameorigin"}:
        return Check("Clickjacking", Status.OK, f"Protegido con X-Frame-Options: {xfo.strip()}")
    return Check(
        "Clickjacking",
        Status.WARN,
        "La web puede incrustarse en otra (clickjacking)",
        "Añade CSP frame-ancestors 'self' o X-Frame-Options: DENY.",
    )


def _check_nosniff(value: str | None) -> Check:
    if value and value.strip().lower() == "nosniff":
        return Check("X-Content-Type-Options", Status.OK, "nosniff activo")
    return Check(
        "X-Content-Type-Options",
        Status.WARN,
        "Sin nosniff: el navegador puede reinterpretar el tipo de los archivos",
        "Añade X-Content-Type-Options: nosniff.",
    )


def _check_referrer(value: str | None) -> Check:
    if value is None:
        return Check(
            "Referrer-Policy",
            Status.INFO,
            "Sin Referrer-Policy (el navegador usa su valor por defecto)",
            "Recomendado: strict-origin-when-cross-origin.",
        )
    if "unsafe-url" in value.lower():
        return Check(
            "Referrer-Policy",
            Status.WARN,
            "unsafe-url: envía la URL completa a otros sitios",
            "Usa strict-origin-when-cross-origin.",
        )
    return Check("Referrer-Policy", Status.OK, f"Referrer-Policy: {value}")


def _check_disclosure(headers: dict[str, str]) -> list[Check]:
    checks = []
    for name in ("server", "x-powered-by"):
        value = headers.get(name)
        if value and VERSION.search(value):
            checks.append(
                Check(
                    name.title(),
                    Status.WARN,
                    f"Revela la versión del software: {value}",
                    "Oculta la versión; facilita buscar vulnerabilidades conocidas.",
                )
            )
    return checks


def _check_cookies(cookies: list[object]) -> list[Check]:
    checks = []
    for cookie in cookies:
        data = _dict(cookie)
        name = data.get("name", "?")
        missing = [
            flag
            for flag, present in (
                ("Secure", data.get("secure")),
                ("HttpOnly", data.get("httponly")),
                ("SameSite", data.get("samesite")),
            )
            if not present
        ]
        if not missing:
            checks.append(Check("Cookies", Status.OK, f"{name}: Secure, HttpOnly y SameSite"))
            continue
        status = Status.WARN if "Secure" in missing else Status.INFO
        checks.append(
            Check(
                "Cookies",
                status,
                f"{name}: le falta {', '.join(missing)}",
                "Las cookies de sesión deben llevar Secure, HttpOnly y SameSite.",
            )
        )
    return checks


def _dict(value: object) -> dict[str, object]:
    return {str(k): v for k, v in value.items()} if isinstance(value, dict) else {}


def _list(value: object) -> list[object]:
    return list(value) if isinstance(value, list) else []
