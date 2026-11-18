import ssl

import dns.resolver
import httpx
import pytest
import respx

from reconmap.checks import Status
from reconmap.headers_assessment import assess_host
from reconmap.models import Entity, EntityType
from reconmap.modules.base import Context
from reconmap.modules.dns import Resolve
from reconmap.modules.headers import Headers, certificate_error, cookie_flags

HOST = Entity(type=EntityType.SUBDOMAIN, value="www.example.com")
HTTPS = "https://www.example.com/"
HTTP = "http://www.example.com/"
GOOD_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'self'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=()",
}


def resolver(resolves: bool = True) -> Resolve:
    async def resolve(name: str, record_type: str) -> list[str]:
        if resolves and record_type == "A":
            return ["192.0.2.10"]
        raise dns.resolver.NXDOMAIN

    return resolve


def status_of(data: dict[str, object], control: str) -> list[Status]:
    return [c.status for c in assess_host("h", data).checks if c.control == control]


def response(status: int = 200, headers: dict[str, str] | None = None) -> dict[str, object]:
    return {
        "status": status,
        "location": (headers or {}).get("location"),
        "headers": {k.lower(): v for k, v in (headers or {}).items()},
        "cookies": [],
    }


REDIRECT_TO_HTTPS = response(301, {"location": HTTPS})


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Headers, "rate_limit", 1000.0)


# Módulo


@respx.mock
async def test_collects_headers_without_following_redirects(ctx: Context) -> None:
    respx.get(HTTPS).respond(200, headers={**GOOD_HEADERS, "Set-Cookie": "sid=SECRETO; Secure"})
    respx.get(HTTP).respond(301, headers={"Location": HTTPS})

    result = await Headers(resolver()).run(HOST, ctx)
    data = result.entities[0].attributes["http_headers"]
    assert isinstance(data, dict)
    assert data["http"]["status"] == 301  # type: ignore[index]
    assert data["https"]["headers"]["x-content-type-options"] == "nosniff"  # type: ignore[index]
    assert "SECRETO" not in str(data)
    assert len(respx.calls) == 2


@respx.mock
async def test_host_without_ip_is_not_contacted(ctx: Context) -> None:
    result = await Headers(resolver(resolves=False)).run(HOST, ctx)
    assert result.entities == []
    assert not respx.calls


@respx.mock
async def test_host_limit(ctx: Context) -> None:
    respx.get(url__regex=r"https?://.*").respond(200)
    module = Headers(resolver(), max_hosts=1)
    await module.run(HOST, ctx)
    other = Entity(type=EntityType.SUBDOMAIN, value="api.example.com")
    data = (await module.run(other, ctx)).entities[0].attributes["http_headers"]
    assert isinstance(data, dict) and "skipped" in data
    assert len(respx.calls) == 2


@respx.mock
async def test_invalid_certificate_is_recorded_and_read_insecurely(ctx: Context) -> None:
    # respx reemplaza la causa encadenada, así que se simula con el mensaje real de OpenSSL.
    error = httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate has expired")
    respx.get(HTTPS).mock(side_effect=[error, httpx.Response(200, headers=GOOD_HEADERS)])
    respx.get(HTTP).respond(301, headers={"Location": HTTPS})

    data = (await Headers(resolver()).run(HOST, ctx)).entities[0].attributes["http_headers"]
    assert isinstance(data, dict)
    assert data["https"]["cert_error"]  # type: ignore[index]
    assert data["https"]["status"] == 200  # type: ignore[index]
    assert len(respx.calls) == 3
    assert status_of(data, "Certificado") == [Status.FAIL]


def test_cookie_values_are_never_kept() -> None:
    flags = cookie_flags(["session=abc123; Path=/; HttpOnly; SameSite=Lax", "pref=x"])
    assert flags == [
        {"name": "session", "secure": False, "httponly": True, "samesite": "lax"},
        {"name": "pref", "secure": False, "httponly": False, "samesite": None},
    ]


# Evaluación


def test_well_configured_site_has_no_problems() -> None:
    report = assess_host("h", {"https": response(200, GOOD_HEADERS), "http": REDIRECT_TO_HTTPS})
    assert report.count(Status.FAIL) == 0 and report.count(Status.WARN) == 0


def test_plain_http_content_is_a_failure() -> None:
    assert status_of(
        {"https": {"error": "No responde"}, "http": response(200)}, "HTTP → HTTPS"
    ) == [Status.FAIL]
    assert status_of(
        {"https": response(200), "http": {"error": "No responde"}}, "HTTP → HTTPS"
    ) == [Status.OK]


def test_missing_headers_are_warnings() -> None:
    report = assess_host("h", {"https": response(200), "http": REDIRECT_TO_HTTPS})
    warned = {c.control for c in report.checks if c.status is Status.WARN}
    assert {"HSTS", "CSP", "Clickjacking", "X-Content-Type-Options"} <= warned


@pytest.mark.parametrize(
    ("hsts", "expected"),
    [("max-age=300", Status.WARN), ("max-age=31536000; includeSubDomains", Status.OK)],
)
def test_hsts_max_age(hsts: str, expected: Status) -> None:
    data = {"https": response(200, {"Strict-Transport-Security": hsts}), "http": REDIRECT_TO_HTTPS}
    assert status_of(data, "HSTS")[0] is expected


def test_weak_csp_and_version_disclosure() -> None:
    headers = {
        **GOOD_HEADERS,
        "Content-Security-Policy": "default-src 'self' 'unsafe-inline'",
        "Server": "Apache/2.4.41 (Ubuntu)",
    }
    report = assess_host("h", {"https": response(200, headers), "http": REDIRECT_TO_HTTPS})
    assert any(c.control == "CSP" and "débil" in c.summary for c in report.checks)
    assert any(c.control == "Server" and c.status is Status.WARN for c in report.checks)


def test_redirect_only_evaluates_hsts() -> None:
    data = {
        "https": response(301, {"location": "https://www.example.com/"}),
        "http": REDIRECT_TO_HTTPS,
    }
    controls = {c.control for c in assess_host("h", data).checks}
    assert "CSP" not in controls and "HSTS" in controls and "Redirección" in controls


def test_cookies_without_secure_warn() -> None:
    https = response(200, GOOD_HEADERS)
    https["cookies"] = cookie_flags(["sid=1; HttpOnly; SameSite=Strict"])
    assert status_of({"https": https, "http": REDIRECT_TO_HTTPS}, "Cookies") == [Status.WARN]


def test_skipped_host_has_note() -> None:
    report = assess_host("h", {"skipped": "Se alcanzó el tope de 50 hosts"})
    assert report.note and not report.checks


def test_certificate_error_reads_the_ssl_cause() -> None:
    cause = ssl.SSLCertVerificationError(1, "verify failed")
    cause.verify_message = "certificate has expired"
    error = httpx.ConnectError("fallo TLS")
    error.__cause__ = cause
    assert certificate_error(error) == "certificate has expired"
    assert certificate_error(httpx.ConnectError("connection refused")) is None
