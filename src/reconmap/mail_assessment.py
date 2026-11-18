"""Evaluación de la configuración de correo a partir de los datos de `modules/mail.py`.

Función pura, sin red. El nivel de riesgo se refiere solo a la suplantación del remitente
@dominio y se decide con criterios explícitos (ver `RISK_CRITERIA`), no con puntuaciones.
"""

import base64
import binascii
from dataclasses import dataclass, field
from enum import StrEnum

MAX_SPF_LOOKUPS = 10

RISK_CRITERIA = (
    "ALTO: no hay DMARC con p=quarantine o p=reject, o el SPF termina en +all.",
    "MEDIO: hay DMARC que bloquea, pero no se aplica a todo el correo (pct<100) "
    "o deja los subdominios sin protección (sp=none).",
    "BAJO: DMARC bloquea todo el correo suplantado del dominio y sus subdominios.",
)


class Status(StrEnum):
    OK = "ok"
    WARN = "warn"
    FAIL = "fail"
    INFO = "info"


class Risk(StrEnum):
    HIGH = "alto"
    MEDIUM = "medio"
    LOW = "bajo"


@dataclass(frozen=True)
class Check:
    control: str
    status: Status
    summary: str
    advice: str = ""


@dataclass(frozen=True)
class MailAssessment:
    risk: Risk
    reasons: list[str]
    checks: list[Check] = field(default_factory=list)


def parse_tags(record: str) -> dict[str, str]:
    """`v=DMARC1; p=reject; pct=100` → {"v": "DMARC1", "p": "reject", "pct": "100"}."""
    tags = {}
    for part in record.split(";"):
        key, sep, value = part.partition("=")
        if sep:
            tags[key.strip().lower()] = value.strip()
    return tags


def assess(mail: dict[str, object], mta_policy: dict[str, object] | None = None) -> MailAssessment:
    spf = _strings(mail.get("spf"))
    dmarc = _strings(mail.get("dmarc"))
    mx = _strings(mail.get("mx"))
    null_mx = mx == ["0 ."]
    lookups = mail.get("spf_lookups")
    raw_dkim = mail.get("dkim")
    dkim = raw_dkim if isinstance(raw_dkim, dict) else {}

    checks = [
        *_check_mx(mx, null_mx),
        *_check_spf(spf, lookups if isinstance(lookups, int) else 0),
        *_check_dmarc(dmarc),
        *_check_dkim(dkim, mail.get("dkim_selectors_tried"), null_mx),
        *_check_mta_sts(_strings(mail.get("mta_sts")), mta_policy, null_mx),
        _presence(
            "TLS-RPT",
            _strings(mail.get("tls_rpt")),
            ok="Publica informes de fallos TLS (TLS-RPT)",
            missing="Sin TLS-RPT: no recibirás avisos si falla el cifrado del correo entrante",
            status_missing=Status.INFO,
        ),
        _presence(
            "BIMI",
            _strings(mail.get("bimi")),
            ok="Publica un logo de marca (BIMI)",
            missing="Sin BIMI (opcional, solo afecta a la imagen de marca)",
            status_missing=Status.INFO,
        ),
        Check("DNSSEC", Status.OK, "El dominio está firmado con DNSSEC")
        if mail.get("dnssec")
        else Check(
            "DNSSEC",
            Status.WARN,
            "Sin DNSSEC: las respuestas DNS (incluidos SPF y DMARC) podrían falsificarse",
            "Activa DNSSEC en el registrador y en el proveedor DNS.",
        ),
    ]
    risk, reasons = _risk(spf, dmarc)
    return MailAssessment(risk=risk, reasons=reasons, checks=checks)


def _risk(spf: list[str], dmarc: list[str]) -> tuple[Risk, list[str]]:
    if len(spf) == 1 and _spf_all(spf[0]) == "+all":
        return Risk.HIGH, ["El SPF termina en +all: autoriza a cualquier servidor del mundo."]
    tags = parse_tags(dmarc[0]) if len(dmarc) == 1 else {}
    policy = tags.get("p", "").lower()
    if policy not in {"quarantine", "reject"}:
        return Risk.HIGH, [
            "No hay DMARC que bloquee: los receptores no tienen instrucción de rechazar "
            "correos que suplanten el remitente @dominio."
        ]
    reasons = []
    if _pct(tags) < 100:
        reasons.append(f"DMARC solo se aplica al {_pct(tags)} % del correo (pct).")
    if tags.get("sp", "").lower() == "none":
        reasons.append("Los subdominios no están protegidos (sp=none).")
    return (Risk.MEDIUM, reasons) if reasons else (Risk.LOW, [])


def _check_mx(mx: list[str], null_mx: bool) -> list[Check]:
    if null_mx:
        return [Check("MX", Status.INFO, "MX nulo: el dominio declara que no recibe correo")]
    if not mx:
        return [Check("MX", Status.INFO, "Sin registros MX: el dominio no recibe correo")]
    return [Check("MX", Status.OK, f"{len(mx)} servidor(es) de correo entrante")]


def _check_spf(spf: list[str], lookups: int) -> list[Check]:
    if not spf:
        return [
            Check(
                "SPF",
                Status.FAIL,
                "No hay registro SPF",
                "Publica un TXT `v=spf1 … -all` con los servidores que envían tu correo "
                "(o `v=spf1 -all` si el dominio no envía correo).",
            )
        ]
    if len(spf) > 1:
        return [
            Check(
                "SPF",
                Status.FAIL,
                f"Hay {len(spf)} registros SPF; el estándar exige uno (error permanente)",
                "Unifica todos los mecanismos en un único registro.",
            )
        ]
    record = spf[0]
    checks = [_spf_all_check(_spf_all(record), "redirect=" in record.lower())]
    if lookups > MAX_SPF_LOOKUPS:
        checks.append(
            Check(
                "SPF",
                Status.FAIL,
                f"Necesita {lookups} consultas DNS (máximo {MAX_SPF_LOOKUPS}): "
                "los receptores lo darán por erróneo",
                "Elimina `include` innecesarios o aplana el SPF.",
            )
        )
    else:
        checks.append(
            Check("SPF", Status.OK, f"{lookups} consultas DNS (máximo {MAX_SPF_LOOKUPS})")
        )
    if any(term.lower().lstrip("+-~?").startswith("ptr") for term in record.split()):
        checks.append(
            Check("SPF", Status.WARN, "Usa el mecanismo `ptr`, desaconsejado por el RFC 7208")
        )
    return checks


def _spf_all(record: str) -> str | None:
    for term in record.split()[1:]:
        lowered = term.lower()
        if lowered.endswith("all") and lowered.lstrip("+-~?") == "all":
            return lowered if lowered[0] in "+-~?" else "+all"
    return None


def _spf_all_check(qualifier: str | None, has_redirect: bool) -> Check:
    if qualifier == "-all":
        return Check("SPF", Status.OK, "Termina en -all: rechaza servidores no autorizados")
    if qualifier == "~all":
        return Check("SPF", Status.OK, "Termina en ~all (softfail): aceptable si DMARC bloquea")
    if qualifier == "?all":
        return Check(
            "SPF", Status.WARN, "Termina en ?all (neutral): no protege", "Usa ~all o -all."
        )
    if qualifier == "+all":
        return Check(
            "SPF",
            Status.FAIL,
            "Termina en +all: cualquier servidor puede enviar como tu dominio",
            "Sustitúyelo por -all o ~all.",
        )
    if has_redirect:
        return Check("SPF", Status.OK, "Delega en otro dominio con redirect=")
    return Check(
        "SPF", Status.WARN, "No termina en un mecanismo `all`", "Añade ~all o -all al final."
    )


def _check_dmarc(dmarc: list[str]) -> list[Check]:
    if not dmarc:
        return [
            Check(
                "DMARC",
                Status.FAIL,
                "No hay registro DMARC",
                "Publica `_dmarc` con `v=DMARC1; p=none; rua=mailto:…`, revisa los informes "
                "y sube a `p=quarantine` y después a `p=reject`.",
            )
        ]
    if len(dmarc) > 1:
        return [Check("DMARC", Status.FAIL, f"Hay {len(dmarc)} registros DMARC; debe haber uno")]

    tags = parse_tags(dmarc[0])
    policy = tags.get("p", "").lower()
    checks = []
    if policy == "reject":
        checks.append(Check("DMARC", Status.OK, "p=reject: el correo suplantado se rechaza"))
    elif policy == "quarantine":
        checks.append(
            Check(
                "DMARC",
                Status.OK,
                "p=quarantine: el correo suplantado va a spam",
                "p=reject es más estricto.",
            )
        )
    elif policy == "none":
        checks.append(
            Check(
                "DMARC",
                Status.FAIL,
                "p=none: solo monitoriza, no bloquea la suplantación",
                "Cuando los informes estén limpios, sube a p=quarantine o p=reject.",
            )
        )
    else:
        checks.append(Check("DMARC", Status.FAIL, "Política p= ausente o no válida"))

    if _pct(tags) < 100:
        checks.append(
            Check("DMARC", Status.WARN, f"pct={_pct(tags)}: solo se aplica a parte del correo")
        )
    if tags.get("sp", "").lower() == "none" and policy in {"quarantine", "reject"}:
        checks.append(Check("DMARC", Status.WARN, "sp=none: los subdominios se pueden suplantar"))
    if "rua" not in tags:
        checks.append(
            Check(
                "DMARC",
                Status.INFO,
                "Sin informes agregados (rua)",
                "Añade rua=mailto:… para saber quién envía correo con tu dominio.",
            )
        )
    return checks


def _check_dkim(dkim: dict[object, object], tried: object, null_mx: bool) -> list[Check]:
    if not dkim:
        return [
            Check(
                "DKIM",
                Status.INFO if null_mx else Status.WARN,
                f"No encontrado en los {tried or 'N'} selectores habituales "
                "(puede usar otro selector)",
                "Comprueba en tu proveedor de correo que la firma DKIM está activa.",
            )
        ]
    active = {str(s): str(r) for s, r in dkim.items() if parse_tags(str(r)).get("p", "").strip()}
    checks = [_dkim_key_check(selector, record) for selector, record in active.items()]
    revoked = len(dkim) - len(active)
    if revoked and active:
        checks.append(
            Check("DKIM", Status.INFO, f"{revoked} selector(es) con la clave revocada (p= vacío)")
        )
    elif revoked:
        checks.append(
            Check(
                "DKIM",
                Status.INFO,
                "Todas las claves DKIM encontradas están revocadas: el dominio declara "
                "que no firma correo",
            )
        )
    return checks


def _dkim_key_check(selector: str, record: str) -> Check:
    tags = parse_tags(record)
    key = tags.get("p", "").replace(" ", "")
    if not key:
        return Check("DKIM", Status.INFO, f"Selector {selector}: clave revocada (p= vacío)")
    if tags.get("k", "rsa").lower() == "ed25519":
        return Check("DKIM", Status.OK, f"Selector {selector}: clave Ed25519")
    bits = rsa_key_bits(key)
    if bits is None:
        return Check("DKIM", Status.WARN, f"Selector {selector}: clave no interpretable")
    if bits < 1024:
        return Check(
            "DKIM", Status.FAIL, f"Selector {selector}: RSA de {bits} bits (rompible)", "Usa 2048."
        )
    if bits < 2048:
        return Check(
            "DKIM", Status.WARN, f"Selector {selector}: RSA de {bits} bits", "Rota a 2048 bits."
        )
    return Check("DKIM", Status.OK, f"Selector {selector}: RSA de {bits} bits")


def _check_mta_sts(
    records: list[str], policy: dict[str, object] | None, null_mx: bool
) -> list[Check]:
    if null_mx:
        return [Check("MTA-STS", Status.INFO, "No aplica: el dominio no recibe correo")]
    if not records:
        return [
            Check(
                "MTA-STS",
                Status.WARN,
                "Sin MTA-STS: el correo entrante podría degradarse a texto sin cifrar",
                "Publica `_mta-sts` y una política con mode: enforce.",
            )
        ]
    if policy is None:
        return [
            Check(
                "MTA-STS",
                Status.INFO,
                "Registro publicado; política no comprobada (requiere la casilla de autorización)",
            )
        ]
    if "error" in policy:
        return [
            Check(
                "MTA-STS",
                Status.WARN,
                f"Registro publicado, pero la política falla: {policy['error']}",
            )
        ]
    mode = str(policy.get("mode", "")).lower()
    if mode == "enforce":
        return [Check("MTA-STS", Status.OK, "Política en modo enforce")]
    return [
        Check(
            "MTA-STS",
            Status.WARN,
            f"Política en modo {mode or 'desconocido'}: no obliga a cifrar",
            "Cambia a mode: enforce cuando los informes TLS-RPT estén limpios.",
        )
    ]


def _presence(
    control: str, records: list[str], ok: str, missing: str, status_missing: Status
) -> Check:
    return Check(control, Status.OK, ok) if records else Check(control, status_missing, missing)


def _pct(tags: dict[str, str]) -> int:
    try:
        return int(tags.get("pct", "100"))
    except ValueError:
        return 100


def _strings(value: object) -> list[str]:
    return [str(item) for item in value] if isinstance(value, list) else []


def rsa_key_bits(key_b64: str) -> int | None:
    """Tamaño del módulo RSA de una clave DKIM (SubjectPublicKeyInfo o PKCS#1, en DER)."""
    try:
        der = base64.b64decode(key_b64, validate=True)
    except (binascii.Error, ValueError):
        return None
    return _rsa_modulus_bits(der)


def _rsa_modulus_bits(der: bytes) -> int | None:
    try:
        tag, start, _end = _tlv(der, 0)
        if tag != 0x30:
            return None
        inner_tag, inner_start, inner_end = _tlv(der, start)
        if inner_tag == 0x02:
            return int.from_bytes(der[inner_start:inner_end], "big").bit_length()
        if inner_tag == 0x30:
            bit_tag, bit_start, bit_end = _tlv(der, inner_end)
            if bit_tag != 0x03:
                return None
            return _rsa_modulus_bits(der[bit_start + 1 : bit_end])
    except IndexError:
        return None
    return None


def _tlv(data: bytes, pos: int) -> tuple[int, int, int]:
    """Lee una cabecera DER: devuelve (etiqueta, inicio del valor, fin del valor)."""
    tag, length = data[pos], data[pos + 1]
    pos += 2
    if length & 0x80:
        size = length & 0x7F
        length = int.from_bytes(data[pos : pos + size], "big")
        pos += size
    if pos + length > len(data):
        raise IndexError("DER truncado")
    return tag, pos, pos + length
