import re
from typing import NamedTuple

MAX_DOMAIN_LENGTH = 253
LABEL_PATTERN = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class InvalidDomainError(ValueError):
    pass


class Domain(NamedTuple):
    name: str
    wildcard: bool = False


def normalize_domain(raw: str) -> Domain:
    """Minúsculas, sin punto final, IDNA (punycode) y comodín `*.` separado como atributo."""
    text = raw.strip().lower().removesuffix(".")
    wildcard = text.startswith("*.")
    text = text.removeprefix("*.")

    labels = [_to_ascii_label(label, raw) for label in text.split(".")]
    name = ".".join(labels)

    if len(labels) < 2 or len(name) > MAX_DOMAIN_LENGTH or labels[-1].isdigit():
        raise InvalidDomainError(f"Dominio no válido: {raw!r}")
    return Domain(name, wildcard)


def _to_ascii_label(label: str, raw: str) -> str:
    try:
        ascii_label = label if label.isascii() else label.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InvalidDomainError(f"Dominio no válido: {raw!r}") from exc
    if not LABEL_PATTERN.match(ascii_label):
        raise InvalidDomainError(f"Dominio no válido: {raw!r}")
    return ascii_label
