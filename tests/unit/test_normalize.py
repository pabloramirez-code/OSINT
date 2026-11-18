import pytest

from reconmap.normalize import Domain, InvalidDomainError, normalize_domain


def test_lowercases_and_strips_trailing_dot() -> None:
    assert normalize_domain("Ejemplo.COM.") == Domain("ejemplo.com", wildcard=False)


def test_wildcard_is_kept_as_attribute() -> None:
    assert normalize_domain("*.ejemplo.com") == Domain("ejemplo.com", wildcard=True)


def test_idn_is_converted_to_punycode() -> None:
    assert normalize_domain("señal.es").name == "xn--seal-hqa.es"


@pytest.mark.parametrize(
    "raw",
    ["no es un dominio", "", "a..b.com", "localhost", "-a.com", "a-.com", "1.2.3.4", "a_b.com"],
)
def test_invalid_domains_raise(raw: str) -> None:
    with pytest.raises(InvalidDomainError):
        normalize_domain(raw)
