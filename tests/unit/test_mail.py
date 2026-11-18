import dns.exception
import dns.resolver
import pytest
import respx

from reconmap.mail_assessment import Risk, Status, assess, parse_tags, rsa_key_bits
from reconmap.models import Entity, EntityType
from reconmap.modules.base import Context, ModuleError
from reconmap.modules.dns import Resolve
from reconmap.modules.mail import Mail, join_txt, redact_mailto
from reconmap.modules.mta_sts import MtaSts, parse_policy
from tests.conftest import load_fixture

ROOT = Entity(type=EntityType.DOMAIN, value="example.com")
SECURE = {
    "mx": ["10 mx.example.com."],
    "spf": ["v=spf1 include:_spf.example.net -all"],
    "spf_lookups": 1,
    "dmarc": ["v=DMARC1; p=reject; rua=mailto:***@example.com"],
    "dkim": {},
    "dnssec": True,
}


def fixture(domain: str) -> dict[str, object]:
    data = load_fixture(f"mail_{domain}.json")
    assert isinstance(data, dict)
    return data


def statuses(data: dict[str, object], control: str) -> list[Status]:
    return [c.status for c in assess(data).checks if c.control == control]


def with_(**changes: object) -> dict[str, object]:
    return {**SECURE, **changes}


# Riesgo de suplantación


def test_domain_that_sends_no_mail_is_low_risk() -> None:
    report = assess(fixture("example.com"))
    assert report.risk is Risk.LOW
    dkim = [c for c in report.checks if c.control == "DKIM"]
    assert len(dkim) == 1 and "revocadas" in dkim[0].summary


@pytest.mark.parametrize(
    "dmarc", [[], ["v=DMARC1; p=none; rua=mailto:***@example.com"]], ids=["sin", "none"]
)
def test_without_enforcing_dmarc_risk_is_high(dmarc: list[str]) -> None:
    assert assess(with_(dmarc=dmarc)).risk is Risk.HIGH


def test_plus_all_is_high_even_with_reject() -> None:
    report = assess(with_(spf=["v=spf1 +all"]))
    assert report.risk is Risk.HIGH
    assert Status.FAIL in statuses(with_(spf=["v=spf1 +all"]), "SPF")


@pytest.mark.parametrize(
    "record", ["v=DMARC1; p=reject; pct=50", "v=DMARC1; p=reject; sp=none"], ids=["pct", "sp"]
)
def test_partial_dmarc_is_medium(record: str) -> None:
    assert assess(with_(dmarc=[record])).risk is Risk.MEDIUM


def test_real_senders_are_low_risk() -> None:
    assert assess(fixture("github.com")).risk is Risk.LOW
    assert assess(fixture("proton.me")).risk is Risk.LOW


# SPF


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        ("v=spf1 -all", Status.OK),
        ("v=spf1 include:x.test ~all", Status.OK),
        ("v=spf1 ?all", Status.WARN),
        ("v=spf1 ip4:192.0.2.1", Status.WARN),
        ("v=spf1 all", Status.FAIL),
    ],
)
def test_spf_all_qualifier(record: str, expected: Status) -> None:
    assert statuses(with_(spf=[record]), "SPF")[0] is expected


def test_spf_errors() -> None:
    assert statuses(with_(spf=["v=spf1 -all", "v=spf1 ~all"]), "SPF") == [Status.FAIL]
    assert statuses(with_(spf=[]), "SPF") == [Status.FAIL]
    assert Status.FAIL in statuses(with_(spf_lookups=11), "SPF")
    assert Status.WARN in statuses(with_(spf=["v=spf1 ptr -all"]), "SPF")


async def test_spf_lookup_counting_follows_includes_without_looping(
    ctx: Context, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Mail, "rate_limit", 1000.0)
    records = {
        "example.com": ['"v=spf1 include:a.test include:b.test mx -all"'],
        "a.test": ['"v=spf1 include:b.test ip4:192.0.2.1 -all"'],
        "b.test": ['"v=spf1 include:a.test a -all"'],
    }

    async def resolve(name: str, record_type: str) -> list[str]:
        if record_type == "TXT" and name in records:
            return records[name]
        raise dns.resolver.NoAnswer

    data = (await Mail(resolve).run(ROOT, ctx)).entities[0].attributes["mail"]
    assert isinstance(data, dict)
    assert data["spf_lookups"] == 6


# DMARC y DKIM


def test_dmarc_details() -> None:
    assert Status.WARN in statuses(with_(dmarc=["v=DMARC1; p=reject; pct=20"]), "DMARC")
    assert Status.INFO in statuses(with_(dmarc=["v=DMARC1; p=reject"]), "DMARC")
    assert parse_tags("v=DMARC1;p=reject; sp = none")["sp"] == "none"


def test_dkim_key_strength_from_real_keys() -> None:
    github = fixture("github.com")
    dkim = github["dkim"]
    assert isinstance(dkim, dict)
    assert rsa_key_bits(parse_tags(dkim["selector1"])["p"]) == 1024
    assert rsa_key_bits(parse_tags(dkim["google"])["p"]) == 2048
    assert statuses(github, "DKIM").count(Status.WARN) == 2


def test_dkim_ed25519_and_unknown() -> None:
    assert statuses(with_(dkim={"s": "v=DKIM1; k=ed25519; p=abc"}), "DKIM") == [Status.OK]
    assert statuses(with_(dkim={"s": "v=DKIM1; p=!!notbase64"}), "DKIM") == [Status.WARN]
    assert statuses(with_(dkim={}), "DKIM") == [Status.WARN]


def test_reporting_addresses_are_redacted() -> None:
    record = "v=DMARC1; p=reject; rua=mailto:jane.doe@example.com,mailto:x@vendor.test"
    assert redact_mailto(record) == (
        "v=DMARC1; p=reject; rua=mailto:***@example.com,mailto:***@vendor.test"
    )
    github = fixture("github.com")
    assert "dmarc@" not in str(github["dmarc"])


def test_join_txt_segments() -> None:
    assert join_txt('"v=spf1 include:a.test " "-all"') == "v=spf1 include:a.test -all"
    assert join_txt("sin comillas") == "sin comillas"


# MTA-STS


def test_mta_sts_states() -> None:
    proton = fixture("proton.me")
    assert statuses(proton, "MTA-STS") == [Status.INFO]
    enforce = assess(proton, {"version": "STSv1", "mode": "enforce", "mx": []})
    assert [c.status for c in enforce.checks if c.control == "MTA-STS"] == [Status.OK]
    testing = assess(proton, {"version": "STSv1", "mode": "testing", "mx": []})
    assert [c.status for c in testing.checks if c.control == "MTA-STS"] == [Status.WARN]
    assert statuses(fixture("github.com"), "MTA-STS") == [Status.WARN]


def test_parse_policy() -> None:
    policy = parse_policy(
        "version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: *.example.net\nmax_age: 604800\n"
    )
    assert policy == {
        "version": "STSv1",
        "mode": "enforce",
        "mx": ["mail.example.com", "*.example.net"],
        "max_age": "604800",
    }
    assert "error" in parse_policy("<html>no es una política</html>")


def txt_resolver(records: dict[str, list[str]]) -> Resolve:
    async def resolve(name: str, record_type: str) -> list[str]:
        if name in records:
            return records[name]
        raise dns.resolver.NXDOMAIN

    return resolve


@respx.mock
async def test_mta_sts_without_record_makes_no_request(ctx: Context) -> None:
    result = await MtaSts(txt_resolver({})).run(ROOT, ctx)
    assert result.entities == []
    assert not respx.calls


MTA_STS_URL = "https://mta-sts.example.com/.well-known/mta-sts.txt"
WITH_RECORD = {"_mta-sts.example.com": ['"v=STSv1; id=1"']}


@respx.mock
async def test_mta_sts_fetches_policy(ctx: Context) -> None:
    respx.get(MTA_STS_URL).respond(text="version: STSv1\nmode: enforce\nmx: mx.example.com")
    result = await MtaSts(txt_resolver(WITH_RECORD)).run(ROOT, ctx)
    policy = result.entities[0].attributes["mta_sts_policy"]
    assert isinstance(policy, dict) and policy["mode"] == "enforce"


@respx.mock
async def test_mta_sts_does_not_follow_redirects(ctx: Context) -> None:
    respx.get(MTA_STS_URL).respond(301, headers={"Location": "https://evil.test/"})
    result = await MtaSts(txt_resolver(WITH_RECORD)).run(ROOT, ctx)
    policy = result.entities[0].attributes["mta_sts_policy"]
    assert isinstance(policy, dict) and "redirección" in str(policy["error"])
    assert len(respx.calls) == 1


# Timeouts de DNS


def flaky_resolver(slow: set[str]) -> Resolve:
    async def resolve(name: str, record_type: str) -> list[str]:
        if name in slow:
            raise dns.exception.Timeout
        if name == "example.com" and record_type == "TXT":
            return ['"v=spf1 -all"']
        if name == "_dmarc.example.com":
            return ['"v=DMARC1; p=reject"']
        raise dns.resolver.NXDOMAIN

    return resolve


async def test_timeout_marks_record_unchecked_instead_of_failing(
    ctx: Context, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Mail, "rate_limit", 1000.0)
    slow = {"s2._domainkey.example.com", "_smtp._tls.example.com"}
    data = (await Mail(flaky_resolver(slow)).run(ROOT, ctx)).entities[0].attributes["mail"]
    assert isinstance(data, dict)
    assert set(data["unresolved"]) == {"TLS-RPT", "DKIM:s2"}  # type: ignore[arg-type]
    report = assess(data)
    assert report.risk is Risk.LOW
    tls = [c for c in report.checks if c.control == "TLS-RPT"]
    assert len(tls) == 1 and "no comprobado" in tls[0].summary
    assert any("1 selector(es) no se pudieron" in c.summary for c in report.checks)


async def test_timeout_in_dmarc_makes_risk_unknown(
    ctx: Context, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Mail, "rate_limit", 1000.0)
    data = (await Mail(flaky_resolver({"_dmarc.example.com"})).run(ROOT, ctx)).entities[0]
    mail = data.attributes["mail"]
    assert isinstance(mail, dict)
    assert assess(mail).risk is Risk.UNKNOWN


async def test_partial_results_are_not_cached(
    ctx: Context, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Mail, "rate_limit", 1000.0)
    await Mail(flaky_resolver({"_dmarc.example.com"})).run(ROOT, ctx)
    data = (await Mail(flaky_resolver(set())).run(ROOT, ctx)).entities[0].attributes["mail"]
    assert isinstance(data, dict) and data["unresolved"] == []


async def test_all_timeouts_is_a_module_error(
    ctx: Context, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Mail, "rate_limit", 1000.0)

    async def dead(name: str, record_type: str) -> list[str]:
        raise dns.exception.Timeout

    with pytest.raises(ModuleError, match="RECONMAP_DNS_SERVERS"):
        await Mail(dead).run(ROOT, ctx)
