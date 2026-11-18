from reconmap.report.compare import compare

REPORT = {
    "scan": {"target": "example.com"},
    "entities": [
        {"type": "domain", "value": "example.com"},
        {"type": "subdomain", "value": "www.example.com"},
        {"type": "subdomain", "value": "api.example.com"},
        {"type": "ip", "value": "192.0.2.1"},
    ],
}
AMASS = """WWW.example.com
mail.example.com
example.com
evil.example.com.attacker.net
no es un dominio

"""


def test_compare_splits_and_normalizes() -> None:
    result = compare(REPORT, AMASS, "amass")
    assert result.only_reconmap == ["api.example.com"]
    assert result.only_other == ["mail.example.com"]
    assert result.both == ["www.example.com"]


def test_markdown_lists_each_group() -> None:
    markdown = compare(REPORT, AMASS, "amass").to_markdown()
    assert "| Solo amass | 1 |" in markdown
    assert "- `mail.example.com`" in markdown
