from fastapi.testclient import TestClient

from reconmap.web.app import templates


def test_index_contains_domain_field(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert 'name="domain"' in response.text


def test_health(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_static_files_are_served(client: TestClient) -> None:
    assert client.get("/static/app.css").status_code == 200
    assert client.get("/static/table.js").status_code == 200


def test_jinja_autoescape_is_enabled() -> None:
    rendered = templates.env.from_string("{{ value }}").render(value="<b>")
    assert rendered == "&lt;b&gt;"
