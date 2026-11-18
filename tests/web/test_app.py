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


def test_landing_lists_modules_and_modes(client: TestClient) -> None:
    page = client.get("/").text
    assert "Fuente falsa" in page and "Módulo de prueba" in page
    assert 'name="authorized" value="1"' in page
    assert "Pasivo" in page and "Ligero" in page and "Activo" in page


def test_landing_images_are_served(client: TestClient) -> None:
    for name in ("progreso", "subdominios", "ips", "correo"):
        response = client.get(f"/static/img/captura-{name}.png")
        assert response.status_code == 200
        assert response.headers["content-type"] == "image/png"
