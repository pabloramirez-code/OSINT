import asyncio
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from reconmap.checks import Status
from reconmap.engine import Engine
from reconmap.insights import ScanIndex
from reconmap.models import (
    Contact,
    Entity,
    EntityType,
    ModuleResult,
    Relation,
    RelationType,
    ScanStatus,
)
from reconmap.modules import docker_tools
from reconmap.modules.active_tools import (
    Gowitness,
    parse_gowitness,
    parse_httpx,
    parse_tlsx,
    screenshot_dir,
)
from reconmap.modules.base import Context, ModuleError
from reconmap.modules.docker_tools import TLSX_IMAGE, run_container, safe_hosts
from reconmap.store import Store
from reconmap.web.app import create_app
from tests.conftest import FIXTURES, FakeModule

TARGET = "example.com"
ALLOW = (TARGET,)
NAMES = ["desarrollo.example.com", "emods.example.com", "www.example.com",
         "www.scout.example.com"]  # fmt: skip
XSS = "<img src=x onerror=alert(1)>"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


# Hosts que llegan a la herramienta


def test_safe_hosts_only_valid_in_scope_and_allowlisted() -> None:
    hosts = [
        "www.example.com",
        "www.example.com",  # duplicado
        "WWW.example.com",  # sin normalizar: no se acepta tal cual
        "otro.org",  # fuera de ámbito
        "example.com.evil.net",
        "a.example.com;rm -rf /",  # caracteres de shell
        "$(id).example.com",
    ]
    assert safe_hosts(hosts, TARGET, ALLOW) == ["www.example.com"]
    assert safe_hosts(["www.example.com"], TARGET, ()) == []  # sin lista blanca, nada


# Lanzador de Docker (sin ejecutar Docker de verdad)


class FakeProcess:
    def __init__(self, returncode: int = 0, stdout: bytes = b"", stderr: bytes = b"") -> None:
        self.returncode = returncode
        self._out = (stdout, stderr)
        self.stdin_data = b""

    async def communicate(self, data: bytes) -> tuple[bytes, bytes]:
        self.stdin_data = data
        return self._out

    def kill(self) -> None:
        pass

    async def wait(self) -> int:
        return self.returncode


@pytest.fixture
def fake_exec(monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, object]]:
    calls: dict[str, object] = {"process": FakeProcess(stdout=b'{"host": "x"}\n')}

    async def create(*args: str, **kwargs: object) -> FakeProcess:
        calls["args"] = args
        calls["kwargs"] = kwargs
        return calls["process"]  # type: ignore[return-value]

    monkeypatch.setattr(docker_tools.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", create)
    yield calls


async def test_container_runs_without_shell_and_pinned_image(
    fake_exec: dict[str, object],
) -> None:
    run = await run_container(TLSX_IMAGE, ["-json"], ["www.example.com"], timeout=5)
    args = fake_exec["args"]
    assert args[:6] == ("docker", "run", "--rm", "-i", "--pull", "never")  # type: ignore[index]
    assert TLSX_IMAGE in args and "@sha256:" in TLSX_IMAGE  # type: ignore[operator]
    assert "shell" not in fake_exec["kwargs"]  # type: ignore[operator]
    process = fake_exec["process"]
    assert process.stdin_data == b"www.example.com\n"  # type: ignore[attr-defined]
    assert not process.stdin_data.startswith(b"\xef\xbb\xbf")  # type: ignore[attr-defined]
    assert run.command.startswith("docker run --rm -i --pull never")


async def test_container_errors_are_module_errors(fake_exec: dict[str, object]) -> None:
    fake_exec["process"] = FakeProcess(returncode=125, stderr=b"Unable to find image 'x' locally")
    with pytest.raises(ModuleError, match="docker pull"):
        await run_container(TLSX_IMAGE, [], ["www.example.com"], timeout=5)


async def test_missing_docker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(docker_tools.shutil, "which", lambda name: None)
    with pytest.raises(ModuleError, match="Docker no está instalado"):
        await run_container(TLSX_IMAGE, [], ["www.example.com"], timeout=5)


# Lectura de la salida real


def test_parse_tlsx() -> None:
    result = parse_tlsx(fixture("tlsx_example.jsonl"), TARGET, NAMES)
    tls = {e.value: e.attributes["tls_live"] for e in result.entities if "tls_live" in e.attributes}
    assert set(tls) == set(NAMES)
    scout = tls["www.scout.example.com"]
    assert scout["issues"] == ["autofirmado", "el nombre no coincide"]  # type: ignore[index]
    assert scout["foreign_names"] == ["ingress.local"]  # type: ignore[index]
    assert tls["emods.example.com"]["issues"] == []  # type: ignore[index]
    certs = [e for e in result.entities if e.type is EntityType.CERTIFICATE]
    assert all(c.value.isalnum() and c.value == c.value.lower() for c in certs)
    # example.com aparece en el SAN de www, pero es el propio objetivo: no es subdominio nuevo
    assert not [
        e
        for e in result.entities
        if e.type is EntityType.SUBDOMAIN and "tls_live" not in e.attributes
    ]


def test_parse_tlsx_new_subdomain_from_san() -> None:
    line = '{"host": "www.example.com", "subject_an": ["nuevo.example.com", "otro.org"]}'
    result = parse_tlsx(line, TARGET, ["www.example.com"])
    new = [r.to_ref.value for r in result.relations if r.type is RelationType.HAS_SUBDOMAIN]
    assert new == ["nuevo.example.com"]  # otro.org solo queda como texto (regla 3)


def test_parse_httpx() -> None:
    result = parse_httpx(fixture("httpx_example.jsonl"), TARGET, NAMES)
    probes = {
        e.value: e.attributes["http_probe"] for e in result.entities if "http_probe" in e.attributes
    }
    dev = probes["desarrollo.example.com"]
    assert dev["status_code"] == 200  # type: ignore[index]
    assert "PHP:8.3.36" in dev["tech"]  # type: ignore[index,operator]
    assert probes["www.example.com"]["location"] == "https://example.com/"  # type: ignore[index]
    techs = {e.value: e.attributes for e in result.entities if e.type is EntityType.TECHNOLOGY}
    assert techs["php:php:8.3.36"]["cpe"] == "cpe:2.3:a:php:php:8.3.36:*:*:*:*:*:*:*"
    assert techs["wappalyzer:site_kit:1.182.0"]["cpe"] is None  # sin equivalente en NVD
    assert techs["f5:nginx:*"]["cpe"] is None  # sin versión


def test_parse_gowitness_copies_screenshots_with_controlled_names(tmp_path: Path) -> None:
    shots, folder = tmp_path / "raw" / "shots", tmp_path / "capturas"
    shots.mkdir(parents=True)
    (shots / "https---desarrollo.example.com-443.jpeg").write_bytes(b"\xff\xd8jpeg")
    (shots / "https---emods.example.com-443.jpeg").write_bytes(b"\xff\xd8jpeg")
    result = parse_gowitness(fixture("gowitness_example.jsonl"), TARGET, NAMES, shots, folder)
    shot = {e.value: e.attributes["screenshot"] for e in result.entities}
    assert shot["desarrollo.example.com"]["file"] == "desarrollo.example.com.jpeg"  # type: ignore[index]
    assert (folder / "desarrollo.example.com.jpeg").is_file()
    assert "REDACTADO" not in str(result) and "PHPSESSID" not in str(result)


def test_parse_gowitness_rejects_path_tricks(tmp_path: Path) -> None:
    line = (
        '{"url": "https://www.example.com:443", "file_name": "../../secreto.jpeg",'
        ' "response_code": "200"}'
    )
    result = parse_gowitness(line, TARGET, ["www.example.com"], tmp_path, tmp_path / "out")
    assert result.entities[0].attributes["screenshot"]["file"] == ""  # type: ignore[index]


async def test_gowitness_deletes_raw_output_even_on_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ctx: Context
) -> None:
    async def failing(*args: object, mount: Path | None = None, **kwargs: object) -> None:
        assert mount is not None
        mount.mkdir(parents=True)
        (mount / "gowitness.jsonl").write_text('{"cookies": "secreto"}')
        raise ModuleError("falló")

    monkeypatch.setattr("reconmap.modules.active_tools.run_container", failing)
    ctx.scan_id, ctx.allowlist, ctx.data_dir, ctx.target = "0123456789ab", ALLOW, tmp_path, TARGET
    with pytest.raises(ModuleError):
        await Gowitness().run_batch([Entity(type=EntityType.SUBDOMAIN, value=NAMES[0])], ctx)
    assert not (tmp_path / "capturas" / "0123456789ab" / "raw").exists()


def test_screenshot_dir_rejects_bad_scan_ids(tmp_path: Path) -> None:
    with pytest.raises(ModuleError):
        screenshot_dir(tmp_path, "../../etc")


# Motor: fase final por lotes


class FakeBatch(FakeModule):
    batch = True

    def __init__(self) -> None:
        super().__init__(
            "lote",
            contact=Contact.ACTIVE,
            accepts=frozenset({EntityType.DOMAIN, EntityType.SUBDOMAIN}),
        )
        self.received: list[list[str]] = []

    async def run_batch(self, hosts: list[Entity], ctx: Context) -> ModuleResult:
        self.received.append(sorted(h.value for h in hosts))
        new = Entity(type=EntityType.SUBDOMAIN, value="nuevo.example.com")
        return ModuleResult(entities=[new])


class Resolver(FakeModule):
    async def run(self, entity: Entity, ctx: Context) -> ModuleResult:
        self.seen.append(entity.value)
        ip = Entity(type=EntityType.IP, value="198.51.100.1")
        if entity.value == "nada.example.com":
            return ModuleResult()
        return ModuleResult(
            entities=[ip],
            relations=[Relation(from_ref=entity.ref, type=RelationType.RESOLVES_TO, to_ref=ip.ref)],
        )


async def test_batch_runs_once_at_the_end_with_resolving_hosts(store: Store) -> None:
    found = FakeModule("crtsh", found=("www", "nada"))
    dns = Resolver("dns", accepts=frozenset({EntityType.DOMAIN, EntityType.SUBDOMAIN}))
    batch = FakeBatch()
    engine = Engine(store, [found, dns, batch], active_allowlist=ALLOW)  # type: ignore[list-item]
    scan_id = engine.create_scan(TARGET, allow_active=True)
    await engine.run(scan_id)
    assert batch.received == [["example.com", "www.example.com"]]  # sin "nada" (no resuelve)
    assert "nuevo.example.com" in dns.seen  # lo descubierto vuelve a la cola normal
    assert batch.seen == []  # nunca se llama host por host


# Interfaz


def build(store: Store, data_dir: Path, title: str = "Inicio") -> str:
    scan = store.create_scan(TARGET, allow_active=True)
    store.update_scan(scan.id, status=ScanStatus.DONE)
    folder = data_dir / "capturas" / scan.id
    folder.mkdir(parents=True)
    (folder / "www.example.com.jpeg").write_bytes(b"\xff\xd8jpeg")
    (data_dir / "secreto.txt").write_text("no")
    root = Entity(
        type=EntityType.DOMAIN,
        value=TARGET,
        attributes={
            "active_run_tlsx": {"command": "docker run --rm -i x", "seconds": 1.5, "hosts": 1}
        },
    )
    www = Entity(
        type=EntityType.SUBDOMAIN,
        value="www.example.com",
        attributes={
            "http_probe": {"status_code": 200, "title": title, "tech": ["PHP:8.3.36"]},
            "tls_live": {
                "issuer": "Let's Encrypt",
                "not_after": "2027-02-03",
                "issues": ["autofirmado"],
            },
            "screenshot": {"file": "www.example.com.jpeg", "status": "200", "title": title},
        },
    )
    store.save_result(scan.id, "t", ModuleResult(entities=[root, www]))
    return scan.id


@pytest.fixture
def app_client(store: Store, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("RECONMAP_DATA_DIR", str(tmp_path))
    return TestClient(create_app(store=store, modules=[], keys={}, active_allowlist=ALLOW))


def test_screenshot_route(app_client: TestClient, store: Store, tmp_path: Path) -> None:
    scan_id = build(store, tmp_path)
    response = app_client.get(f"/scans/{scan_id}/capturas/www.example.com.jpeg")
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/jpeg"
    assert response.headers["x-content-type-options"] == "nosniff"
    for bad in ("..%2F..%2Fsecreto.txt", "secreto.txt", "otro.example.com.jpeg"):
        assert app_client.get(f"/scans/{scan_id}/capturas/{bad}").status_code == 404


def test_active_tab(app_client: TestClient, store: Store, tmp_path: Path) -> None:
    page = app_client.get(f"/scans/{build(store, tmp_path, title=XSS)}/tabs/active").text
    assert "docker run --rm -i x" in page
    assert "/capturas/www.example.com.jpeg" in page
    assert "autofirmado" in page and "PHP:8.3.36" in page
    assert XSS not in page and "&lt;img src=x onerror=alert(1)&gt;" in page


def test_active_tab_for_non_active_scan(app_client: TestClient, store: Store) -> None:
    scan = store.create_scan(TARGET)
    store.update_scan(scan.id, status=ScanStatus.DONE)
    page = app_client.get(f"/scans/{scan.id}/tabs/active").text
    assert "Este escaneo no es Activo" in page and "está en la lista blanca" in page


def test_live_certificate_problem_reaches_host(store: Store, tmp_path: Path) -> None:
    index = ScanIndex(store, build(store, tmp_path))
    insights = index.insights("subdomain:www.example.com")
    assert insights is not None
    check = next(c for c in insights.problems if c.control == "Certificado (hoy)")
    assert check.status is Status.WARN and "autofirmado" in check.summary


# Modo local (dentro del contenedor)


async def test_local_runner_uses_binaries_and_real_folder(
    fake_exec: dict[str, object], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("RECONMAP_TOOLS_RUNNER", "local")
    monkeypatch.setattr(docker_tools.shutil, "which", lambda name: f"/usr/local/bin/{name}")
    await run_container(
        docker_tools.GOWITNESS_IMAGE, ["-s", "/out/shots", "-x", "/outro"], ["a.b"], 5, tmp_path
    )
    args = fake_exec["args"]
    assert args[0] == "/usr/local/bin/gowitness"  # type: ignore[index]
    assert "docker" not in args  # type: ignore[operator]
    out = str(tmp_path.resolve())
    assert list(args[1:]) == ["-s", f"{out}/shots", "-x", "/outro"]  # type: ignore[index]


async def test_local_runner_uses_httpx_toolkit(
    fake_exec: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RECONMAP_TOOLS_RUNNER", "local")
    monkeypatch.setattr(docker_tools.shutil, "which", lambda name: f"/bin/{name}")
    await run_container(docker_tools.HTTPX_IMAGE, [], ["a.b"], 5)
    assert fake_exec["args"][0] == "/bin/httpx-toolkit"  # type: ignore[index]


async def test_local_runner_missing_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RECONMAP_TOOLS_RUNNER", "local")
    monkeypatch.setattr(docker_tools.shutil, "which", lambda name: None)
    with pytest.raises(ModuleError, match="modo local"):
        await run_container(TLSX_IMAGE, [], ["a.b"], 5)
