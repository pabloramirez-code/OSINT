import pytest

from reconmap.models import Entity, EntityType, ScanStatus
from reconmap.scope import in_scope
from reconmap.store import Store


def test_same_entity_from_two_sources_is_one_row(store: Store) -> None:
    scan = store.create_scan("example.com")
    entity = Entity(type=EntityType.SUBDOMAIN, value="www.example.com")
    store.upsert_entity(scan.id, entity, "crtsh")
    store.upsert_entity(scan.id, entity, "dns")

    rows = store.entities(scan.id, EntityType.SUBDOMAIN)
    assert len(rows) == 1
    assert rows[0].sources == {"crtsh", "dns"}


def test_attributes_are_merged(store: Store) -> None:
    scan = store.create_scan("example.com")
    store.upsert_entity(
        scan.id, Entity(type=EntityType.DOMAIN, value="example.com", attributes={"a": 1}), "x"
    )
    store.upsert_entity(
        scan.id, Entity(type=EntityType.DOMAIN, value="example.com", attributes={"b": 2}), "y"
    )
    assert store.entities(scan.id)[0].attributes == {"a": 1, "b": 2}


def test_interrupted_scans_are_marked_failed(store: Store) -> None:
    scan = store.create_scan("example.com")
    store.update_scan(scan.id, status=ScanStatus.RUNNING)
    store.fail_interrupted_scans()
    assert store.get_scan(scan.id).status is ScanStatus.FAILED  # type: ignore[union-attr]


def test_update_rejects_unknown_columns(store: Store) -> None:
    scan = store.create_scan("example.com")
    with pytest.raises(ValueError, match="no permitidas"):
        store.update_scan(scan.id, target="evil.com")


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("api.ejemplo.com", True),
        ("ejemplo.com", True),
        ("ejemplo.com.evil.net", False),
        ("otroejemplo.com", False),
    ],
)
def test_in_scope(name: str, expected: bool) -> None:
    assert in_scope(name, "ejemplo.com") is expected
