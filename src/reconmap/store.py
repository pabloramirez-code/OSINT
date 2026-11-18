import json
import sqlite3
import threading
import uuid
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path

from reconmap.cache import Cache
from reconmap.models import (
    Entity,
    EntityRef,
    EntityType,
    ModuleProgress,
    ModuleResult,
    Relation,
    RunStatus,
    Scan,
    ScanStatus,
    utcnow,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    depth INTEGER NOT NULL,
    allow_light INTEGER NOT NULL,
    status TEXT NOT NULL,
    host_limit_reached INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT
);
CREATE TABLE IF NOT EXISTS module_runs (
    scan_id TEXT NOT NULL REFERENCES scans(id),
    module TEXT NOT NULL,
    label TEXT NOT NULL,
    position INTEGER NOT NULL,
    status TEXT NOT NULL,
    done INTEGER NOT NULL DEFAULT 0,
    total INTEGER NOT NULL DEFAULT 0,
    results INTEGER NOT NULL DEFAULT 0,
    requests INTEGER NOT NULL DEFAULT 0,
    errors INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    PRIMARY KEY (scan_id, module)
);
CREATE TABLE IF NOT EXISTS entities (
    scan_id TEXT NOT NULL REFERENCES scans(id),
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    attributes TEXT NOT NULL,
    sources TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    PRIMARY KEY (scan_id, type, value)
);
CREATE TABLE IF NOT EXISTS relations (
    scan_id TEXT NOT NULL REFERENCES scans(id),
    from_type TEXT NOT NULL,
    from_value TEXT NOT NULL,
    type TEXT NOT NULL,
    to_type TEXT NOT NULL,
    to_value TEXT NOT NULL,
    source TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    PRIMARY KEY (scan_id, from_type, from_value, type, to_type, to_value, source)
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL REFERENCES scans(id),
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_value TEXT NOT NULL,
    title TEXT NOT NULL,
    evidence TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""

MIGRATIONS = {
    "scans": {"host_limit_reached": "INTEGER NOT NULL DEFAULT 0"},
    "module_runs": {"errors": "INTEGER NOT NULL DEFAULT 0"},
}

SCAN_FIELDS = {"status", "started_at", "finished_at", "host_limit_reached"}
RUN_FIELDS = {"status", "done", "total", "results", "requests", "errors", "error"}


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _dt(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def _sql_value(value: object) -> object:
    return value.isoformat() if isinstance(value, datetime) else value


class Store:
    def __init__(self, path: str | Path) -> None:
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._migrate()
        self.cache = Cache(self._conn, self._lock)

    def _migrate(self) -> None:
        """Añade columnas nuevas a bases de datos creadas por versiones anteriores."""
        for table, columns in MIGRATIONS.items():
            existing = {row["name"] for row in self._conn.execute(f"PRAGMA table_info({table})")}
            for column, ddl in columns.items():
                if column not in existing:
                    self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")

    def close(self) -> None:
        self._conn.close()

    def _query(self, sql: str, params: Iterable[object] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, tuple(params)).fetchall()

    def _update(
        self, table: str, allowed: set[str], where: dict[str, str], fields: dict[str, object]
    ) -> None:
        unknown = fields.keys() - allowed
        if unknown:
            raise ValueError(f"Columnas no permitidas: {sorted(unknown)}")
        assignments = ", ".join(f"{name} = ?" for name in fields)
        conditions = " AND ".join(f"{name} = ?" for name in where)
        params = [_sql_value(value) for value in fields.values()] + list(where.values())
        self._query(f"UPDATE {table} SET {assignments} WHERE {conditions}", params)  # noqa: S608

    # Escaneos

    def create_scan(self, target: str, depth: int = 1, allow_light: bool = False) -> Scan:
        scan = Scan(id=uuid.uuid4().hex[:12], target=target, depth=depth, allow_light=allow_light)
        self._query(
            "INSERT INTO scans (id, target, depth, allow_light, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                scan.id,
                scan.target,
                scan.depth,
                int(scan.allow_light),
                scan.status,
                _iso(scan.created_at),
            ),
        )
        return scan

    def get_scan(self, scan_id: str) -> Scan | None:
        rows = self._query("SELECT * FROM scans WHERE id = ?", (scan_id,))
        if not rows:
            return None
        scan = self._row_to_scan(rows[0])
        scan.progress = [
            ModuleProgress(
                module=row["module"],
                label=row["label"],
                status=RunStatus(row["status"]),
                done=row["done"],
                total=row["total"],
                results=row["results"],
                requests=row["requests"],
                errors=row["errors"],
                error=row["error"],
            )
            for row in self._query(
                "SELECT * FROM module_runs WHERE scan_id = ? ORDER BY position", (scan_id,)
            )
        ]
        return scan

    def list_scans(self, limit: int = 20) -> list[Scan]:
        rows = self._query("SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", (limit,))
        return [self._row_to_scan(row) for row in rows]

    def active_scan(self) -> Scan | None:
        rows = self._query(
            "SELECT * FROM scans WHERE status IN (?, ?) LIMIT 1",
            (ScanStatus.PENDING, ScanStatus.RUNNING),
        )
        return self._row_to_scan(rows[0]) if rows else None

    def update_scan(self, scan_id: str, **fields: object) -> None:
        self._update("scans", SCAN_FIELDS, {"id": scan_id}, fields)

    def fail_interrupted_scans(self) -> None:
        self._query(
            "UPDATE scans SET status = ?, finished_at = ? WHERE status IN (?, ?)",
            (ScanStatus.FAILED, _iso(utcnow()), ScanStatus.PENDING, ScanStatus.RUNNING),
        )

    @staticmethod
    def _row_to_scan(row: sqlite3.Row) -> Scan:
        return Scan(
            id=row["id"],
            target=row["target"],
            depth=row["depth"],
            allow_light=bool(row["allow_light"]),
            status=ScanStatus(row["status"]),
            host_limit_reached=bool(row["host_limit_reached"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            started_at=_dt(row["started_at"]),
            finished_at=_dt(row["finished_at"]),
        )

    # Progreso por módulo

    def start_module_runs(self, scan_id: str, modules: list[tuple[str, str]]) -> None:
        for position, (name, label) in enumerate(modules):
            self._query(
                "INSERT OR REPLACE INTO module_runs (scan_id, module, label, position, status) "
                "VALUES (?, ?, ?, ?, ?)",
                (scan_id, name, label, position, RunStatus.PENDING),
            )

    def update_module_run(self, scan_id: str, module: str, **fields: object) -> None:
        self._update("module_runs", RUN_FIELDS, {"scan_id": scan_id, "module": module}, fields)

    # Grafo

    def save_result(self, scan_id: str, source: str, result: ModuleResult) -> None:
        for entity in result.entities:
            self.upsert_entity(scan_id, entity, source)
        for relation in result.relations:
            self.add_relation(scan_id, relation.model_copy(update={"source": source}))

    def upsert_entity(self, scan_id: str, entity: Entity, source: str) -> None:
        key = (scan_id, entity.type, entity.value)
        with self._lock:
            row = self._conn.execute(
                "SELECT attributes, sources, first_seen FROM entities "
                "WHERE scan_id = ? AND type = ? AND value = ?",
                key,
            ).fetchone()
            attributes = json.loads(row["attributes"]) if row else {}
            attributes.update(entity.attributes)
            sources = set(json.loads(row["sources"])) if row else set()
            sources |= entity.sources | {source}
            first_seen = row["first_seen"] if row else _iso(entity.first_seen)
            self._conn.execute(
                "INSERT OR REPLACE INTO entities "
                "(scan_id, type, value, attributes, sources, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    *key,
                    json.dumps(attributes),
                    json.dumps(sorted(sources)),
                    first_seen,
                    _iso(utcnow()),
                ),
            )

    def add_relation(self, scan_id: str, relation: Relation) -> None:
        self._query(
            "INSERT OR IGNORE INTO relations VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                scan_id,
                relation.from_ref.type,
                relation.from_ref.value,
                relation.type,
                relation.to_ref.type,
                relation.to_ref.value,
                relation.source,
                _iso(relation.observed_at),
            ),
        )

    def entities(self, scan_id: str, entity_type: EntityType | None = None) -> list[Entity]:
        sql = "SELECT * FROM entities WHERE scan_id = ?"
        params: list[object] = [scan_id]
        if entity_type is not None:
            sql += " AND type = ?"
            params.append(entity_type)
        return [
            Entity(
                type=EntityType(row["type"]),
                value=row["value"],
                attributes=json.loads(row["attributes"]),
                sources=set(json.loads(row["sources"])),
                first_seen=datetime.fromisoformat(row["first_seen"]),
                last_seen=datetime.fromisoformat(row["last_seen"]),
            )
            for row in self._query(sql + " ORDER BY value", params)
        ]

    def relations(self, scan_id: str) -> list[Relation]:
        return [
            Relation(
                from_ref=EntityRef(type=row["from_type"], value=row["from_value"]),
                type=row["type"],
                to_ref=EntityRef(type=row["to_type"], value=row["to_value"]),
                source=row["source"],
                observed_at=datetime.fromisoformat(row["observed_at"]),
            )
            for row in self._query("SELECT * FROM relations WHERE scan_id = ?", (scan_id,))
        ]

    def first_seen_anywhere(self, scan_id: str, entity_type: EntityType) -> dict[str, datetime]:
        """Primera vez que se vio cada entidad de este escaneo en cualquier escaneo anterior."""
        rows = self._query(
            "SELECT value, MIN(first_seen) AS first_seen FROM entities "
            "WHERE type = ? AND value IN "
            "(SELECT value FROM entities WHERE scan_id = ? AND type = ?) "
            "GROUP BY value",
            (entity_type, scan_id, entity_type),
        )
        return {row["value"]: datetime.fromisoformat(row["first_seen"]) for row in rows}
