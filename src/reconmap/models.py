from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


def utcnow() -> datetime:
    return datetime.now(UTC)


class EntityType(StrEnum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    ASN = "asn"
    ORG = "org"
    URL = "url"
    PORT = "port"
    CERTIFICATE = "certificate"
    CANDIDATE = "candidate"


class RelationType(StrEnum):
    HAS_SUBDOMAIN = "has_subdomain"
    RESOLVES_TO = "resolves_to"
    BELONGS_TO_ASN = "belongs_to_asn"
    OWNED_BY = "owned_by"
    EXPOSES_PORT = "exposes_port"
    HAS_CERTIFICATE = "has_certificate"
    ARCHIVED_URL = "archived_url"
    CNAME_TO = "cname_to"


class Contact(StrEnum):
    PASSIVE = "passive"
    LIGHT = "light"
    ACTIVE = "active"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ScanStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


class RunStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"


class EntityRef(BaseModel):
    model_config = ConfigDict(frozen=True)

    type: EntityType
    value: str


class Entity(BaseModel):
    type: EntityType
    value: str
    attributes: dict[str, object] = Field(default_factory=dict)
    sources: set[str] = Field(default_factory=set)
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)

    @property
    def ref(self) -> EntityRef:
        return EntityRef(type=self.type, value=self.value)


class Relation(BaseModel):
    from_ref: EntityRef
    type: RelationType
    to_ref: EntityRef
    source: str = ""
    observed_at: datetime = Field(default_factory=utcnow)


class ModuleResult(BaseModel):
    entities: list[Entity] = Field(default_factory=list)
    relations: list[Relation] = Field(default_factory=list)


class Evidence(BaseModel):
    source: str
    raw: str


class Finding(BaseModel):
    rule_id: str
    severity: Severity
    entity: EntityRef
    title: str
    evidence: list[Evidence] = Field(min_length=1)
    created_at: datetime = Field(default_factory=utcnow)


class ModuleProgress(BaseModel):
    module: str
    label: str
    status: RunStatus = RunStatus.PENDING
    done: int = 0
    total: int = 0
    results: int = 0
    requests: int = 0
    error: str | None = None


class Scan(BaseModel):
    id: str
    target: str
    depth: int = Field(default=1, ge=1, le=3)
    allow_light: bool = False
    status: ScanStatus = ScanStatus.PENDING
    created_at: datetime = Field(default_factory=utcnow)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    progress: list[ModuleProgress] = Field(default_factory=list)

    @property
    def is_active(self) -> bool:
        return self.status in {ScanStatus.PENDING, ScanStatus.RUNNING}

    @property
    def elapsed_seconds(self) -> int:
        if self.started_at is None:
            return 0
        end = self.finished_at or utcnow()
        return int((end - self.started_at).total_seconds())
