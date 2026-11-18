from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


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


class RelationType(StrEnum):
    HAS_SUBDOMAIN = "has_subdomain"
    RESOLVES_TO = "resolves_to"
    BELONGS_TO_ASN = "belongs_to_asn"
    OWNED_BY = "owned_by"
    EXPOSES_PORT = "exposes_port"
    HAS_CERTIFICATE = "has_certificate"
    ARCHIVED_URL = "archived_url"
    CNAME_TO = "cname_to"


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


class Entity(BaseModel):
    type: EntityType
    value: str
    attributes: dict[str, object] = Field(default_factory=dict)
    sources: set[str] = Field(default_factory=set)
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)


class Relation(BaseModel):
    from_entity: Entity
    type: RelationType
    to_entity: Entity
    source: str
    observed_at: datetime = Field(default_factory=utcnow)


class Evidence(BaseModel):
    source: str
    raw: str


class Finding(BaseModel):
    rule_id: str
    severity: Severity
    entity: Entity
    title: str
    evidence: list[Evidence] = Field(min_length=1)
    created_at: datetime = Field(default_factory=utcnow)


class ModuleProgress(BaseModel):
    module: str
    status: ScanStatus = ScanStatus.PENDING
    done: int = 0
    total: int = 0
    results: int = 0
    error: str | None = None


class Scan(BaseModel):
    id: str
    target: str
    depth: int = Field(default=1, ge=1, le=3)
    status: ScanStatus = ScanStatus.PENDING
    started_at: datetime | None = None
    finished_at: datetime | None = None
    progress: list[ModuleProgress] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
