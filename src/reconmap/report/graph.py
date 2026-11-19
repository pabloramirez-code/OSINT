"""Grafo de entidades para Cytoscape.js: {nodes, edges}. Los valores viajan como texto;
la interfaz los pinta con textContent, nunca como HTML."""

import json
from collections.abc import Callable

from reconmap.insights import ScanIndex, short_label
from reconmap.models import Entity, EntityType, Relation
from reconmap.store import Store

MAX_NODES = 300
GROUP_ORDER = (EntityType.URL, EntityType.CERTIFICATE, EntityType.PORT, EntityType.CVE)
GROUP_LABELS = {
    EntityType.URL: "URLs archivadas",
    EntityType.CERTIFICATE: "certificados",
    EntityType.PORT: "puertos",
    EntityType.CVE: "CVEs",
}
MAX_DETAIL_LENGTH = 300
KEEP_CVSS = 9.0
TYPE_RANK = {t: i for i, t in enumerate(EntityType)}


def node_id(entity_type: str, value: str) -> str:
    return f"{entity_type}:{value}"


def build_graph(store: Store, scan_id: str, max_nodes: int = MAX_NODES) -> dict[str, object]:
    entities = sorted(
        store.entities(scan_id), key=lambda e: (e.first_seen, TYPE_RANK[e.type], e.value)
    )
    relations = store.relations(scan_id)
    kept = {node_id(e.type, e.value) for e in entities if _always_visible(e)}
    grouped = _types_to_group(entities, max_nodes, kept)
    index = ScanIndex(store, scan_id)

    def in_group(entity_type: EntityType, value: str) -> bool:
        return entity_type in grouped and node_id(entity_type, value) not in kept

    nodes: dict[str, dict[str, object]] = {}
    for entity in entities:
        if in_group(entity.type, entity.value):
            continue
        nid = node_id(entity.type, entity.value)
        insights = index.insights(nid)
        nodes[nid] = {**_node(entity), "worst": insights.worst if insights else None}
    for entity_type in grouped:
        members = [e for e in entities if e.type is entity_type and in_group(e.type, e.value)]
        if not members:
            continue
        count = len(members)
        nodes[_group_id(entity_type)] = {
            "id": _group_id(entity_type),
            "type": entity_type,
            "label": _group_label(entity_type, count, kept),
            "short": _group_label(entity_type, count, kept),
            "group": True,
            "sources": [],
            "details": {"Agrupados": f"{count} nodos de tipo {entity_type}"},
            "seen": members[0].first_seen.isoformat(),
            "worst": None,
        }
    ordered = sorted(nodes.values(), key=lambda n: str(n["seen"]))
    for position, node in enumerate(ordered):
        node["order"] = position

    edges: dict[str, dict[str, object]] = {}
    for relation in relations:
        edge = _edge(relation, in_group)
        if edge and edge["source"] in nodes and edge["target"] in nodes:
            edges[str(edge["id"])] = edge

    return {
        "nodes": ordered,
        "edges": list(edges.values()),
        "grouped": [str(t) for t in grouped],
    }


def _always_visible(entity: Entity) -> bool:
    """CVEs en KEV o con CVSS >= 9: nunca se esconden dentro de un grupo."""
    if entity.type is not EntityType.CVE:
        return False
    nvd = entity.attributes.get("nvd")
    if not isinstance(nvd, dict):
        return False
    score = nvd.get("cvss")
    return nvd.get("kev") is True or (isinstance(score, int | float) and score >= KEEP_CVSS)


def _group_label(entity_type: EntityType, count: int, kept: set[str]) -> str:
    if entity_type is EntityType.CVE and kept:
        return f"{count} CVEs más (CVSS < {KEEP_CVSS:g})"
    return f"{count} {GROUP_LABELS[entity_type]}"


def _types_to_group(
    entities: list[Entity], max_nodes: int, kept: set[str] | None = None
) -> list[EntityType]:
    """Agrupa tipos en el orden de GROUP_ORDER hasta que el grafo quepa en max_nodes."""
    kept = kept or set()
    total = len(entities)
    grouped = []
    for entity_type in GROUP_ORDER:
        if total <= max_nodes:
            break
        count = sum(
            e.type is entity_type and node_id(e.type, e.value) not in kept for e in entities
        )
        if count > 1:
            grouped.append(entity_type)
            total -= count - 1
    return grouped


def _group_id(entity_type: EntityType) -> str:
    return f"group:{entity_type}"


def _node(entity: Entity) -> dict[str, object]:
    return {
        "id": node_id(entity.type, entity.value),
        "type": entity.type,
        "label": entity.value,
        "short": short_label(entity),
        "group": False,
        "sources": sorted(entity.sources),
        "details": {key: _as_text(value) for key, value in sorted(entity.attributes.items())},
        "seen": entity.first_seen.isoformat(),
    }


def _edge(
    relation: Relation, in_group: Callable[[EntityType, str], bool]
) -> dict[str, object] | None:
    source = _endpoint(relation.from_ref.type, relation.from_ref.value, in_group)
    target = _endpoint(relation.to_ref.type, relation.to_ref.value, in_group)
    if source == target:
        return None
    return {
        "id": f"{source}|{relation.type}|{target}",
        "source": source,
        "target": target,
        "type": relation.type,
    }


def _endpoint(
    entity_type: EntityType, value: str, in_group: Callable[[EntityType, str], bool]
) -> str:
    return _group_id(entity_type) if in_group(entity_type, value) else node_id(entity_type, value)


def _as_text(value: object) -> str:
    if isinstance(value, str):
        text = value
    elif isinstance(value, list):
        text = ", ".join(str(item) for item in value)
    else:
        text = json.dumps(value, ensure_ascii=False)
    return text if len(text) <= MAX_DETAIL_LENGTH else text[: MAX_DETAIL_LENGTH - 1] + "…"
