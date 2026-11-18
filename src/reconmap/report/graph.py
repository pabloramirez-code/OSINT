"""Grafo de entidades para Cytoscape.js: {nodes, edges}. Los valores viajan como texto;
la interfaz los pinta con textContent, nunca como HTML."""

import json

from reconmap.models import Entity, EntityType, Relation
from reconmap.store import Store

MAX_NODES = 300
GROUP_ORDER = (EntityType.URL, EntityType.CERTIFICATE, EntityType.PORT)
GROUP_LABELS = {
    EntityType.URL: "URLs archivadas",
    EntityType.CERTIFICATE: "certificados",
    EntityType.PORT: "puertos",
}
MAX_DETAIL_LENGTH = 300
MAX_SHORT_LABEL = 30


def node_id(entity_type: str, value: str) -> str:
    return f"{entity_type}:{value}"


def build_graph(store: Store, scan_id: str, max_nodes: int = MAX_NODES) -> dict[str, object]:
    entities = store.entities(scan_id)
    relations = store.relations(scan_id)
    grouped = _types_to_group(entities, max_nodes)

    nodes: dict[str, dict[str, object]] = {}
    for entity in entities:
        if entity.type in grouped:
            continue
        nodes[node_id(entity.type, entity.value)] = _node(entity)
    for entity_type in grouped:
        count = sum(e.type is entity_type for e in entities)
        nodes[_group_id(entity_type)] = {
            "id": _group_id(entity_type),
            "type": entity_type,
            "label": f"{count} {GROUP_LABELS[entity_type]}",
            "short": f"{count} {GROUP_LABELS[entity_type]}",
            "group": True,
            "sources": [],
            "details": {"Agrupados": f"{count} nodos de tipo {entity_type}"},
        }

    edges: dict[str, dict[str, object]] = {}
    for relation in relations:
        edge = _edge(relation, grouped)
        if edge and edge["source"] in nodes and edge["target"] in nodes:
            edges[str(edge["id"])] = edge

    return {
        "nodes": list(nodes.values()),
        "edges": list(edges.values()),
        "grouped": [str(t) for t in grouped],
    }


def _types_to_group(entities: list[Entity], max_nodes: int) -> list[EntityType]:
    """Agrupa tipos en el orden de GROUP_ORDER hasta que el grafo quepa en max_nodes."""
    total = len(entities)
    grouped = []
    for entity_type in GROUP_ORDER:
        if total <= max_nodes:
            break
        count = sum(e.type is entity_type for e in entities)
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
    }


def short_label(entity: Entity) -> str:
    """Etiqueta corta para el canvas; el valor completo se ve en el panel lateral."""
    if entity.type is EntityType.PORT:
        text = entity.value.rsplit(":", 1)[-1]
    elif entity.type is EntityType.CERTIFICATE:
        text = f"cert. {str(entity.attributes.get('not_after', ''))[:10]}".strip()
    else:
        text = entity.value
    return text if len(text) <= MAX_SHORT_LABEL else text[: MAX_SHORT_LABEL - 1] + "…"


def _edge(relation: Relation, grouped: list[EntityType]) -> dict[str, object] | None:
    source = _endpoint(relation.from_ref.type, relation.from_ref.value, grouped)
    target = _endpoint(relation.to_ref.type, relation.to_ref.value, grouped)
    if source == target:
        return None
    return {
        "id": f"{source}|{relation.type}|{target}",
        "source": source,
        "target": target,
        "type": relation.type,
    }


def _endpoint(entity_type: EntityType, value: str, grouped: list[EntityType]) -> str:
    return _group_id(entity_type) if entity_type in grouped else node_id(entity_type, value)


def _as_text(value: object) -> str:
    if isinstance(value, str):
        text = value
    elif isinstance(value, list):
        text = ", ".join(str(item) for item in value)
    else:
        text = json.dumps(value, ensure_ascii=False)
    return text if len(text) <= MAX_DETAIL_LENGTH else text[: MAX_DETAIL_LENGTH - 1] + "…"
