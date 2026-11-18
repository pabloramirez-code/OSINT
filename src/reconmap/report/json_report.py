from reconmap.store import Store


def build_report(store: Store, scan_id: str) -> dict[str, object] | None:
    scan = store.get_scan(scan_id)
    if scan is None:
        return None
    return {
        "scan": scan.model_dump(mode="json"),
        "entities": [e.model_dump(mode="json") for e in store.entities(scan_id)],
        "relations": [r.model_dump(mode="json") for r in store.relations(scan_id)],
        "findings": [],
    }
