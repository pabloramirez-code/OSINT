def in_scope(name: str, target: str) -> bool:
    return name == target or name.endswith("." + target)
