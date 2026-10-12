"""A list key of an upstream YAML file, read as the importers need it."""

from __future__ import annotations


def items(data: dict, key: str, kind: type) -> list:
    """The items of list key `key`: none when it is absent or empty (YAML
    loads an empty key as null), and a null item skipped. A value that isn't
    a list, or an item that isn't a `kind`, raises: the file is an error,
    counted and named, never read as empty (a mapping would iterate as its
    keys, a string as its characters)."""
    value = data.get(key)
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{key} is a {type(value).__name__}, not a list")
    for item in value:
        if item is not None and not isinstance(item, kind):
            raise ValueError(
                f"{key} holds a {type(item).__name__}, not a {kind.__name__}"
            )
    return [item for item in value if item is not None]
