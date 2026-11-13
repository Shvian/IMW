"""Source adapter registry.

An adapter turns one exported file into SourceRecord objects. To add a source,
write a module with a class that subclasses Adapter, then list it in ADAPTERS.
"""

from .base import Adapter, AdapterError  # noqa: F401
from .delinea import DelineaAdapter
from .keepass import KeePassAdapter
from .table import TableAdapter

ADAPTERS = {a.name: a for a in (DelineaAdapter, KeePassAdapter, TableAdapter)}


def get_adapter(name):
    try:
        return ADAPTERS[name.lower()]()
    except KeyError:
        raise AdapterError(f"unknown source '{name}'; choose one of: {', '.join(ADAPTERS)}")


def detect_adapter(path):
    """Pick the adapter whose sniff() scores highest for this file."""
    best, best_score = None, 0
    for cls in ADAPTERS.values():
        score = cls.sniff(path)
        if score > best_score:
            best, best_score = cls, score
    if best is None:
        raise AdapterError(f"cannot tell what kind of export {path} is; pass --source")
    return best()
