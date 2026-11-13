"""Adapter base class and helpers shared by the adapters."""

import re
from pathlib import Path


class AdapterError(Exception):
    pass


class Adapter:
    name = ""
    description = ""
    extensions = ()

    @classmethod
    def sniff(cls, path):
        """Return 0..100: how likely this adapter understands the file."""
        return 0

    def read(self, path, cfg, encoding="utf-8-sig"):
        """Yield SourceRecord objects."""
        raise NotImplementedError


def read_head(path, size=65536, encoding="utf-8-sig"):
    try:
        with open(path, encoding=encoding, errors="replace") as fh:
            return fh.read(size)
    except OSError:
        return ""


def file_stem(path):
    return re.sub(r"[^A-Za-z0-9_.-]", "_", Path(path).stem)


def column_lookup(columns):
    return {c.strip().lower(): c for c in columns}


def find_column(lookup, aliases):
    for alias in aliases:
        col = lookup.get(alias.strip().lower())
        if col is not None:
            return col
    return None


def first_value(row, lookup, aliases):
    """(column, value) for the first alias that is present and non-empty."""
    first = None
    for alias in aliases:
        col = lookup.get(alias.strip().lower())
        if col is None:
            continue
        first = first or col
        val = row.get(col)
        if val is not None and str(val).strip():
            return col, str(val)
    return first, ""


def matches_any(name, patterns):
    return any(re.search(p, name, re.IGNORECASE) for p in patterns)


def address_from_url(value):
    """Keep the host part of a URL as the address (https://h.example/x -> h.example)."""
    m = re.match(r"^[a-z][a-z0-9+.-]*://([^/?#]+)", value.strip(), re.IGNORECASE)
    if not m:
        return value.strip()
    host = m.group(1).rsplit("@", 1)[-1]
    if host.startswith("["):          # [IPv6]:port
        return host[1:].split("]", 1)[0]
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host
