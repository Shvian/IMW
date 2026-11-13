"""Turn one tabular row (dict of column -> value) into a SourceRecord.

Shared by the Delinea adapter and the generic CSV/Excel adapter.
"""

import re
from collections import OrderedDict

from ..model import Grant, SourceRecord, split_folder
from .base import column_lookup, first_value, matches_any

ACCESS_SPLIT = re.compile(r"[;\n]+")


def parse_access(text):
    """'CORP\\A=Owner; CORP\\B=View' (or ':' / '|' instead of '=') -> [Grant]."""
    grants = []
    for part in ACCESS_SPLIT.split(text or ""):
        part = part.strip()
        if not part:
            continue
        m = re.match(r"^(.*?)\s*[=|]\s*([^=|]+)$", part)
        if m:
            grants.append(Grant(m.group(1).strip(), m.group(2).strip()))
        else:
            grants.append(Grant(part, ""))
    return grants


def record_from_row(row, cfg, *, source, source_file, row_ref, row_number,
                    type_hint="", columns=None, folder_separator="\\",
                    group_column="", permission_column=""):
    aliases = {k: list(v) for k, v in cfg["field_aliases"].items()}
    columns = columns or {}
    # An explicit mapping wins over the aliases.
    for logical, col in columns.items():
        if col:
            aliases[logical] = [col]
    skip_cols = {c.lower() for c in (group_column, permission_column) if c}
    lookup = {k: v for k, v in column_lookup([c for c in row if not c.startswith("_")]).items()
              if k not in skip_cols}

    def get(logical):
        return first_value(row, lookup, aliases.get(logical, []))

    used = {}
    for logical in ("id", "name", "folder", "type", "address", "username", "password",
                    "private_key", "access", "safe", "platform"):
        used[logical] = get(logical)

    rec = SourceRecord(source=source, source_file=source_file,
                       source_id=used["id"][1].strip() or f"row{row_number}",
                       source_ref=row_ref)
    rec.name = used["name"][1].strip()
    rec.folder = split_folder(used["folder"][1], folder_separator)
    rec.type = (used["type"][1] or type_hint or "").strip()
    rec.address = used["address"][1].strip()
    rec.username = used["username"][1].strip()
    rec.target_safe = used["safe"][1].strip()
    rec.target_platform = used["platform"][1].strip()

    key = used["private_key"][1]
    pwd = used["password"][1]
    key_types = {t.lower() for t in cfg["key_types"]}
    if key.strip() or rec.type.lower() in key_types:
        rec.secret_type = "key"
        rec.secret = key
        for col in row:
            if "passphrase" in col.lower() and str(row[col]).strip():
                rec.notes.append(f"key has a passphrase in '{col}'; Privilege Cloud key "
                                 "accounts do not take it, confirm the platform handles it")
    else:
        rec.secret = pwd
    if not rec.secret.strip():
        rec.notes.append("secret is empty in the source")

    if used["access"][0]:
        rec.grants = parse_access(used["access"][1])
    if group_column and row.get(group_column, "").strip():
        rec.grants = (rec.grants or []) + [Grant(row[group_column].strip(),
                                                 row.get(permission_column, "").strip())]

    rec.extra = OrderedDict()
    for col, val in row.items():
        if col.startswith("_"):
            continue
        if matches_any(col, cfg["secret_column_patterns"]):
            continue
        if matches_any(col, cfg["exclude_field_patterns"]):
            if str(val).strip():
                rec.notes.append(f"attachment field '{col}' not migrated")
            continue
        rec.extra[col] = "" if val is None else str(val)
    return rec
