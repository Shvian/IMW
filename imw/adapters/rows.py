"""Turn one tabular row (dict of column -> value) into a SourceRecord.

Shared by the Delinea adapter and the generic CSV/Excel adapter.
"""

import re
from collections import OrderedDict

from ..model import ERROR_NOTE, Grant, SourceRecord, split_folder
from .base import column_lookup, first_value, is_otp_value, is_secret_column, matches_any, otp_fields, otp_note

ACCESS_SPLIT = re.compile(r"[;\n]+")


EXTRA_COL = re.compile(r"^Extra_\d+$")


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


SHIFTED = (ERROR_NOTE + "this row has more values than the header has columns, so its values have "
           "probably moved (for example an unquoted comma in a password). Values from the secret column "
           "on are not kept. Fix the export and load it again.")


def _guard_shifted(row, aliases, cfg):
    """A CSV row with values past the last header: everything from the first secret column on may
    hold a piece of the secret, so it is blanked (the record becomes an error)."""
    if not any(EXTRA_COL.match(c) and str(v or "").strip() for c, v in row.items()):
        return row, False
    secret_cols = {a.strip().lower() for k in ("password", "private_key") for a in aliases.get(k, [])}
    cols = list(row)
    first = next((i for i, c in enumerate(cols) if c.strip().lower() in secret_cols or is_secret_column(c, cfg)),
                 None)
    start = first if first is not None else next(i for i, c in enumerate(cols) if EXTRA_COL.match(c))
    return OrderedDict((c, v if i < start else "") for i, (c, v) in enumerate(row.items())), True


def record_from_row(row, cfg, *, source, source_file, row_ref, row_number,
                    type_hint="", columns=None, folder_separator="\\",
                    group_column="", permission_column="", from_csv=False):
    """from_csv: values past the header can only mean a shifted row (see SHIFTED)."""
    aliases = {k: list(v) for k, v in cfg["field_aliases"].items()}
    columns = columns or {}
    # An explicit mapping wins over the aliases.
    for logical, col in columns.items():
        if col:
            aliases[logical] = [col]
    shifted = False
    if from_csv:
        row, shifted = _guard_shifted(row, aliases, cfg)
    skip_cols = {c.strip().lower() for c in (group_column, permission_column) if c}
    full_lookup = column_lookup([c for c in row if not c.startswith("_")])
    lookup = {k: v for k, v in full_lookup.items() if k not in skip_cols}
    # The configured group/permission columns match the header whatever its case.
    group_col = full_lookup.get(group_column.strip().lower()) if group_column else None
    perm_col = full_lookup.get(permission_column.strip().lower()) if permission_column else None

    def get(logical):
        return first_value(row, lookup, aliases.get(logical, []))

    used = {}
    for logical in ("id", "name", "folder", "type", "address", "username", "password",
                    "private_key", "access", "safe", "platform"):
        used[logical] = get(logical)

    rec = SourceRecord(source=source, source_file=source_file,
                       source_id=used["id"][1].strip() or f"row{row_number}",
                       source_ref=row_ref)
    if shifted:
        rec.notes.append(SHIFTED)
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
    if not rec.secret.strip() and not shifted:
        rec.notes.append("secret is empty in the source")

    if used["access"][0]:
        rec.grants = parse_access(used["access"][1])
    group_val = str(row.get(group_col) or "").strip() if group_col else ""
    if group_val:
        perm_val = str(row.get(perm_col) or "").strip() if perm_col else ""
        rec.grants = (rec.grants or []) + [Grant(group_val, perm_val)]

    rec.extra = OrderedDict()
    otp = otp_fields((c, v) for c, v in row.items() if not c.startswith("_"))
    if otp:
        rec.notes.append(otp_note(otp))
    for col, val in row.items():
        if col.startswith("_"):
            continue
        if col in otp and (is_secret_column(col, cfg) or is_otp_value(val)):
            continue                     # the seed: noted once above, never kept
        if is_secret_column(col, cfg):
            if str(val or "").strip() and col not in (used["password"][0], used["private_key"][0]) \
                    and "passphrase" not in col.lower():
                rec.notes.append(f"secret field '{col}' is not migrated (an account takes one secret) "
                                 "and is left out of the review files")
            continue
        if matches_any(col, cfg["exclude_field_patterns"]):
            if str(val).strip():
                rec.notes.append(f"attachment field '{col}' not migrated")
            continue
        val = "" if val is None else str(val)
        if not val.strip() and EXTRA_COL.match(col):
            # Values past the header row get synthetic Extra_N names; a stray blank cell far to
            # the right of a sheet would otherwise add thousands of empty columns.
            continue
        rec.extra[col] = val
    return rec
