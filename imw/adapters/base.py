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


# Column names that hold secrets, always on (config secret_column_patterns adds to them).
# Their values are never kept as Source.* columns, so they never reach a review file.
BUILTIN_SECRET_COLUMNS = (
    r"pass ?word", r"passwd", r"\bpwd\b", r"^pass$", r"passphrase", r"pass ?code",
    r"private ?key", r"ssh ?key", r"\bsecret\b(?! ?(name|id|template|folder|policy|type)\b)",
    r"api ?key", r"\btoken\b", r"\bpin\b", r"\btotp\b", r"\botp\b", r"\bseed\b",
    r"recovery ?(code|key)", r"backup ?code", r"security ?(answer|code)", r"\bcvv\b", r"\bcvc\b",
    r"card ?number", r"connection ?string", r"combination", r"alarm ?code", r"(license|product) ?key",
)


def is_secret_column(name, cfg):
    """True when a column (or KeePass field) name says it holds a secret value."""
    return matches_any(name or "", BUILTIN_SECRET_COLUMNS) or \
        matches_any(name or "", (cfg or {}).get("secret_column_patterns") or [])


# Fields that hold (or set up) a one-time password: KeePass "otp" / "TimeOtp-*" / "HmacOtp-*",
# KeePassXC "TOTP Seed", Delinea or spreadsheet "OTP" / "TOTP" / "One-Time Password" columns.
# Any value that is an otpauth:// URI counts too, whatever the column is called.
OTP_FIELD_PATTERNS = (r"\b[th]?otp\b", r"timeotp", r"hmacotp", r"\btotp", r"one[ -]?time[ -]?pass")
OTP_NOTE = "one-time password (OTP) in the source"
_OFF = {"", "0", "false", "no", "n", "none", "off", "disabled", "null"}


def is_otp_value(value):
    return str(value or "").strip().lower().startswith("otpauth://")


def otp_fields(items):
    """Names of the fields in (name, value) pairs that show a one-time password is set up."""
    return [k for k, v in items
            if str(v or "").strip().lower() not in _OFF
            and (matches_any(k or "", OTP_FIELD_PATTERNS) or is_otp_value(v))]


def otp_note(fields):
    """The account note for a record with a one-time password. The seed is never kept."""
    names = ", ".join(f"'{f}'" for f in fields)
    return (f"{OTP_NOTE} ({names}): it is not migrated and is left out of the review files; "
            "set up MFA for this account again after migration")


def address_from_url(value):
    """Keep the host part of a URL as the address (https://h.example/x -> h.example)."""
    m = re.match(r"^[a-z][a-z0-9+.-]*://([^/?#]+)", value.strip(), re.IGNORECASE)
    if not m:
        return value.strip()
    host = m.group(1).rsplit("@", 1)[-1]
    if host.startswith("["):          # [IPv6]:port
        return host[1:].split("]", 1)[0]
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host
