"""Keep spreadsheet programs from running cell values as formulas (CSV/formula injection).

Review files are meant to be opened in Excel. A source value that starts with = + - @ or a
tab / carriage return could be read as a formula (or DDE command), so such values are
written with a leading apostrophe, which Excel shows as plain text. When a review file
comes back (--overrides, --from-review) the apostrophe is taken off again.

Upload files (upload/*.csv) are API input and are NOT escaped: changing a value there
would change the account (a password may well start with '-').
"""

TRIGGERS = ("=", "+", "-", "@", "\t", "\r")


def escape(value):
    if not isinstance(value, str) or not value:
        return value
    if value.startswith(TRIGGERS) or (value.startswith("'") and value[1:].startswith(TRIGGERS + ("'",))):
        return "'" + value
    return value


def unescape(value):
    if isinstance(value, str) and value.startswith("'") and value[1:].startswith(TRIGGERS + ("'",)):
        return value[1:]
    return value


def row(values):
    return [escape(v) for v in values]


class SafeWriter:
    """csv.writer that escapes every value it writes."""

    def __init__(self, writer):
        self._w = writer

    def writerow(self, values):
        return self._w.writerow(row(values))

    def writerows(self, rows):
        for r in rows:
            self.writerow(r)
