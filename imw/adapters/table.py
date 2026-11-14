"""Generic table: any CSV, TSV or Excel (.xlsx) sheet with one credential per row.

Columns are found through config field_aliases, or set explicitly in
sources.table.columns, e.g. {"address": "Hostname", "username": "Login"}.
"""

import csv
from collections import OrderedDict

from .. import xlsx
from ..csvsafe import reading
from .base import Adapter, file_stem, read_head
from .rows import record_from_row


class TableAdapter(Adapter):
    name = "table"
    description = "Generic CSV / TSV / Excel (.xlsx) sheet, one account per row"
    extensions = (".csv", ".tsv", ".txt", ".xlsx", ".xlsm")

    @classmethod
    def sniff(cls, path):
        p = str(path).lower()
        if p.endswith((".xlsx", ".xlsm")):
            return 50
        if p.endswith((".csv", ".tsv", ".txt")):
            return 20 if read_head(path, 1024).strip() else 0
        return 0

    def _rows(self, path, tcfg, encoding):
        p = str(path).lower()
        header_row = int(tcfg.get("header_row") or 1)
        if p.endswith((".xlsx", ".xlsm")):
            sheet, rows = xlsx.read_rows(path, tcfg.get("sheet", ""))
            label = f"{sheet}!row "
        else:
            with open(path, newline="", encoding=encoding) as fh, reading(path):
                sample = fh.read(8192)
                fh.seek(0)
                try:
                    dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
                except csv.Error:
                    dialect = csv.excel_tab if p.endswith(".tsv") else csv.excel
                rows = list(csv.reader(fh, dialect))
            label = "row "
        if len(rows) < header_row:
            return
        headers, seen = [], {}
        for i, h in enumerate(rows[header_row - 1]):
            h = (h or "").strip() or f"Column_{i + 1}"
            seen[h.lower()] = seen.get(h.lower(), 0) + 1
            headers.append(h if seen[h.lower()] == 1 else f"{h}_{seen[h.lower()]}")
        for n, values in enumerate(rows[header_row:], start=header_row + 1):
            if not any(str(v).strip() for v in values):
                continue
            values = list(values)
            while len(values) > len(headers) and not str(values[-1]).strip():
                values.pop()      # blank cells past the last header (e.g. a stray space in XFD)
            values += [""] * (len(headers) - len(values))
            cols = headers + [f"Extra_{i + 1}" for i in range(len(values) - len(headers))]
            yield f"{label}{n}", n, OrderedDict(zip(cols, values))

    def read(self, path, cfg, encoding="utf-8-sig"):
        tcfg = cfg["sources"]["table"]
        stem = file_stem(path)
        from_csv = not str(path).lower().endswith((".xlsx", ".xlsm"))
        records = (self._record(row, ref, n, cfg, tcfg, stem, from_csv)
                   for ref, n, row in self._rows(path, tcfg, encoding))
        if not tcfg.get("group_column"):
            yield from records
            return
        # One grant per row: rows for the same account are merged into one record.
        merged = OrderedDict()
        for rec in records:
            key = (rec.name.lower(), rec.address.lower(), rec.username.lower(), rec.folder_path.lower())
            if key in merged:
                first = merged[key]
                first.grants = (first.grants or []) + (rec.grants or [])
                if rec.secret != first.secret:
                    first.notes.append(f"{rec.source_ref} has a different secret for the same "
                                       "account; first one kept")
            else:
                merged[key] = rec
        yield from merged.values()

    def _record(self, row, ref, n, cfg, tcfg, stem, from_csv=False):
        return record_from_row(row, cfg, source=self.name, source_file=stem, row_ref=ref,
                                  row_number=n, columns=tcfg.get("columns") or {},
                                  folder_separator=tcfg.get("folder_separator") or "auto",
                                  group_column=tcfg.get("group_column", ""),
                                  permission_column=tcfg.get("permission_column", ""), from_csv=from_csv)
