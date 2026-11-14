"""Delinea (Thycotic) Secret Server exports: the multi-template CSV export, and the XML
export / import file (see delinea_xml.py), which also carries folders and permissions.

CSV:

The export repeats a header row for each Secret Template, each with its own
columns, often preceded by a one-cell row holding the template name. Quoted
multi-line values are handled by the csv module.
"""

import csv
import logging
from collections import OrderedDict, defaultdict

from ..csvsafe import reading
from .. import safexml
from . import delinea_xml
from .base import Adapter, file_stem, read_head
from .rows import record_from_row

log = logging.getLogger("imw.delinea")


def _is_blank(row):
    return not any(c.strip() for c in row)


def _dedupe(headers):
    seen = defaultdict(int)
    out = []
    for h in headers:
        h = h.strip() or "Unnamed"
        seen[h.lower()] += 1
        out.append(h if seen[h.lower()] == 1 else f"{h}_{seen[h.lower()]}")
    return out


def parse_sections(path, markers, encoding="utf-8-sig"):
    """Yield (template_name, line_no, OrderedDict row) for every data row."""
    markers = {m.lower() for m in markers}
    with open(path, newline="", encoding=encoding) as fh, reading(path):
        reader = csv.reader(fh)
        lines = [(reader.line_num, row) for row in reader]
    lines = [(n, r) for n, r in lines if not _is_blank(r)]

    def is_header(r):
        return bool(markers.intersection(c.strip().lower() for c in r))

    headers, template, pending = None, None, None
    for idx, (line_no, row) in enumerate(lines):
        if is_header(row):
            headers = _dedupe(row)
            template, pending = pending, None
            continue
        non_empty = [c for c in row if c.strip()]
        if len(non_empty) == 1 and row[0].strip() and idx + 1 < len(lines) \
                and is_header(lines[idx + 1][1]):
            pending = non_empty[0].strip()
            continue
        if headers is None:
            log.warning("line %d: data before any header row, skipped", line_no)
            continue
        cols = headers
        if len(row) > len(headers):
            extra = row[len(headers):]
            if any(c.strip() for c in extra):
                log.warning("line %d: %d more values than headers; values may have moved, record marked as an error", line_no, len(extra))
            cols = headers + [f"Extra_{i + 1}" for i in range(len(extra))]
        else:
            row = row + [""] * (len(headers) - len(row))
        yield template, line_no, OrderedDict(zip(cols, row))


class DelineaAdapter(Adapter):
    name = "delinea"
    description = "Delinea / Thycotic Secret Server export: multi-template CSV, or XML (with folders and permissions)"
    extensions = (".csv", ".xml")

    @classmethod
    def sniff(cls, path):
        if str(path).lower().endswith(".xml"):
            return delinea_xml.sniff(safexml.read_head_text(path))
        if not str(path).lower().endswith(".csv"):
            return 0
        head = read_head(path).lower()
        if "secret name" in head or "secretname" in head:
            return 80 if "folder path" in head or "secret id" in head else 60
        return 0

    def read(self, path, cfg, encoding="utf-8-sig"):
        if str(path).lower().endswith(".xml"):
            return delinea_xml.read(self.name, path, cfg)
        return self._read_csv(path, cfg, encoding)

    def _read_csv(self, path, cfg, encoding):
        scfg = cfg["sources"]["delinea"]
        stem = file_stem(path)
        n = 0
        for template, line_no, row in parse_sections(path, scfg["header_markers"], encoding):
            n += 1
            yield record_from_row(row, cfg, source=self.name, source_file=stem,
                                  row_ref=f"line {line_no}", row_number=n,
                                  type_hint=template or "", folder_separator="\\", from_csv=True)
