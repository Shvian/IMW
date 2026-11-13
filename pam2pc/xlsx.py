"""Minimal .xlsx reader (standard library only).

Reads cell values as text. Formulas give their cached value. Dates arrive as
Excel serial numbers, because the reader does not interpret number formats.
"""

import re
import zipfile
import xml.etree.ElementTree as ET

NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
      "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
      "pr": "http://schemas.openxmlformats.org/package/2006/relationships"}
CELL_REF = re.compile(r"^([A-Z]+)(\d+)$")


def _col_index(letters):
    n = 0
    for ch in letters:
        n = n * 26 + (ord(ch) - 64)
    return n - 1


def _text(node):
    return "".join(t.text or "" for t in node.iter(f"{{{NS['m']}}}t"))


def _number(v):
    try:
        f = float(v)
    except ValueError:
        return v
    if f.is_integer() and abs(f) < 1e15:
        return str(int(f))
    return v


def sheet_names(path):
    with zipfile.ZipFile(path) as z:
        wb = ET.fromstring(z.read("xl/workbook.xml"))
    return [s.get("name") for s in wb.iterfind("m:sheets/m:sheet", NS)]


def read_rows(path, sheet=""):
    """Return (sheet_name, list of rows); each row is a list of strings."""
    with zipfile.ZipFile(path) as z:
        wb = ET.fromstring(z.read("xl/workbook.xml"))
        rels = ET.fromstring(z.read("xl/_rels/workbook.xml.rels"))
        targets = {r.get("Id"): r.get("Target") for r in rels.iterfind("pr:Relationship", NS)}
        sheets = [(s.get("name"), s.get(f"{{{NS['r']}}}id")) for s in wb.iterfind("m:sheets/m:sheet", NS)]
        if not sheets:
            raise ValueError(f"{path}: workbook has no sheets")
        if sheet:
            match = [s for s in sheets if s[0].lower() == sheet.lower()]
            if not match:
                raise ValueError(f"{path}: no sheet named '{sheet}' (have: {', '.join(s[0] for s in sheets)})")
            name, rid = match[0]
        else:
            name, rid = sheets[0]
        target = targets[rid].lstrip("/")
        target = target if target.startswith("xl/") else "xl/" + target
        shared = []
        if "xl/sharedStrings.xml" in z.namelist():
            ss = ET.fromstring(z.read("xl/sharedStrings.xml"))
            shared = [_text(si) for si in ss.iterfind("m:si", NS)]
        data = ET.fromstring(z.read(target))

    rows = []
    for row in data.iterfind("m:sheetData/m:row", NS):
        rnum = int(row.get("r", len(rows) + 1))
        while len(rows) < rnum - 1:
            rows.append([])
        values = []
        for c in row.iterfind("m:c", NS):
            ref = CELL_REF.match(c.get("r", ""))
            idx = _col_index(ref.group(1)) if ref else len(values)
            t = c.get("t", "n")
            v = c.findtext("m:v", default="", namespaces=NS)
            if t == "s":
                val = shared[int(v)] if v else ""
            elif t == "inlineStr":
                is_ = c.find("m:is", NS)
                val = _text(is_) if is_ is not None else ""
            elif t == "b":
                val = "TRUE" if v == "1" else "FALSE"
            elif t in ("str", "e"):
                val = v
            else:
                val = _number(v) if v else ""
            while len(values) < idx:
                values.append("")
            values.append(val)
        rows.append(values)
    return name, rows
