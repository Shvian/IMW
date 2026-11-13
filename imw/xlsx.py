"""Minimal .xlsx reader (standard library only).

Reads cell values as text. Formulas give their cached value. Dates arrive as
Excel serial numbers, because the reader does not interpret number formats.
"""

import re
import zipfile

from . import safexml

NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
      "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
      "pr": "http://schemas.openxmlformats.org/package/2006/relationships"}
CELL_REF = re.compile(r"^([A-Z]+)(\d+)$")
MAX_ROW, MAX_COL = 1_048_576, 16_384        # Excel's own sheet limits
MAX_PART_BYTES = 512 * 1024 * 1024          # one uncompressed part of the workbook (sheet XML)


def _read_xml(z, name, path):
    """One XML part of the workbook: size-checked before it is unpacked, DTDs refused."""
    try:
        info = z.getinfo(name)
    except KeyError:
        raise ValueError(f"{path}: the workbook is missing {name}") from None
    if info.file_size > MAX_PART_BYTES:
        raise ValueError(f"{path}: {name} unpacks to {info.file_size // (1024 * 1024)} MB, more than "
                         f"the {MAX_PART_BYTES // (1024 * 1024)} MB this reader accepts. Save the sheet "
                         "as CSV and load that instead.")
    try:
        return safexml.fromstring(z.read(name))
    except (safexml.UnsafeXmlError, safexml.ET.ParseError) as exc:
        raise ValueError(f"{path}: {name}: {exc}") from None


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
        wb = _read_xml(z, "xl/workbook.xml", path)
    return [s.get("name") for s in wb.iterfind("m:sheets/m:sheet", NS)]


def read_rows(path, sheet=""):
    """Return (sheet_name, list of rows); each row is a list of strings."""
    with zipfile.ZipFile(path) as z:
        wb = _read_xml(z, "xl/workbook.xml", path)
        rels = _read_xml(z, "xl/_rels/workbook.xml.rels", path)
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
            ss = _read_xml(z, "xl/sharedStrings.xml", path)
            shared = [_text(si) for si in ss.iterfind("m:si", NS)]
        data = _read_xml(z, target, path)

    # Only cells with a value are kept. A formatted but empty cell far down or far right
    # (row 1048576, column XFD) adds nothing, so it cannot blow up the row lists.
    rows = []
    empty = ()                                  # shared filler for blank rows between data rows
    last_rnum = 0
    for row in data.iterfind("m:sheetData/m:row", NS):
        try:
            rnum = int(row.get("r") or last_rnum + 1)
        except ValueError:
            raise ValueError(f"{path}: bad row number {row.get('r')!r}") from None
        if not 1 <= rnum <= MAX_ROW:
            raise ValueError(f"{path}: row number {rnum} is outside an Excel sheet")
        last_rnum = rnum
        cells = {}
        next_idx = 0
        for c in row.iterfind("m:c", NS):
            ref = CELL_REF.match(c.get("r", ""))
            idx = _col_index(ref.group(1)) if ref else next_idx
            if not 0 <= idx < MAX_COL:
                raise ValueError(f"{path}: cell {c.get('r')} is outside an Excel sheet")
            next_idx = idx + 1
            t = c.get("t", "n")
            v = c.findtext("m:v", default="", namespaces=NS)
            if t == "s":
                try:
                    val = shared[int(v)] if v else ""
                except (ValueError, IndexError):
                    raise ValueError(f"{path}: cell {c.get('r')} points at a shared string that "
                                     "does not exist; the file is damaged") from None
            elif t == "inlineStr":
                is_ = c.find("m:is", NS)
                val = _text(is_) if is_ is not None else ""
            elif t == "b":
                val = "TRUE" if v == "1" else "FALSE"
            elif t in ("str", "e"):
                val = v
            else:
                val = _number(v) if v else ""
            if val != "":
                cells[idx] = val
        if not cells:
            continue
        values = [""] * (max(cells) + 1)
        for idx, val in cells.items():
            values[idx] = val
        while len(rows) < rnum - 1:
            rows.append(empty)
        if len(rows) >= rnum:                    # rows out of order or repeated: keep the first
            continue
        rows.append(values)
    return name, rows
