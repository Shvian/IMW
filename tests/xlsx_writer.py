"""Tiny .xlsx writer for tests and samples (standard library only)."""

import zipfile
from xml.sax.saxutils import escape


def _col(i):
    s = ""
    i += 1
    while i:
        i, r = divmod(i - 1, 26)
        s = chr(65 + r) + s
    return s


def write_xlsx(path, sheets):
    """sheets: {name: [[cell, ...], ...]}. Strings go to sharedStrings, ints/floats stay numbers."""
    shared, index = [], {}

    def sid(text):
        if text not in index:
            index[text] = len(shared)
            shared.append(text)
        return index[text]

    sheet_xml = []
    for rows in sheets.values():
        out = []
        for r, row in enumerate(rows, start=1):
            cells = []
            for c, val in enumerate(row):
                ref = f"{_col(c)}{r}"
                if val is None or val == "":
                    continue
                if isinstance(val, (int, float)) and not isinstance(val, bool):
                    cells.append(f'<c r="{ref}"><v>{val}</v></c>')
                else:
                    cells.append(f'<c r="{ref}" t="s"><v>{sid(str(val))}</v></c>')
            out.append(f'<row r="{r}">{"".join(cells)}</row>')
        sheet_xml.append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                         '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                         f'<sheetData>{"".join(out)}</sheetData></worksheet>')

    names = list(sheets)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml",
                   '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                   '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                   '<Default Extension="xml" ContentType="application/xml"/>'
                   '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
                   '<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>'
                   + "".join(f'<Override PartName="/xl/worksheets/sheet{i + 1}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' for i in range(len(names)))
                   + '</Types>')
        z.writestr("_rels/.rels",
                   '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
        z.writestr("xl/workbook.xml",
                   '<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
                   'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'
                   + "".join(f'<sheet name="{escape(n)}" sheetId="{i + 1}" r:id="rId{i + 1}"/>' for i, n in enumerate(names))
                   + '</sheets></workbook>')
        z.writestr("xl/_rels/workbook.xml.rels",
                   '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   + "".join(f'<Relationship Id="rId{i + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{i + 1}.xml"/>' for i in range(len(names)))
                   + f'<Relationship Id="rId{len(names) + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/>'
                   '</Relationships>')
        z.writestr("xl/sharedStrings.xml",
                   '<?xml version="1.0" encoding="UTF-8"?><sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                   + "".join(f'<si><t xml:space="preserve">{escape(s)}</t></si>' for s in shared) + '</sst>')
        for i, xml in enumerate(sheet_xml):
            z.writestr(f"xl/worksheets/sheet{i + 1}.xml", xml)


SAMPLE = {
    "Instructions": [["This sheet is ignored; accounts are on the Accounts sheet."]],
    "Accounts": [
        ["Account Inventory - exported 2026-11"],
        ["Account Name", "Server", "User Name", "Password", "Platform ID", "Target Safe", "AD Group", "Access Level", "Port"],
        ["unix-batch01-root", "batch01.corp.example.com", "root", "Rt!batch01", "UnixSSH", "", "CORP\\PAM-Unix-Admins", "Owner", 22],
        ["unix-batch01-root", "batch01.corp.example.com", "root", "Rt!batch01", "UnixSSH", "", "CORP\\Helpdesk", "List", 22],
        ["payments-api", "pay01.corp.example.com", "svc_pay", "Pay!01", "WinServerLocal", "APP:Payments/Prod", "CORP\\APP-Payments-Owners", "Owner", ""],
        ["leading zero id", "0042.corp.example.com", "0042", "=1+1", "WinServerLocal", "APP-Payments", "", "", 3389],
    ],
}

if __name__ == "__main__":
    import sys
    write_xlsx(sys.argv[1], SAMPLE)
    print("wrote", sys.argv[1])
