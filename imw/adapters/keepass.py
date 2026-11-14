"""KeePass exports.

Supported:
  - KeePass 2.x XML export (File > Export > KeePass XML (2.x)). Best choice: it
    keeps the full group tree, custom fields and entry UUIDs.
  - KeePass / KeePassXC CSV export (Group, Title, Username, Password, URL, Notes...).

Encrypted .kdbx files are not read directly (that needs third-party crypto
libraries); export to XML from KeePass first.
"""

import csv
from collections import OrderedDict

from .. import safexml
from ..csvsafe import reading
from ..model import SourceRecord, split_folder
from .base import Adapter, AdapterError, file_stem, is_secret_column, read_head
from .rows import record_from_row

STANDARD = {"Title", "UserName", "Password", "URL", "Notes"}


class KeePassAdapter(Adapter):
    name = "keepass"
    description = "KeePass 2.x XML export, or KeePass/KeePassXC CSV export"
    extensions = (".xml", ".csv")

    @classmethod
    def sniff(cls, path):
        p = str(path).lower()
        if p.endswith(".kdbx"):
            return 90  # read() explains that an XML export is needed
        head = read_head(path, 4096)
        if p.endswith(".xml") and "<KeePassFile" in head:
            return 95
        if p.endswith(".csv"):
            first = head.splitlines()[0].lower() if head else ""
            if '"title"' in first and ('"group"' in first or '"url"' in first):
                return 70
            if '"account","login name","password","web site"' in first:
                return 70
        return 0

    def read(self, path, cfg, encoding="utf-8-sig"):
        p = str(path).lower()
        if p.endswith(".kdbx"):
            raise AdapterError(f"{path} is an encrypted KeePass database. In KeePass use "
                               "File > Export > KeePass XML (2.x) and convert that file instead.")
        if p.endswith(".xml"):
            return self._read_xml(path, cfg)
        return self._read_csv(path, cfg, encoding)

    # ------------------------------------------------------------------ XML
    def _read_xml(self, path, cfg):
        kcfg = cfg["sources"]["keepass"]
        skip = {g.lower() for g in kcfg["skip_groups"]}
        stem = file_stem(path)
        try:
            root = safexml.parse(path).getroot()
        except (safexml.UnsafeXmlError, safexml.ET.ParseError) as exc:
            raise AdapterError(f"{path}: {exc}") from None
        if root.tag != "KeePassFile":
            raise AdapterError(f"{path} is not a KeePass XML export")
        recycle = (root.findtext("Meta/RecycleBinUUID") or "").strip()
        top = root.find("Root/Group")
        if top is None:
            return []
        out = []

        def walk(group, trail):
            name = (group.findtext("Name") or "").strip()
            uuid = (group.findtext("UUID") or "").strip()
            if name.lower() in skip or (recycle and uuid == recycle):
                return
            here = trail + (name,) if name else trail
            for entry in group.findall("Entry"):
                out.append(self._entry(entry, here, stem, cfg, len(out) + 1))
            for sub in group.findall("Group"):
                walk(sub, here)

        walk(top, ())
        if kcfg["drop_root_group"]:
            for rec in out:
                rec.folder = rec.folder[1:]
        return out

    def _entry(self, entry, folder, stem, cfg, idx):
        kcfg = cfg["sources"]["keepass"]
        fields = OrderedDict()
        protected = set()
        for s in entry.findall("String"):
            key = (s.findtext("Key") or "").strip()
            fields[key] = s.findtext("Value") or ""
            v = s.find("Value")
            # Fields you marked as protected in KeePass are secrets, whatever their name.
            if v is not None and any(str(v.get(a, "")).lower() == "true" for a in ("ProtectInMemory", "Protected")):
                protected.add(key)
        uuid = (entry.findtext("UUID") or "").strip()
        rec = SourceRecord(source=self.name, source_file=stem, source_id=uuid or f"entry{idx}",
                           source_ref=f"entry {fields.get('Title', '')!r}")
        rec.name = fields.get("Title", "").strip()
        rec.folder = tuple(folder)
        rec.username = fields.get("UserName", "").strip()
        rec.address = fields.get("URL", "").strip()   # build_plan turns it into a host when url_address_to_host is on
        rec.secret = fields.get("Password", "")
        rec.type = "\\".join(folder) if kcfg["type_from"] == "group" else kcfg["fixed_type"]
        for k, v in fields.items():
            if k in STANDARD:
                if k in ("URL", "Notes"):
                    rec.extra[k] = v
                continue
            if k in protected or is_secret_column(k, cfg):
                if "private" in k.lower() and "key" in k.lower() and v.strip():
                    rec.secret, rec.secret_type = v, "key"
                elif v.strip():
                    rec.notes.append(f"secret field '{k}' is not migrated (an account takes one secret) "
                                     "and is left out of the review files")
                continue
            rec.extra[k] = v
        for b in entry.findall("Binary"):
            rec.notes.append(f"attachment '{b.findtext('Key') or ''}' not migrated")
        if not rec.secret.strip():
            rec.notes.append("secret is empty in the source")
        if not uuid:
            rec.notes.append("entry has no UUID")
        return rec

    # ------------------------------------------------------------------ CSV
    def _read_csv(self, path, cfg, encoding):
        kcfg = cfg["sources"]["keepass"]
        skip = {g.lower() for g in kcfg["skip_groups"]}
        stem = file_stem(path)
        out = []
        with open(path, newline="", encoding=encoding) as fh, reading(path):
            reader = csv.DictReader(fh, restkey="_extra")
            for n, row in enumerate(reader, start=1):
                extra = row.pop("_extra", None) or []
                row = OrderedDict((k or f"Unnamed_{i}", v or "") for i, (k, v) in enumerate(row.items()))
                for i, v in enumerate(extra, start=1):
                    row[f"Extra_{i}"] = v or ""
                # KeePass 1.x CSV names.
                cols = {"name": "Title" if "Title" in row else "Account",
                        "username": "Username" if "Username" in row else "Login Name",
                        "password": "Password",
                        "address": "URL" if "URL" in row else "Web Site",
                        "folder": "Group" if "Group" in row else ""}
                rec = record_from_row(row, cfg, source=self.name, source_file=stem,
                                      row_ref=f"row {n + 1}", row_number=n, columns=cols,
                                      folder_separator="/", from_csv=True)
                if any(g.lower() in skip for g in rec.folder):
                    continue
                if kcfg["drop_root_group"]:
                    rec.folder = rec.folder[1:]
                rec.type = "\\".join(rec.folder) if kcfg["type_from"] == "group" else kcfg["fixed_type"]
                out.append(rec)
        return out
