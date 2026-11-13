"""Regression tests for the round 2 audit (2026-11-13)."""

import unittest
from pathlib import Path
import zipfile
from collections import OrderedDict
from unittest import mock

from test_imw import SAMPLES, Base, read_csv  # noqa: F401

from imw import config as config_mod, csvsafe, safexml, xlsx
from imw.adapters.rows import record_from_row
from imw.adapters.table import TableAdapter
from imw.config import config_diff, config_from_dict, upgrade_config
from imw.model import Grant, SourceRecord
from imw.transform import build_plan, load_overrides
from imw.writers import write_upload


def rec(sid, folder=("Apps",), grants=()):
    r = SourceRecord(source="t", source_file="f", source_id=sid, source_ref=sid, name=sid, folder=folder,
                     type="Windows", address="h1", username="u" + sid, secret="x")
    r.grants = [Grant(m, p) for m, p in grants]
    return r


CFG = {"default_platform": "WinServerLocal"}


def members(plan):
    return {(s, m["member_name"]): m for (s, _), m in plan.members.items()}


class MemberEditsAfterRename(unittest.TestCase):
    RENAME = {"corp\\unix-admins": {"member_name": "Cloud-Unix-Admins", "member_type": None, "search_in": None}}

    def plan(self, edits):
        recs = [rec("1", grants=[("CORP\\Unix-Admins", "View")])]
        return build_plan(recs, config_from_dict(CFG), member_overrides=self.RENAME, member_edits=edits)

    def test_remove_renamed_member(self):
        plan = self.plan([{"safe_name": "APPS", "member_name": "Cloud-Unix-Admins", "action": "remove"}])
        self.assertEqual(plan.members, {})

    def test_role_change_on_renamed_member_does_not_duplicate(self):
        plan = self.plan([{"safe_name": "APPS", "member_name": "Cloud-Unix-Admins", "action": "add",
                           "role": "Full", "member_type": "", "search_in": ""}])
        rows = list(plan.members.values())
        self.assertEqual([(m["member_name"], m["role"]) for m in rows], [("Cloud-Unix-Admins", "Full")])

    def test_edit_saved_with_old_name_still_matches(self):
        for name in ("Unix-Admins", "CORP\\Unix-Admins"):
            plan = self.plan([{"safe_name": "APPS", "member_name": name, "action": "remove"}])
            self.assertEqual(plan.members, {}, name)


class MergedMembers(Base):
    def test_two_domains_same_group_one_row(self):
        recs = [rec("1", grants=[("CORP\\SQL-Admins", "View")]),
                rec("2", grants=[("LEGACY\\SQL-Admins", "Owner"), ("CORP\\SQL-Admins", "View")])]
        cfg = config_from_dict(CFG)
        plan = build_plan(recs, cfg)
        ms = members(plan)
        self.assertEqual(list(ms), [("APPS", "SQL-Admins")])
        m = ms[("APPS", "SQL-Admins")]
        self.assertEqual(m["source_name"], "CORP\\SQL-Admins | LEGACY\\SQL-Admins")
        self.assertEqual(m["role"], "Full")                      # strongest wins
        self.assertEqual(m["accounts"], 2)                       # unique accounts, not grants
        self.assertTrue(any(n.startswith("merged source members") for n in m["notes"]))
        write_upload(plan, cfg, self.tmp, False)
        rows = read_csv(self.tmp / "upload" / "SafeMembers.csv")
        self.assertEqual([(r["safeName"], r["memberName"]) for r in rows], [("APPS", "SQL-Admins")])

    def test_rename_onto_existing_member_merges(self):
        recs = [rec("1", grants=[("CORP\\A", "View"), ("CORP\\B", "View")])]
        plan = build_plan(recs, config_from_dict(CFG),
                          member_overrides={"corp\\b": {"member_name": "A", "member_type": None, "search_in": None}})
        self.assertEqual(list(members(plan)), [("APPS", "A")])

    def test_different_directories_are_flagged(self):
        cfg = config_from_dict(dict(CFG, directory_map={"CORP": "corp.example.com", "LEGACY": "legacy.local"}))
        recs = [rec("1", grants=[("CORP\\SQL-Admins", "View"), ("LEGACY\\SQL-Admins", "View")])]
        m = next(iter(build_plan(recs, cfg).members.values()))
        self.assertTrue(any("different directories" in n for n in m["notes"]))


class ConfigUpgradeSteps(unittest.TestCase):
    def test_workbench_saved_v2_upgrades_to_future_version(self):
        saved = config_diff(config_from_dict({"default_platform": "X"}))
        self.assertNotIn("field_aliases", saved)
        with mock.patch.object(config_mod, "CONFIG_VERSION", 3):
            up = upgrade_config(saved)
        self.assertEqual(up["config_version"], 3)
        self.assertEqual(up["default_platform"], "X")

    def test_hand_written_v1_left_alone(self):
        self.assertEqual(upgrade_config({"default_platform": "X"}), {"default_platform": "X"})

    def test_v1_dump_upgraded(self):
        up = upgrade_config({"field_aliases": {}, "fallback_strategy": "folder_leaf"})
        self.assertEqual((up["fallback_strategy"], up["config_version"]), ("convention", config_mod.CONFIG_VERSION))


class StrayFarRightCell(Base):
    NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"

    def _xlsx(self, sheet, shared=None):
        path = self.tmp / "s.xlsx"
        parts = {
            "xl/workbook.xml": f'<workbook xmlns="{self.NS}" xmlns:r="http://schemas.openxmlformats.org/'
                               'officeDocument/2006/relationships"><sheets><sheet name="S" sheetId="1" '
                               'r:id="rId1"/></sheets></workbook>',
            "xl/_rels/workbook.xml.rels": '<Relationships xmlns="http://schemas.openxmlformats.org/package/'
                                          '2006/relationships"><Relationship Id="rId1" Target="worksheets/'
                                          'sheet1.xml" Type="worksheet"/></Relationships>',
            "xl/worksheets/sheet1.xml": sheet}
        if shared is not None:
            parts["xl/sharedStrings.xml"] = f'<sst xmlns="{self.NS}">{shared}</sst>'
        with zipfile.ZipFile(path, "w") as z:
            for n, data in parts.items():
                z.writestr(n, data)
        return path

    def test_space_in_xfd_adds_no_columns(self):
        path = self._xlsx(
            f'<worksheet xmlns="{self.NS}"><sheetData>'
            '<row r="1"><c r="A1" t="inlineStr"><is><t>Name</t></is></c>'
            '<c r="B1" t="inlineStr"><is><t>Username</t></is></c></row>'
            '<row r="2"><c r="A2" t="inlineStr"><is><t>web01</t></is></c>'
            '<c r="B2" t="inlineStr"><is><t>admin</t></is></c>'
            '<c r="XFD2" t="inlineStr"><is><t> </t></is></c></row>'
            '</sheetData></worksheet>')
        recs = list(TableAdapter().read(path, config_from_dict(CFG)))
        self.assertEqual(len(recs), 1)
        self.assertFalse([k for k in recs[0].extra if k.startswith("Extra_")])

    def test_blank_extra_columns_skipped_but_values_kept(self):
        row = OrderedDict([("Name", "a"), ("Username", "u"), ("Extra_1", ""), ("Extra_2", "note")])
        r = record_from_row(row, config_from_dict({}), source="table", source_file="f", row_ref="r2",
                            row_number=1)
        self.assertNotIn("Extra_1", r.extra)
        self.assertEqual(r.extra["Extra_2"], "note")

    def test_bad_shared_string_index_is_a_clean_error(self):
        path = self._xlsx(f'<worksheet xmlns="{self.NS}"><sheetData><row r="1">'
                          '<c r="A1" t="s"><v>7</v></c></row></sheetData></worksheet>', shared="<si><t>x</t></si>")
        with self.assertRaisesRegex(ValueError, "shared string"):
            xlsx.read_rows(path)


class ReimportTrimsAfterUnescape(Base):
    def test_leading_tab_is_trimmed(self):
        self.assertEqual(csvsafe.escape("\tadmin"), "'\tadmin")
        f = self.tmp / "o.csv"
        f.write_text("Record_ID,Account_Name\nt:f:1,'\tadmin\n")
        self.assertEqual(load_overrides(f)["t:f:1"]["Account_Name"], "admin")


class XmlReadOnce(Base):
    def test_parse_reads_file_once(self):
        f = self.tmp / "k.xml"
        f.write_bytes(b"<KeePassFile><Root/></KeePassFile>")
        real_open = open
        calls = []

        def spy(path, *a, **kw):
            calls.append(path)
            return real_open(path, *a, **kw)
        with mock.patch("builtins.open", spy):
            self.assertEqual(safexml.parse(f).getroot().tag, "KeePassFile")
        self.assertEqual(len(calls), 1)

    def test_size_cap(self):
        f = self.tmp / "k.xml"
        f.write_bytes(b"<KeePassFile>" + b" " * 100 + b"</KeePassFile>")
        with mock.patch.object(safexml, "MAX_FILE_BYTES", 50):
            with self.assertRaisesRegex(ValueError, "larger than"):
                safexml.parse(f)

    def test_broken_keepass_xml_is_an_adapter_error(self):
        from imw.adapters.base import AdapterError
        from imw.adapters.keepass import KeePassAdapter
        f = self.tmp / "k.xml"
        f.write_bytes(b"<KeePassFile><Root>")
        with self.assertRaises(AdapterError):
            KeePassAdapter()._read_xml(f, config_from_dict({}))


class FrontendCsp(unittest.TestCase):
    def test_no_inline_scripts_or_handlers(self):
        import re
        from imw.ui import server
        static = server.STATIC
        html = (static / "index.html").read_text()
        self.assertEqual(re.findall(r"<script(?![^>]*\bsrc=)", html), [])
        for name in ["index.html"] + list(server.STATIC_SCRIPTS.values()):
            text = (static / name).read_text()
            self.assertEqual(re.findall(r"\son[a-z]+\s*=\s*[\"']", text), [], name)
        src = (Path(server.__file__)).read_text()
        self.assertIn("script-src 'self';", src)
        self.assertNotIn("script-src 'self' 'unsafe-inline'", src)

    def test_security_notice_on_overview(self):
        from imw.ui import server
        js = (server.STATIC / "app.js").read_text()
        self.assertIn("const securityNotice", js)
        self.assertIn("${securityNotice(true)}", js)                 # welcome page: open
        self.assertIn("${securityNotice(false)}", js)                # overview: folded


if __name__ == "__main__":
    unittest.main()
