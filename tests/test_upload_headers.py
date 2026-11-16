"""Upload CSVs use the Privilege Cloud (ISPSS) sample layouts: column names, order and value formats."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))

from test_imw import SAMPLES, Base, read_csv  # noqa: E402

PC_SAMPLES = SAMPLES / "privilege_cloud"


def first_line(path):
    with open(path, encoding="utf-8-sig", newline="") as fh:
        return fh.readline().rstrip("\r\n")


class UploadHeaders(Base):
    def test_headers_match_privilege_cloud_samples(self):
        out = self.convert(SAMPLES / "delinea_export.csv", extra=["-p", str(SAMPLES / "delinea_permissions.csv")])
        for ours, theirs in (("Safes.csv", "AddSafes.csv"), ("SafeMembers.csv", "AddSafeMembers.csv"),
                             ("Accounts.csv", "AddAccounts.csv")):
            self.assertEqual(first_line(out / "upload" / ours), first_line(PC_SAMPLES / theirs), ours)
        safes = read_csv(out / "upload" / "Safes.csv")
        self.assertTrue(safes)
        self.assertTrue(all(s["Location"] == "\\" for s in safes))
        members = read_csv(out / "upload" / "SafeMembers.csv")
        flags = {v for m in members for k, v in m.items() if k not in ("SafeName", "MemberName", "MemberType")}
        self.assertEqual(flags, {"True", "False"})
        self.assertTrue({m["MemberType"] for m in members} <= {"User", "Group", "Role"})
        accounts = read_csv(out / "upload" / "Accounts.csv")
        self.assertEqual({a["AutomaticManagement"] for a in accounts}, {"False"})
        with open(out / "upload" / "Accounts.csv", "rb") as fh:
            self.assertIn(b"\r\n", fh.read())

    def test_extra_columns_only_when_used(self):
        cfg = self.tmp / "cfg.json"
        cfg.write_text(json.dumps({
            "safe_defaults": {"olacEnabled": True, "location": "\\Migrated"},
            "account_defaults": {"automaticManagementEnabled": True, "manualManagementReason": "x"},
            "account_property_map": {"Notes": "Notes", "NoSuchColumn": "Unused"},
            "directory_map": {"*": "corp.example.com"}}))
        out = self.convert(SAMPLES / "delinea_export.csv", config=cfg,
                           extra=["-p", str(SAMPLES / "delinea_permissions.csv")])
        safes = read_csv(out / "upload" / "Safes.csv")
        self.assertEqual(list(safes[0])[-1], "OlacEnabled")
        self.assertNotIn("AutoPurgeEnabled", safes[0])
        self.assertEqual({s["OlacEnabled"] for s in safes}, {"True"})
        self.assertEqual({s["Location"] for s in safes}, {"\\Migrated"})
        members = read_csv(out / "upload" / "SafeMembers.csv")
        self.assertEqual(list(members[0])[-1], "SearchIn")
        accounts = read_csv(out / "upload" / "Accounts.csv")
        self.assertIn("platformAccountProperties.Notes", accounts[0])
        self.assertNotIn("platformAccountProperties.Unused", accounts[0])
        self.assertEqual({a["AutomaticManagement"] for a in accounts}, {"True"})
        self.assertEqual({a["ManualManagementReason"] for a in accounts}, {""})

    def test_semicolon_not_allowed_in_account_name(self):
        src = self.tmp / "a.csv"
        src.write_text("Active Directory Account\n"
                       "Secret ID,Secret Name,Folder Path,Domain,Username,Password\n"
                       "1,app;db,\\IT,host1.example.com,admin,pw\n", encoding="utf-8")
        out = self.convert(src)
        self.assertEqual(read_csv(out / "upload" / "Accounts.csv")[0]["Name"], "app_db")


if __name__ == "__main__":
    unittest.main()
