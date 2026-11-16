"""Reference files: exports and reports that hold no accounts but help map them.

Real Delinea Secret Server migrations come with several report CSVs next to the secrets
export. Each one is recognised by its header row:

  templates      "allsecrets.csv": Name, Secret template (Folder, value). The secrets export
                 has no template column, so each secret's template (record type, which picks
                 its platform) comes from this file, matched on the secret's name; the folder
                 only breaks a tie between secrets with the same name.
  users          "lauserslist.csv": Username, Display name, Email address... Delinea's folder
                 reports name users by their full (display) name; this file turns that name
                 into the Username column, which holds the UPN that Privilege Cloud needs.
  permissions    folder-permission reports (see transform.Permissions).
  template_list  "secret-template-list.csv": Secret templates, Total Secrets, Enabled.
  groups         "lagroups.csv": Name, Description.
  roles          "whatroleassignmentsexist.csv" and "whatrolepermissionassignments...": Delinea's
                 own application roles (who may administer Secret Server), not access to secrets.

The last three are recognised so they are not read as accounts, and are not needed.
"""

import csv
from collections import OrderedDict
from pathlib import Path

from .csvsafe import reading
from .model import split_folder

TEMPLATE_NAME_COLUMNS = ("Name", "Secret Name", "SecretName")
TEMPLATE_COLUMNS = ("Secret template", "Secret Template Name", "Template", "Template Name")
TEMPLATE_FOLDER_COLUMNS = ("Folder", "Folder Path", "FolderPath")
USER_DISPLAY_COLUMNS = ("Display name", "DisplayName", "Full name", "Full Name")
USER_NAME_COLUMNS = ("Username", "User name", "UserName", "UPN", "User Principal Name")
USER_EMAIL_COLUMNS = ("Email address", "Email", "E-mail", "Mail")

KINDS = OrderedDict([
    ("templates", "Template for each secret"),
    ("users", "Users list (full name to UPN)"),
    ("template_list", "List of secret templates (not needed)"),
    ("groups", "List of groups (not needed)"),
    ("roles", "Secret Server role report (not needed)"),
])
# What each kind adds, in plain words for the Add files page.
KIND_HELP = {
    "templates": "Gives each secret its template, which picks its platform. Needed when the secrets "
                 "export has no template column.",
    "users": "Turns the full names in the folder reports into UPNs, so users are uploaded with "
             "the name Privilege Cloud needs.",
    "template_list": "Lists every template with its count. The Workbench takes templates from the "
                     "secrets themselves, so this file is not needed.",
    "groups": "Lists the groups. Groups come from the folder-permission report, so this file is "
              "not needed.",
    "roles": "Who may administer Secret Server itself (its own roles), not who may use secrets. "
             "Not used.",
}
USED_KINDS = ("templates", "users")


def read_header(path, encoding="utf-8-sig"):
    """The first non-empty row of a CSV, stripped; [] for anything else."""
    if Path(path).suffix.lower() != ".csv":
        return []
    try:
        with open(path, newline="", encoding=encoding, errors="replace") as fh:
            for row in csv.reader(fh):
                if any(c.strip() for c in row):
                    return [c.strip() for c in row]
    except (OSError, csv.Error):
        pass
    return []


def _has(header_l, names):
    return any(n.lower() in header_l for n in names)


def reference_kind(path, encoding="utf-8-sig"):
    """'templates', 'users', 'template_list', 'groups', 'roles' or '' (not a reference file)."""
    header = read_header(path, encoding)
    h = {c.lower() for c in header}
    if not h:
        return ""
    secrets = any("password" in c for c in h) or _has(h, ("Username", "User Name", "Secret Name"))
    if "permission from" in h:
        return "roles"
    if "secret templates" in h and ("total secrets" in h or "enabled" in h):
        return "template_list"
    if _has(h, USER_DISPLAY_COLUMNS) and _has(h, USER_NAME_COLUMNS) and not any("password" in c for c in h):
        return "users"
    if _has(h, TEMPLATE_COLUMNS) and _has(h, TEMPLATE_NAME_COLUMNS) and not secrets:
        return "templates"
    if h == {"name", "description"}:
        return "groups"
    return ""


def _rows(path, encoding):
    with open(path, newline="", encoding=encoding) as fh, reading(path):
        reader = csv.DictReader(fh)
        cols = {c.strip().lower(): c for c in reader.fieldnames or [] if c}
        rows = list(reader)
    return cols, rows


def _pick(cols, names):
    return next((cols[n.lower()] for n in names if n.lower() in cols), None)


def _val(row, col):
    return (row.get(col) or "").strip() if col else ""


def read_templates(path, encoding="utf-8-sig"):
    """[(name, folder, template)] from an "all secrets with their template" report."""
    cols, rows = _rows(path, encoding)
    name_c, tmpl_c = _pick(cols, TEMPLATE_NAME_COLUMNS), _pick(cols, TEMPLATE_COLUMNS)
    folder_c = _pick(cols, TEMPLATE_FOLDER_COLUMNS)
    if not name_c or not tmpl_c:
        raise ValueError(f"{path}: needs a Name and a Secret template column")
    out = []
    for r in rows:
        name, tmpl = _val(r, name_c), _val(r, tmpl_c)
        if name and tmpl:
            out.append((name, _val(r, folder_c), tmpl))
    return out


def read_users(path, encoding="utf-8-sig"):
    """[(display name, username, email)] from a users list."""
    cols, rows = _rows(path, encoding)
    disp_c, user_c = _pick(cols, USER_DISPLAY_COLUMNS), _pick(cols, USER_NAME_COLUMNS)
    mail_c = _pick(cols, USER_EMAIL_COLUMNS)
    if not disp_c or not user_c:
        raise ValueError(f"{path}: needs a Display name and a Username column")
    out = []
    for r in rows:
        disp, user = _val(r, disp_c), _val(r, user_c)
        if disp and user:
            out.append((disp, user, _val(r, mail_c)))
    return out


def folder_key(folder):
    if isinstance(folder, (tuple, list)):
        return "\\".join(f.lower() for f in folder)
    return "\\".join(split_folder(folder, "auto")).lower()


class References:
    """Templates, users and your decisions on users who may get their access through a group,
    applied when the rules run (so the order the files are loaded in doesn't matter)."""

    def __init__(self, templates=(), users=(), decisions=None):
        self.templates = OrderedDict()      # lower name -> [(folder key, template)]
        for name, folder, tmpl in templates:
            self.templates.setdefault(name.lower(), []).append((folder_key(folder), tmpl))
        self.users = OrderedDict()          # lower display name -> [usernames], first spelling kept
        self.usernames = set()
        for disp, user, _mail in users:
            lst = self.users.setdefault(disp.lower(), [])
            if user.lower() not in (u.lower() for u in lst):
                lst.append(user)
            self.usernames.add(user.lower())
        self.decisions = dict(decisions or {})   # (folder key, lower member) -> include | exclude

    @property
    def has_users(self):
        return bool(self.users)

    def template_for(self, name, folder):
        """(template, note). An empty template with a note when the name is missing or the
        same name has several templates that the folder doesn't settle."""
        hits = self.templates.get((name or "").lower())
        if not self.templates:
            return "", ""
        if not hits:
            return "", "not in the template list (allsecrets.csv): no template, so no platform"
        tmpls = list(OrderedDict.fromkeys(t for _, t in hits))
        if len(tmpls) == 1:
            return tmpls[0], ""
        key = folder_key(folder)
        in_folder = list(OrderedDict.fromkeys(t for f, t in hits if f == key))
        if len(in_folder) == 1:
            return in_folder[0], ""
        return "", ("CHECK: the template list has " + str(len(tmpls)) + " secrets with this name and "
                    "different templates (" + ", ".join(tmpls) + "), and the folder doesn't settle it")

    def upn_for(self, name):
        """(username, note) for a user's full name. (None, note) when it can't be found or is
        not unique; (None, "") when there is no users list or the name already is a username."""
        if not self.users or not name or name.lower() in self.usernames:
            return None, ""
        hits = self.users.get(name.lower())
        if not hits:
            return None, "CHECK: not in the users list, so the full name is uploaded; give it the UPN"
        if len(hits) > 1:
            return None, ("CHECK: " + str(len(hits)) + " users in the users list have this full name ("
                          + ", ".join(hits) + "); pick the right one")
        return hits[0], ""

    def decision(self, folder, member):
        return self.decisions.get((folder_key(folder), (member or "").lower()), "")
