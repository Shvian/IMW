"""Delinea (Thycotic) Secret Server XML export / import file.

This is the format of Secret Server's Advanced Import and Export, and what Delinea's
migration tools (for example the KeePass converter) produce for importing:

  <ImportFile>
    <Folders>
      <Folder>
        <FolderName>Windows</FolderName>
        <FolderPath>\\Infrastructure\\Windows</FolderPath>
        <Permissions>
          <Permission>
            <GroupName>PAM-Windows-Admins</GroupName>     (or <UserName>)
            <DomainName>CORP</DomainName>                  (optional)
            <FolderAccessRoleName>Owner</FolderAccessRoleName>
            <SecretAccessRoleName>Owner</SecretAccessRoleName>
          </Permission>
        </Permissions>
      </Folder>
    </Folders>
    <SecretTemplates>
      <secrettype>
        <name>Windows Account</name>
        <fields><field><name>Password</name><ispassword>true</ispassword>...</field></fields>
      </secrettype>
    </SecretTemplates>
    <Secrets>
      <Secret>
        <SecretName>...</SecretName><SecretTemplateName>...</SecretTemplateName>
        <FolderPath>\\Infrastructure\\Windows</FolderPath>
        <SecretItems><SecretItem><FieldName>Password</FieldName><Value>...</Value></SecretItem></SecretItems>
        <SecretDependencies />
        <Permissions />
      </Secret>
    </Secrets>
    <Groups />
  </ImportFile>

Which fields are secrets comes from the template's field flags (ispassword), plus the
usual secret-name patterns as a safety net, so a secret never reaches a review file even
when its field has an unusual name. File fields (isfile) are attachments and are not
migrated.

Permissions follow Secret Server's inheritance: a secret with an empty <Permissions> takes
the permissions of its folder, and a folder with an empty <Permissions> takes those of its
parent folder. When neither the secret nor any folder above it lists permissions, the
record has no access data, so a permissions file can still supply it.

Element names are matched without regard to case or XML namespace, because the files are
written by several tools and Secret Server versions.
"""

import re
from collections import OrderedDict

from .. import safexml
from ..model import Grant, split_folder
from .base import AdapterError, file_stem, is_secret_column
from .rows import record_from_row

ROOT_TAG = "importfile"

# Where a permission's role is written, in order of preference. For a folder the secret role
# is what its secrets get; the folder role only says what members can do to the folder.
SECRET_ROLE_TAGS = ("secretaccessrolename", "accessrolename", "rolename", "role", "permission",
                    "permissionname", "folderaccessrolename")
# Older exports write one true/false element per right instead of a role name; strongest first.
FLAG_ROLES = (("owner", "Owner"), ("edit", "Edit"), ("view", "View"), ("list", "List"))
TRUE = ("true", "1", "yes")


def _tag(el):
    return el.tag.rsplit("}", 1)[-1].lower()


def _child(el, *names):
    if el is None:
        return None
    for c in el:
        if _tag(c) in names:
            return c
    return None


def _children(el, name):
    return [c for c in el if _tag(c) == name] if el is not None else []


def _text(el, *names):
    c = _child(el, *names)
    return (c.text or "").strip() if c is not None and c.text else ""


def _flag(el, name):
    return _text(el, name).lower() in TRUE


def _member(perm, known_groups):
    """(member, member_type) of one <Permission>; member is DOMAIN\\name when a domain is given."""
    domain = _text(perm, "domainname", "domain")
    for tag, mtype in (("groupname", "Group"), ("username", "User"), ("name", ""),
                       ("principalname", ""), ("usergroupname", "")):
        name = _text(perm, tag)
        if name:
            break
    else:
        return "", ""
    full = name if not domain or "\\" in name else f"{domain}\\{name}"
    if not mtype and (full.lower() in known_groups or name.lower() in known_groups):
        mtype = "Group"
    return full, mtype


def parse_permissions(block, known_groups):
    """[Grant] from a <Permissions> element (empty list when it lists none)."""
    grants = []
    for perm in _children(block, "permission"):
        member, mtype = _member(perm, known_groups)
        if not member:
            continue
        role = next((_text(perm, t) for t in SECRET_ROLE_TAGS if _text(perm, t)), "")
        if not role:
            role = next((label for tag, label in FLAG_ROLES if _flag(perm, tag)), "")
        key = (member.lower(), role.lower())
        if all((g.member.lower(), g.permission.lower()) != key for g in grants):
            grants.append(Grant(member, role, mtype))
    return grants


def _templates(root):
    """template name (lower) -> {field name (lower): flags dict}."""
    out = {}
    block = _child(root, "secrettemplates")
    for st in list(block) if block is not None else []:
        name = _text(st, "name", "secrettemplatename")
        fields = {}
        for f in _children(_child(st, "fields"), "field"):
            info = {k: _flag(f, k) for k in ("ispassword", "isnotes", "isurl", "isfile")}
            for key in (_text(f, "name"), _text(f, "displayname"), _text(f, "fieldslugname")):
                if key:
                    fields[key.lower()] = info
        if name:
            out[name.lower()] = fields
    return out


def _folders(root, known_groups):
    """folder path (lower, '\\'-joined levels) -> [Grant] for the folders that list permissions."""
    out = {}

    def walk(block, parent):
        for f in _children(block, "folder"):
            path = split_folder(_text(f, "folderpath"), "\\")
            name = _text(f, "foldername")
            if not path and name:
                path = parent + (name,)
            grants = parse_permissions(_child(f, "permissions"), known_groups)
            if path and grants:
                out["\\".join(path).lower()] = grants
            walk(_child(f, "folders"), path or parent)     # nested folders, if a tool writes them

    walk(_child(root, "folders"), ())
    return out


def _groups(root):
    names = set()
    for g in _children(_child(root, "groups"), "group"):
        name = _text(g, "name", "groupname")
        domain = _text(g, "domainname", "domain")
        if name:
            names.add(name.lower())
            if domain:
                names.add(f"{domain}\\{name}".lower())
    return names


def folder_grants(folder, folders):
    """Nearest folder (itself, then each parent) that lists permissions."""
    levels = [x.lower() for x in folder]
    for i in range(len(levels), 0, -1):
        hit = folders.get("\\".join(levels[:i]))
        if hit is not None:
            return list(hit)
    return None


def sniff(head):
    return 95 if "<importfile" in head.lower() else 0


def read(adapter_name, path, cfg):
    stem = file_stem(path)
    try:
        root = safexml.parse(path).getroot()
    except (safexml.UnsafeXmlError, safexml.ET.ParseError) as exc:
        raise AdapterError(f"{path}: {exc}") from None
    if _tag(root) != ROOT_TAG:
        raise AdapterError(f"{path} is not a Delinea Secret Server XML export (no <ImportFile>)")
    known_groups = _groups(root)
    templates = _templates(root)
    folders = _folders(root, known_groups)
    key_aliases = [a.lower() for a in cfg["field_aliases"].get("private_key", [])]
    out = []
    for n, sec in enumerate(_children(_child(root, "secrets"), "secret"), start=1):
        out.append(_record(adapter_name, sec, n, stem, cfg, templates, folders, known_groups, key_aliases))
    return out


def _record(adapter_name, sec, n, stem, cfg, templates, folders, known_groups, key_aliases):
    tname = _text(sec, "secrettemplatename", "templatename")
    tfields = templates.get(tname.lower(), {})
    folder_path = _text(sec, "folderpath")

    items = OrderedDict()
    for it in _children(_child(sec, "secretitems"), "secretitem"):
        fname = _text(it, "fieldname", "name", "slug")
        if not fname:
            continue
        v = _child(it, "value")
        val = v.text if v is not None and v.text else ""
        while fname in items:                 # same field twice: keep both
            fname += "_2"
        items[fname] = val

    def flags(fname):
        return tfields.get(fname.lower(), {})

    secret_fields = [f for f in items if flags(f).get("ispassword") or is_secret_column(f, cfg)]
    file_fields = [f for f in items if flags(f).get("isfile")]
    url_fields = [f for f in items if flags(f).get("isurl")]
    key_field = next((f for f in secret_fields if f.lower() in key_aliases and items[f].strip()), "")
    pw_field = next((f for f in secret_fields if f != key_field and "passphrase" not in f.lower()
                     and items[f].strip()), "") or \
        next((f for f in secret_fields if f != key_field and "passphrase" not in f.lower()), "")

    row = OrderedDict()
    row["Secret Name"] = _text(sec, "secretname", "name")
    row["Folder Path"] = folder_path
    row["Secret Template"] = tname
    sid = _text(sec, "secretid", "id")
    if sid:
        row["Secret ID"] = sid
    for f, v in items.items():
        if f.lower() in ("secret name", "folder path", "secret template", "secret id"):
            f = f"{f} (field)"
        row[f] = v
    columns = {"id": "Secret ID" if sid else "", "name": "Secret Name", "folder": "Folder Path",
               "type": "Secret Template", "password": pw_field, "private_key": key_field}
    # Template-flagged secrets are secrets whatever their name; the extra patterns make
    # record_from_row leave them out of the kept columns.
    exact = [f"^{re.escape(f)}$" for f in secret_fields]
    one = dict(cfg)
    one["secret_column_patterns"] = list(cfg.get("secret_column_patterns") or []) + exact
    rec = record_from_row(row, one, source=adapter_name, source_file=stem,
                          row_ref=f"secret {n} {row['Secret Name']!r}", row_number=n,
                          type_hint=tname, columns=columns, folder_separator="\\")
    if not sid:
        rec.source_id = f"secret{n}"
    rec.folder = split_folder(folder_path, "\\")

    for f in file_fields:
        if rec.extra.pop(f, None) is not None and items[f].strip():
            rec.notes.append(f"attachment field '{f}' not migrated")
    if not rec.address:
        for f in url_fields:
            if items[f].strip():
                rec.address = items[f].strip()
                break

    deps = _child(sec, "secretdependencies")
    if deps is not None and len(deps):
        rec.notes.append(f"{len(deps)} secret dependenc{'y' if len(deps) == 1 else 'ies'} not migrated")

    own = parse_permissions(_child(sec, "permissions"), known_groups)
    if own:
        rec.grants, rec.access_source = own, "record"
    else:
        inherited = folder_grants(rec.folder, folders)
        if inherited is not None:
            rec.grants, rec.access_source = inherited, "folder"
    return rec
