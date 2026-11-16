r"""Safe naming convention: build short, layered Safe names from abbreviations.

Follows the usual CyberArk convention layers, most important first:
  Environment (P/D/T/Q) - Location - Business unit/Application - Technology (SVR, DB,
  NET, DOM...) - Flavor (WIN, LNX, SQL, ORC, CSC...) - Account type (LA, DA, LS, DS,
  RT, EN, SA)

Existing structure comes first: when a record has folders, safe_convention.template
(default "{folder}") names the Safe after its folder levels, in order, each level
abbreviated (\Applications\Storefront\Prod -> APP-SF-P). Only records with no
folders use template_no_folders (default "{env}-{tech}-{flavor}-{acct}", the CyberArk
example layers). Folder names and words become 1-4 letter codes through the
abbreviation dictionary, whole folder names first (or an automatic abbreviation). Codes that repeat an earlier
code are dropped, and when the name is over the limit it is shortened step by step
(see fit()) instead of simply being cut off.
"""

import re

WORD_SPLIT = re.compile(r"[\s\-_/\\:;,.()\[\]{}\"'&+]+")
VOWELS = set("AEIOU")

DEFAULT_ABBREVIATIONS = {
    # Environment (category 1)
    "production": "P", "prod": "P", "prd": "P", "development": "D", "dev": "D",
    "test": "T", "testing": "T", "tst": "T", "qa": "Q", "uat": "Q", "quality assurance": "Q",
    "staging": "S", "stage": "S", "dr": "DR", "disaster recovery": "DR", "sandbox": "SBX", "lab": "LAB",
    # Location (category 2)
    "datacenter": "DC", "data center": "DC", "east": "E", "west": "W", "north": "N", "south": "S",
    "europe": "EU", "united states": "US", "boston": "BOS", "new york": "NYC", "california": "CA",
    # Business unit / application (category 3)
    "security": "SEC", "engineering": "ENG", "support": "SUP", "support desk": "SUP", "helpdesk": "SUP",
    "finance": "FIN", "human resources": "HR", "payments": "PAY", "payroll": "PAY", "storefront": "SF",
    "marketing": "MKT", "sales": "SLS", "operations": "OPS", "ops": "OPS", "self service": "SS",
    "vendor": "VND", "vendors": "VND", "portal": "PRT", "portals": "PRT", "reporting": "RPT",
    "replica": "RPL", "replicas": "RPL", "batch": "BAT", "jobs": "JOB", "nightly": "NGT", "weekly": "WKL",
    "deploy": "DPL", "deployment": "DPL", "keys": "KEY", "key": "KEY", "legacy": "LGC", "break glass": "BG",
    "subscriptions": "SUB", "accounts": "ACC", "tier": "TR", "edge": "EDG", "proxy": "PRX",
    # Technology (category 4)
    "server": "SVR", "servers": "SVR", "member servers": "SVR", "workstation": "WKS", "workstations": "WKS",
    "network": "NET", "network devices": "NET", "database": "DB", "databases": "DB", "mainframe": "MF",
    "domain": "DOM", "domain controllers": "DC", "infrastructure": "INF", "applications": "APP",
    "application": "APP", "web": "WEB", "cloud": "CLD", "firewall": "FW", "firewalls": "FW",
    "switch": "SW", "switches": "SW", "core switches": "CSW", "router": "RTR", "routers": "RTR",
    "wireless": "WLS", "storage": "STG", "backup": "BKP", "middleware": "MW",
    # Flavor (category 5)
    "windows": "WIN", "unix": "UNX", "linux": "LNX", "hp-ux": "HP", "hpux": "HP", "aix": "AIX",
    "solaris": "SOL", "cisco": "CSC", "juniper": "JNP", "palo alto": "PAN", "sql": "SQL",
    "sql server": "SQL", "mssql": "SQL", "oracle": "ORC", "mysql": "MYS", "postgres": "PG",
    "postgresql": "PG", "db2": "DB2", "azure": "AZ", "aws": "AWS", "gcp": "GCP", "vmware": "VMW",
    "esxi": "ESX", "active directory": "AD",
    # Account type (category 6)
    "local": "LA", "service": "SVC", "service accounts": "SVC", "admin": "ADM", "admins": "ADM",
    "administrators": "ADM", "root": "RT",
}
# Word parts recognised inside compound folder names (Storefront -> Store+front -> SF).
COMPOUND_PARTS = {
    "store", "front", "back", "end", "pay", "roll", "net", "work", "share", "point", "data", "base",
    "web", "mail", "time", "sheet", "book", "desk", "help", "cash", "gate", "way", "key", "vault",
    "fire", "wall", "out", "look", "box", "drop", "cloud", "hub", "line", "sales", "force", "power",
    "shell", "file", "ware", "soft", "user", "check", "card", "bank", "pass", "word", "site", "core",
    "edge", "home", "page", "app", "apps", "ops", "dev", "sec", "log", "logs", "stream", "flow",
    "market", "place", "self", "service", "client", "server", "admin", "main", "frame", "net",
}
STOPWORDS = {"and", "of", "the", "for", "a", "an", "to", "in", "on", "at", "with"}

# Platform ID -> technology / flavor / default account type (categories 4-6).
DEFAULT_PLATFORM_CODES = {
    "WinDomain": {"tech": "DOM", "flavor": "WIN", "acct": "DA"},
    "WinServerLocal": {"tech": "SVR", "flavor": "WIN", "acct": "LA"},
    "WinDesktopLocal": {"tech": "WKS", "flavor": "WIN", "acct": "LA"},
    "WinService": {"tech": "SVR", "flavor": "WIN", "acct": "LS"},
    "UnixSSH": {"tech": "SVR", "flavor": "UNX", "acct": "LA"},
    "UnixSSHKeys": {"tech": "SVR", "flavor": "UNX", "acct": "LA"},
    "MSSql": {"tech": "DB", "flavor": "SQL", "acct": "LA"},
    "Oracle": {"tech": "DB", "flavor": "ORC", "acct": "LA"},
    "MySQL": {"tech": "DB", "flavor": "MYS", "acct": "LA"},
    "PostgreSQL": {"tech": "DB", "flavor": "PGS", "acct": "LA"},
    "CiscoSSH": {"tech": "NET", "flavor": "CSC", "acct": "LA"},
    "CiscoEnable": {"tech": "NET", "flavor": "CSC", "acct": "EN"},
    "PaloAltoNetworks": {"tech": "NET", "flavor": "PAN", "acct": "LA"},
    "VMwareESX": {"tech": "VRT", "flavor": "ESX", "acct": "LA"},
    "GenericWebApp": {"tech": "WEB", "flavor": "", "acct": "LA"},
    "AzureWebAccount": {"tech": "CLD", "flavor": "AZ", "acct": "LA"},
    "AWSAccessKeys": {"tech": "CLD", "flavor": "AWS", "acct": "LA"},
}

# Placeholder layers. Each layer's value comes from its rules, checked in order; the first
# rule whose conditions all match gives the code, otherwise the layer's default.
# A condition looks at one field (see LAYER_FIELDS) and is a case-insensitive regex.
LAYER_FIELDS = {
    "folder_word": "a word or phrase in any folder level",
    "folder_level": "any whole folder level",
    "folder": "the whole folder path",
    "platform": "the platform ID",
    "username": "the username",
    "address": "the address",
    "address_domain": "the address's domain (srv01.boston.corp.example.com -> boston.corp.example.com)",
    "name": "the account name",
    "type": "the record type / template",
    "source": "the source (delinea, keepass, table)",
    "env": "the {env} code", "tech": "the {tech} code", "flavor": "the {flavor} code", "acct": "the {acct} code",
    # plus "column:<name>" for any source column
}
BUILTIN_LAYERS = ("env", "tech", "flavor", "acct")
ENV_WORDS = {"production", "prod", "prd", "development", "dev", "test", "testing", "tst", "qa", "uat",
             "quality assurance", "staging", "stage"}


def _rule(field, pattern, code, field2="", pattern2=""):
    r = {"field": field, "pattern": pattern, "code": code}
    if field2:
        r.update(field2=field2, pattern2=pattern2)
    return r


def _by_platform(key):
    groups = {}
    for platform, codes in DEFAULT_PLATFORM_CODES.items():
        groups.setdefault(codes.get(key, ""), []).append(platform)
    return [_rule("platform", "^(%s)$" % "|".join(p), code) for code, p in groups.items() if code]


def default_layers():
    """The built-in placeholder layers (editable copies go into safe_convention.layers)."""
    unix = "^(UNX|LNX|HP|AIX|SOL)$"
    svc = "^(svc|srv|service)[_.-]"
    return {
        "env": {"label": "Environment", "default": "", "rules": [
            _rule("folder_word", "^(production|prod|prd)$", "P"),
            _rule("folder_word", "^(development|dev)$", "D"),
            _rule("folder_word", "^(test|testing|tst)$", "T"),
            _rule("folder_word", "^(qa|uat|quality assurance)$", "Q"),
            _rule("folder_word", "^(staging|stage)$", "S"),
        ]},
        "tech": {"label": "Technology", "default": "", "rules": _by_platform("tech")},
        "flavor": {"label": "Flavor", "default": "", "rules": _by_platform("flavor")},
        "acct": {"label": "Account type", "default": "", "rules": [
            _rule("username", "^root$", "RT", "flavor", unix),
            _rule("username", "^sa$", "SA", "tech", "^DB$"),
            _rule("username", "^enable$", "EN", "tech", "^NET$"),
            _rule("username", svc, "DS", "tech", "^DOM$"),
            _rule("username", svc, "LS"),
        ] + _by_platform("acct")},
    }


IP_ADDRESS = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$|:")


def address_domain(address):
    """'srv01.boston.corp.example.com' -> 'boston.corp.example.com'; '' for a short name or an IP."""
    host = str(address or "").strip().lower().rstrip(".")
    if not host or IP_ADDRESS.search(host) or "." not in host:
        return ""
    return host.split(".", 1)[1]


def norm(text):
    """Folder name or phrase -> lookup key ("Batch: Nightly/Weekly" -> "batch nightly weekly")."""
    return " ".join(w for w in WORD_SPLIT.split(str(text).lower()) if w)


class Namer:
    def __init__(self, cfg):
        conv = cfg.get("safe_convention", {})
        self.cfg = conv
        self.template = conv.get("template") or "{folder}"
        self.template_flat = conv.get("template_no_folders") or "{env}-{tech}-{flavor}-{acct}"
        self.sep = conv.get("separator", "-")
        self.max_len = cfg["safe_name"]["max_length"]
        self.abbr = {norm(k): v for k, v in DEFAULT_ABBREVIATIONS.items()}
        self.user_abbr = {norm(k): str(v).strip() for k, v in (conv.get("abbreviations") or {}).items()}
        self.abbr.update(self.user_abbr)
        self.skip_levels = {norm(s) for s in conv.get("skip_folder_levels") or []}
        self.default_env = conv.get("default_environment", "")
        self.max_phrase = max(len(k.split()) for k in self.abbr)
        self.layer_defs = self._layer_defs(conv)
        self.unknown = {}

    def _layer_defs(self, conv):
        layers = {k: dict(v) for k, v in (conv.get("layers") or default_layers()).items()}
        for name, base in default_layers().items():
            layers.setdefault(name, base)
        # Older settings: extra platform codes and environment words still count.
        for platform, codes in (conv.get("platform_codes") or {}).items():
            for key in ("tech", "flavor", "acct"):
                if codes.get(key) is not None:
                    rule = _rule("platform", "^%s$" % re.escape(platform), codes[key])
                    rules = list(layers[key]["rules"])
                    at = next((i for i, r in enumerate(rules) if r.get("field") == "platform"), len(rules)) \
                        if key == "acct" else 0
                    rules.insert(at, rule)
                    layers[key]["rules"] = rules
        words = [w for w in conv.get("environment_words") or [] if w]
        if words:
            layers["env"]["rules"] = list(layers["env"]["rules"]) + [
                _rule("folder_word", "^%s$" % re.escape(w.lower()), self.abbr.get(norm(w)) or self.auto(w)[:1])
                for w in words]
        compiled = {}
        for name, layer in layers.items():
            rules = []
            for r in layer.get("rules") or []:
                conds = [(r.get("field"), r.get("pattern")), (r.get("field2"), r.get("pattern2"))]
                conds = [(f, re.compile(p or "", re.IGNORECASE)) for f, p in conds if f]
                if conds:
                    rules.append((conds, str(r.get("code") or "").strip()))
            default = str(layer.get("default") or "").strip()
            if name == "env" and not default:
                default = self.default_env
            compiled[name] = (rules, default)
        return compiled

    def _field(self, field, rec, platform, units, codes):
        if field == "folder_word":
            return [u for u, _ in units]
        if field == "folder_level":
            return list(self.levels(rec))
        if field == "folder":
            return ["\\" + "\\".join(rec.folder) if rec.folder else ""]
        if field == "platform":
            return [platform or ""]
        if field == "address_domain":
            return [address_domain(rec.address)]
        if field in codes:
            return [codes[field]]
        if field.startswith("column:"):
            want = field[7:].strip().lower()
            return [str(v) for k, v in (rec.extra or {}).items() if k.lower() == want] or [""]
        return [str(getattr(rec, field, "") or "")]

    def layer_value(self, name, rec, platform, units, codes):
        """(code, matched folder units) for one layer."""
        rules, default = self.layer_defs.get(name, ([], ""))
        for conds, code in rules:
            hits = []
            for field, rx in conds:
                vals = [v for v in self._field(field, rec, platform, units, codes) if rx.search(v)]
                if not vals:
                    break
                if field == "folder_word":
                    hits.extend(vals)
            else:
                return code, hits
        return default, []

    # -- words ----------------------------------------------------------------
    def auto(self, word):
        """Automatic code for a word missing from the dictionary."""
        w = word.upper()
        if len(w) <= 4 or w.isdigit() or (w.isalnum() and word.isupper()):
            return w[:4]
        # CamelCase (SharePoint -> SP, HRApp -> HRA) or a known compound (Storefront -> SF).
        parts = re.findall(r"[A-Z]+(?![a-z])|[A-Z][a-z]+|[a-z]+|\d+", word)
        if len(parts) == 1:
            low = word.lower()
            known = COMPOUND_PARTS | {k for k in self.abbr if " " not in k and len(k) >= 3}
            for i in range(3, len(low) - 2):
                if low[:i] in known and low[i:] in known:
                    parts = [low[:i], low[i:]]
                    break
        if 1 < len(parts) <= 4:
            return "".join(p if (p.isupper() or p.isdigit()) else p[0].upper() for p in parts)[:4]
        out = w[0]
        for ch in w[1:]:
            if ch not in VOWELS and ch.isalnum() and ch != out[-1]:
                out += ch
            if len(out) == 3:
                break
        return out

    def level_codes(self, text):
        """['SQL Production Reporting'] -> [('SQL', 'SQL'), ('Production', 'P'), ...] (source, code)."""
        whole = norm(text)
        if whole in self.abbr and " " in whole:      # a whole multi-word folder name
            return [(text, self.abbr[whole])] if self.abbr[whole] else []
        words = [w for w in WORD_SPLIT.split(text) if w]
        out, i = [], 0
        while i < len(words):
            for n in range(min(self.max_phrase, len(words) - i), 0, -1):
                phrase = " ".join(words[i:i + n]).lower()
                if phrase in self.abbr:
                    if self.abbr[phrase]:
                        out.append((" ".join(words[i:i + n]), self.abbr[phrase]))
                    i += n
                    break
            else:
                w = words[i]
                if w.lower() not in STOPWORDS:
                    code = self.auto(w)
                    self.unknown[w] = code
                    out.append((w, code))
                i += 1
        return out

    # -- layers ---------------------------------------------------------------
    def levels(self, rec):
        return [lvl for lvl in rec.folder if norm(lvl) not in self.skip_levels]

    def layers(self, rec, platform, with_type=False, env_in_place=False):
        levels = [self.level_codes(level) for level in self.levels(rec)]
        units = [pair for lvl in levels for pair in lvl]
        codes = {}
        env_units = set()
        for name in list(BUILTIN_LAYERS) + [n for n in self.layer_defs if n not in BUILTIN_LAYERS]:
            code, hits = self.layer_value(name, rec, platform, units, codes)
            codes[name] = code
            if name == "env":
                env_units = {norm(h) for h in hits}
        folder = []          # list of levels, each a list of codes
        for lvl in levels:
            out = []
            for src, code in lvl:
                if norm(src) in env_units:
                    if not env_in_place:
                        continue
                    code = codes["env"] or code
                out.append(code)
            if out:
                folder.append(out)
        if env_units and not codes["env"]:
            codes["env"] = self.default_env
        codes["folder"] = folder
        codes["type"] = [c for _, c in self.level_codes(rec.type)] if (with_type and rec.type) else []
        return codes

    def folder_code(self, level):
        """(code, automatic) for one whole folder name as it would appear in a Safe name."""
        pairs = self.level_codes(level)
        auto = any(norm(src) not in self.abbr for src, _ in pairs)
        return self.sep.join(c for _, c in pairs), auto

    def suggest(self, folder_counts):
        """Distinct folder names -> suggested codes, so a table can be filled from the data.
        folder_counts: {folder name: accounts}. Codes another name already uses are flagged."""
        rows, by_code = [], {}
        for name, count in sorted(folder_counts.items(), key=lambda kv: (-kv[1], kv[0].lower())):
            if norm(name) in self.skip_levels:
                continue
            code, auto = self.folder_code(name)
            row = {"folder": name, "code": code, "accounts": count, "automatic": auto,
                   "yours": norm(name) in self.user_abbr, "clash": ""}
            other = by_code.get(code.upper())
            if other and auto and norm(other) != norm(name):
                row["clash"] = other
            by_code.setdefault(code.upper(), name)
            rows.append(row)
        return rows

    # -- assemble -------------------------------------------------------------
    def build(self, rec, platform, template=None):
        """Return (name, notes). The name already fits max_length when possible."""
        if not template:
            template = self.template if self.levels(rec) else self.template_flat
        lay = self.layers(rec, platform, with_type="{type}" in template, env_in_place="{env}" not in template)
        tokens = re.findall(r"\{(\w+)\}|([^{}]+)", template)
        # Each part: (kind, levels) where levels is a list of lists of codes.
        parts = []
        for key, literal in tokens:
            if literal:
                lit = literal.strip(self.sep)
                if lit:
                    parts.append(("literal", [[lit]]))
            elif key == "folder":
                parts.append(("folder", [list(lvl) for lvl in lay["folder"]]))
            elif key == "folder_leaf":
                parts.append(("folder", [list(lay["folder"][-1])] if lay["folder"] else []))
            elif key == "type":
                parts.append(("type", [list(lay["type"])] if lay["type"] else []))
            elif key in lay:
                parts.append((key, [[lay[key]]] if lay[key] else []))
        # Drop codes already used earlier in the name (e.g. SQL from the folder and the flavor).
        seen = set()
        for kind, levels in parts:
            for lvl in levels:
                keep = [c for c in lvl if kind == "literal" or c.upper() not in seen]
                seen.update(c.upper() for c in lvl)
                lvl[:] = keep
        return self.fit(parts)

    def fit(self, parts):
        """Shorten in steps until the name fits, keeping the most specific folders:
        1. a multi-word folder level above the last one becomes its initials (Customer Facing -> CF)
        2. the last folder level becomes its initials
        3. folder levels are dropped from the top (most generic) down, never the last one
        4. the end is cut off (reported as an issue)."""
        def render():
            return self.sep.join(c for _, levels in parts for lvl in levels for c in lvl if c)

        if len(render()) <= self.max_len:
            return render(), []
        folders = [levels for kind, levels in parts if kind in ("folder", "type") and levels]

        def initials(lvl):
            if len(lvl) > 1:
                lvl[:] = ["".join(c[0] for c in lvl)]

        for levels in folders:
            for lvl in levels[:-1]:
                initials(lvl)
                if len(render()) <= self.max_len:
                    return render(), ["long folder names turned into initials to fit"]
        for levels in folders:
            if levels:
                initials(levels[-1])
                if len(render()) <= self.max_len:
                    return render(), ["long folder names turned into initials to fit"]
        for levels in folders:
            while len(levels) > 1 and len(render()) > self.max_len:
                levels.pop(0)
            if len(render()) <= self.max_len:
                return render(), ["top folder levels left out to fit"]
        return render()[: self.max_len].rstrip(self.sep), ["convention name still too long; cut to fit"]
