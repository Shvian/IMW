"""Safe naming convention: build short, layered Safe names from abbreviations.

Follows the usual CyberArk convention layers, most important first:
  Environment (P/D/T/Q) - Location - Business unit/Application - Technology (SVR, DB,
  NET, DOM...) - Flavor (WIN, LNX, SQL, ORC, CSC...) - Account type (LA, DA, LS, DS,
  RT, EN, SA)

The template in config safe_convention.template decides which layers are used and
in what order, e.g. "{env}-{folder}-{tech}-{flavor}-{acct}". {folder} is every
folder level, each word turned into a 1-4 letter code through the abbreviation
dictionary (or an automatic consonant abbreviation). Codes that repeat an earlier
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
    "finance": "FIN", "human resources": "HR", "payments": "PAY", "payroll": "PAY", "storefront": "SHOP",
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
    "CiscoSSH": {"tech": "NET", "flavor": "CSC", "acct": "LA"},
    "CiscoEnable": {"tech": "NET", "flavor": "CSC", "acct": "EN"},
    "GenericWebApp": {"tech": "WEB", "flavor": "", "acct": "LA"},
    "AzureWebAccount": {"tech": "CLD", "flavor": "AZ", "acct": "LA"},
    "AWSAccessKeys": {"tech": "CLD", "flavor": "AWS", "acct": "LA"},
}

# Username patterns that refine the account type, checked in order.
# "tech" / "flavor" (optional, regex for flavor) limit a rule to matching platforms.
DEFAULT_ACCOUNT_TYPE_RULES = [
    {"username": "^root$", "acct": "RT", "flavor": "^(UNX|LNX|HP|AIX|SOL)$"},
    {"username": "(?i)^sa$", "acct": "SA", "tech": "DB"},
    {"username": "(?i)^enable$", "acct": "EN", "tech": "NET"},
    {"username": "(?i)^(svc|srv|service)[_.-]", "acct": "LS", "domain_acct": "DS"},
]

# Folder words that set the environment layer instead of becoming a folder code.
ENV_WORDS = {"production", "prod", "prd", "development", "dev", "test", "testing", "tst", "qa", "uat",
             "quality assurance", "staging", "stage"}


class Namer:
    def __init__(self, cfg):
        conv = cfg.get("safe_convention", {})
        self.cfg = conv
        self.template = conv.get("template") or "{env}-{folder}-{tech}-{flavor}-{acct}"
        self.sep = conv.get("separator", "-")
        self.max_len = cfg["safe_name"]["max_length"]
        self.abbr = {k.lower(): v for k, v in DEFAULT_ABBREVIATIONS.items()}
        self.abbr.update({k.lower(): v for k, v in (conv.get("abbreviations") or {}).items()})
        self.skip_levels = {s.lower() for s in conv.get("skip_folder_levels") or []}
        self.platform_codes = dict(DEFAULT_PLATFORM_CODES)
        self.platform_codes.update(conv.get("platform_codes") or {})
        self.pc_lower = {k.lower(): v for k, v in self.platform_codes.items()}
        self.acct_rules = conv.get("account_type_rules") or DEFAULT_ACCOUNT_TYPE_RULES
        self.default_env = conv.get("default_environment", "")
        self.max_phrase = max(len(k.split()) for k in self.abbr)
        self.env_words = ENV_WORDS | {w.lower() for w in conv.get("environment_words") or []}
        self.unknown = {}

    # -- words ----------------------------------------------------------------
    def auto(self, word):
        """Automatic code for a word missing from the dictionary."""
        w = word.upper()
        if len(w) <= 4 or w.isdigit() or (w.isalnum() and word.isupper()):
            return w[:4]
        out = w[0]
        for ch in w[1:]:
            if ch not in VOWELS and ch.isalnum() and ch != out[-1]:
                out += ch
            if len(out) == 3:
                break
        return out

    def level_codes(self, text):
        """['SQL Production Reporting'] -> [('SQL', 'SQL'), ('Production', 'P'), ...] (source, code)."""
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
    def layers(self, rec, platform, with_type=False):
        folder = []          # list of levels, each a list of codes
        env = ""
        for level in rec.folder:
            if level.lower() in self.skip_levels:
                continue
            codes = []
            for src, code in self.level_codes(level):
                if src.lower() in self.env_words:
                    env = env or code
                    continue
                codes.append(code)
            if codes:
                folder.append(codes)
        pc = self.pc_lower.get((platform or "").lower(), {})
        acct = pc.get("acct", "")
        for rule in self.acct_rules:
            if rule.get("tech") and rule["tech"] != pc.get("tech"):
                continue
            if rule.get("flavor") and not re.search(rule["flavor"], pc.get("flavor", "")):
                continue
            if re.search(rule["username"], rec.username or ""):
                acct = rule.get("domain_acct") if pc.get("tech") == "DOM" and rule.get("domain_acct") else rule["acct"]
                break
        return {"env": env or self.default_env, "folder": folder, "tech": pc.get("tech", ""),
                "flavor": pc.get("flavor", ""), "acct": acct,
                "type": [c for _, c in self.level_codes(rec.type)] if (with_type and rec.type) else []}

    # -- assemble -------------------------------------------------------------
    def build(self, rec, platform, template=None):
        """Return (name, notes). The name already fits max_length when possible."""
        template = template or self.template
        lay = self.layers(rec, platform, with_type="{type}" in template)
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
