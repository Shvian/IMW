"""Common data model every source adapter produces."""

from collections import OrderedDict
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass
class Grant:
    """One principal's access to a record, as the source expressed it."""
    member: str
    permission: str              # source wording: Owner, Edit, View, Read, Full...
    member_type: str = ""        # Group or User; blank -> config default_member_type


@dataclass
class SourceRecord:
    """One credential from any source, before any target rules are applied."""
    source: str                  # adapter name
    source_file: str             # file stem, used in Record_ID
    source_id: str               # id unique within the file (Secret ID, UUID, row number)
    source_ref: str              # human pointer, e.g. "line 12" or "Sheet1!row 7"
    name: str = ""
    folder: Tuple[str, ...] = ()
    type: str = ""               # template / account type, drives platform mapping
    address: str = ""
    username: str = ""
    secret: str = ""
    secret_type: str = "password"   # password | key
    has_secret: Optional[bool] = None  # set when loaded from the database without the secret
    # None = the source has no access data for this record (use --permissions);
    # [] = the source says nobody has access.
    grants: Optional[List[Grant]] = None
    access_source: str = ""      # where grants came from: source, record, folder, none
    # Explicit target values a spreadsheet may already carry.
    target_safe: str = ""
    target_platform: str = ""
    # Non-secret source columns kept for review and platformAccountProperties.
    extra: "OrderedDict[str, str]" = field(default_factory=OrderedDict)
    notes: List[str] = field(default_factory=list)

    @property
    def record_id(self):
        return f"{self.source}:{self.source_file}:{self.source_id}"

    @property
    def folder_path(self):
        return "\\" + "\\".join(self.folder) if self.folder else "\\"


def split_folder(path, separator="\\"):
    """Split a folder path into clean levels. separator "auto" picks \\ if present, else /."""
    path = (path or "").strip()
    if separator == "auto":
        separator = "\\" if "\\" in path else "/"
    return tuple(p.strip() for p in path.split(separator) if p.strip())
