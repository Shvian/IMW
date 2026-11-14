"""XML parsing that refuses document type declarations (standard library only).

Source exports (KeePass XML, the parts inside an .xlsx) never need a DTD. A DTD is what
entity-expansion attacks ("billion laughs", external entities) rely on, so any document
that declares one is rejected before ElementTree builds a tree from it.
"""

import codecs
import re
import xml.etree.ElementTree as ET
from xml.parsers import expat


class UnsafeXmlError(ValueError):
    pass


def _refuse(*_args):
    raise UnsafeXmlError("the XML declares a DTD or entities, which the Workbench does not accept")


def _checker():
    p = expat.ParserCreate()
    p.StartDoctypeDeclHandler = _refuse
    p.EntityDeclHandler = _refuse
    p.UnparsedEntityDeclHandler = _refuse
    p.ExternalEntityRefHandler = _refuse
    return p


def check(data):
    """Raise UnsafeXmlError when data (bytes or str) declares a DTD or entities."""
    try:
        _checker().Parse(data, True)
    except expat.ExpatError as exc:
        raise ET.ParseError(str(exc)) from None


MAX_FILE_BYTES = 512 * 1024 * 1024   # same limit as one part of an .xlsx


def read_head_text(path, size=8192):
    """The start of an XML file as text (for sniffing), decoded like parse() does."""
    try:
        with open(path, "rb") as fh:
            data = fh.read(size)
    except OSError:
        return ""
    if data[:2] in (codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE) or (len(data) > 1 and 0 in data[:2]):
        data = data[: len(data) - len(data) % 2]
    try:
        return decode(data)
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace")


def read_capped(path, limit=None):
    """The file's bytes, read once; refuse a file larger than limit."""
    limit = MAX_FILE_BYTES if limit is None else limit
    with open(path, "rb") as fh:
        data = fh.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"{path}: larger than {limit // (1024 * 1024)} MB; split the export")
    return data


_DECLARED = re.compile(rb"""^<\?xml[^>]*?encoding\s*=\s*["']([A-Za-z0-9._-]+)["']""")


def decode(data):
    """Bytes of an XML file -> text, whatever the file says about itself.

    Windows tools write XML as UTF-16 (with or without a byte order mark), and some, such as
    Delinea's KeePass migration tool, declare encoding="utf-16" on a file whose bytes are
    plain UTF-8. Expat refuses such a file, so the bytes are decoded here from what they
    really are: byte order mark first, then the zero-byte pattern of UTF-16, then UTF-8,
    then the declared encoding, then Windows-1252."""
    if isinstance(data, str):
        return data
    if data.startswith(codecs.BOM_UTF8):
        return data[3:].decode("utf-8")
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return data.decode("utf-16")
    head = data[:2]
    if len(head) == 2 and head[1] == 0 and head[0] != 0:
        return data.decode("utf-16-le")
    if len(head) == 2 and head[0] == 0 and head[1] != 0:
        return data.decode("utf-16-be")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        pass
    m = _DECLARED.match(data)
    if m and not m.group(1).lower().startswith(b"utf-16"):
        try:
            return data.decode(m.group(1).decode("ascii"))
        except (LookupError, UnicodeDecodeError):
            pass
    return data.decode("cp1252", errors="replace")


def fromstring(data):
    check(data)
    return ET.fromstring(data)


def parse(path):
    """Read the file once, check it, then build the tree from the same bytes (no second
    read, so the file cannot change between the check and the parse)."""
    data = read_capped(path)
    try:
        text = decode(data)
    except UnicodeDecodeError as exc:
        raise ET.ParseError(f"{path}: cannot read the text encoding ({exc})") from None
    try:
        return ET.ElementTree(fromstring(text))
    except ET.ParseError as exc:
        raise ET.ParseError(f"{path}: {exc}") from None
