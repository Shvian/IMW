"""XML parsing that refuses document type declarations (standard library only).

Source exports (KeePass XML, the parts inside an .xlsx) never need a DTD. A DTD is what
entity-expansion attacks ("billion laughs", external entities) rely on, so any document
that declares one is rejected before ElementTree builds a tree from it.
"""

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


def read_capped(path, limit=None):
    """The file's bytes, read once; refuse a file larger than limit."""
    limit = MAX_FILE_BYTES if limit is None else limit
    with open(path, "rb") as fh:
        data = fh.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"{path}: larger than {limit // (1024 * 1024)} MB; split the export")
    return data


def fromstring(data):
    check(data)
    return ET.fromstring(data)


def parse(path):
    """Read the file once, check it, then build the tree from the same bytes (no second
    read, so the file cannot change between the check and the parse)."""
    data = read_capped(path)
    try:
        return ET.ElementTree(fromstring(data))
    except ET.ParseError as exc:
        raise ET.ParseError(f"{path}: {exc}") from None
