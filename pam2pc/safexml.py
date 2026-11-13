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
    raise UnsafeXmlError("the XML declares a DTD or entities, which pam2pc does not accept")


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


def check_file(path, chunk=1 << 20):
    p = _checker()
    try:
        with open(path, "rb") as fh:
            while True:
                block = fh.read(chunk)
                p.Parse(block, not block)
                if not block:
                    break
    except expat.ExpatError as exc:
        raise ET.ParseError(f"{path}: {exc}") from None


def fromstring(data):
    check(data)
    return ET.fromstring(data)


def parse(path):
    check_file(path)
    return ET.parse(path)
