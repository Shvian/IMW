"""HTTPS for the Workbench with a self-signed certificate, standard library only.

The certificate is made on the computer the Workbench runs on, in pure Python (RSA 2048,
SHA-256), because Windows has no openssl and pam2pc installs nothing. Its subject is this
computer's name, and its alternative names (SAN) are this computer's host name and full DNS
name, localhost, 127.0.0.1 and ::1. It is valid for 397 days, is remade when the computer's
name no longer matches, and is kept in <workspace>/tls/ so you can trust it once:

  workbench.crt         the certificate (public). Double-click it, or run
                        "python -m pam2pc ui --trust-cert", to trust it for your Windows user.
  workbench.key.dpapi   the private key, encrypted with Windows DPAPI for your user.
                        On other systems (tests only) workbench.key.pem, readable by you only.

At start-up the key is decrypted into a temporary file inside <workspace>/tls (owner-only)
only for as long as it takes Python to load it, then that file is overwritten and deleted.
"""

import base64
import datetime as dt
import hashlib
import os
import re
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
from pathlib import Path

CERT_NAME = "workbench.crt"
KEY_DPAPI = "workbench.key.dpapi"
KEY_PEM = "workbench.key.pem"
VALID_DAYS = 397          # browsers reject longer-lived server certificates
RENEW_DAYS = 30           # make a new one when less than this is left
ORGANIZATION = "Idira Migration Workbench"


class TlsError(Exception):
    pass


# ---------------------------------------------------------------- DER encoding

def _len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag, content):
    return bytes([tag]) + _len(len(content)) + content


def _int(n):
    b = n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big")   # leading 0 keeps it positive
    return _tlv(0x02, b)


def _seq(*items):
    return _tlv(0x30, b"".join(items))


def _set(*items):
    return _tlv(0x31, b"".join(items))


def _oid(dotted):
    parts = [int(p) for p in dotted.split(".")]
    out = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.append(0x80 | (p & 0x7F))
            p >>= 7
        out += bytes(reversed(chunk))
    return _tlv(0x06, out)


def _bits(data):
    return _tlv(0x03, b"\x00" + data)


def _octets(data):
    return _tlv(0x04, data)


def _utf8(text):
    return _tlv(0x0C, text.encode("utf-8"))


def _time(when):
    if when.year < 2050:
        return _tlv(0x17, when.strftime("%y%m%d%H%M%SZ").encode())
    return _tlv(0x18, when.strftime("%Y%m%d%H%M%SZ").encode())


NULL = b"\x05\x00"
RSA_ENCRYPTION = _seq(_oid("1.2.840.113549.1.1.1"), NULL)
SHA256_WITH_RSA = _seq(_oid("1.2.840.113549.1.1.11"), NULL)
SHA256_DIGESTINFO = bytes.fromhex("3031300d060960864801650304020105000420")


# ---------------------------------------------------------------- RSA

_SMALL_PRIMES = [p for p in range(3, 2000) if all(p % d for d in range(2, int(p ** 0.5) + 1))]


def _probably_prime(n, rounds=40):
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(bits, e):
    while True:
        c = secrets.randbits(bits) | (3 << (bits - 2)) | 1   # top two bits set: n has full length
        if (c - 1) % e and _probably_prime(c):
            return c


def generate_rsa(bits=2048, e=65537):
    while True:
        p, q = _prime(bits // 2, e), _prime(bits // 2, e)
        if p != q and (p * q).bit_length() == bits:
            break
    if p < q:
        p, q = q, p
    n, phi = p * q, (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    return {"n": n, "e": e, "d": d, "p": p, "q": q,
            "dp": d % (p - 1), "dq": d % (q - 1), "qinv": pow(q, -1, p)}


def _sign(key, data):
    k = (key["n"].bit_length() + 7) // 8
    t = SHA256_DIGESTINFO + hashlib.sha256(data).digest()
    em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    m = int.from_bytes(em, "big")
    m1, m2 = pow(m, key["dp"], key["p"]), pow(m, key["dq"], key["q"])     # CRT
    s = m2 + key["q"] * ((key["qinv"] * (m1 - m2)) % key["p"])
    if pow(s, key["e"], key["n"]) != m:
        raise TlsError("RSA self-check failed")
    return s.to_bytes(k, "big")


def key_der(key):
    return _seq(_int(0), *(_int(key[f]) for f in ("n", "e", "d", "p", "q", "dp", "dq", "qinv")))


def _pem(label, der):
    body = base64.encodebytes(der).decode("ascii").replace("\n", "")
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n"


# ---------------------------------------------------------------- certificate

_DNS_NAME = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


def machine_names():
    """This computer's DNS names, most specific first: full DNS name, then host name."""
    names = []
    for n in (socket.getfqdn(), socket.gethostname()):
        n = (n or "").strip().rstrip(".").lower()
        if n and _DNS_NAME.match(n) and n not in names and n != "localhost" and not n.replace(".", "").isdigit():
            names.append(n)
    return names


def make_certificate(key, now=None, days=VALID_DAYS, names=None):
    now = (now or dt.datetime.now(dt.timezone.utc)).replace(microsecond=0)
    names = machine_names() if names is None else names
    subject = names[0] if names else "localhost"
    name = _seq(_set(_seq(_oid("2.5.4.3"), _utf8(subject))),
                _set(_seq(_oid("2.5.4.10"), _utf8(ORGANIZATION))))
    spki = _seq(RSA_ENCRYPTION, _bits(_seq(_int(key["n"]), _int(key["e"]))))
    ski = hashlib.sha1(_seq(_int(key["n"]), _int(key["e"]))).digest()
    san = _seq(*(_tlv(0x82, n.encode("ascii")) for n in names + ["localhost"]),
               _tlv(0x87, bytes([127, 0, 0, 1])), _tlv(0x87, bytes(15) + b"\x01"))      # 127.0.0.1 and ::1
    critical = _tlv(0x01, b"\xff")
    extensions = _seq(
        _seq(_oid("2.5.29.17"), _octets(san)),                                   # subjectAltName
        _seq(_oid("2.5.29.19"), critical, _octets(_seq())),                       # basicConstraints CA:FALSE
        _seq(_oid("2.5.29.15"), critical, _octets(_tlv(0x03, b"\x05\xa0"))),     # digitalSignature, keyEncipherment
        _seq(_oid("2.5.29.37"), _octets(_seq(_oid("1.3.6.1.5.5.7.3.1")))),      # serverAuth
        _seq(_oid("2.5.29.14"), _octets(_octets(ski))),                          # subjectKeyIdentifier
    )
    tbs = _seq(
        _tlv(0xA0, _int(2)),                                    # v3
        _int(secrets.randbits(63) | (1 << 62)),
        SHA256_WITH_RSA,
        name,
        _seq(_time(now - dt.timedelta(minutes=5)), _time(now + dt.timedelta(days=days))),
        name,
        spki,
        _tlv(0xA3, extensions),
    )
    return _seq(tbs, SHA256_WITH_RSA, _bits(_sign(key, tbs)))


def _read(der, i):
    """(tag, content start, end) of the DER element at i."""
    tag, n = der[i], der[i + 1]
    i += 2
    if n & 0x80:
        size = int.from_bytes(der[i:i + (n & 0x7F)], "big")
        i += n & 0x7F
        n = size
    return tag, i, i + n


def _children(der, start, end):
    out, i = [], start
    while i < end:
        tag, s, e = _read(der, i)
        out.append((tag, s, e))
        i = e
    return out


def cert_dns_names(cert_pem):
    """DNS names in the certificate's subjectAltName."""
    der = ssl.PEM_cert_to_DER_cert(cert_pem)
    at = der.find(b"\x06\x03\x55\x1d\x11")          # OID 2.5.29.17
    if at < 0:
        return []
    _, _, e = _read(der, at)
    tag, s, e = _read(der, e)                          # the extension's value (an OCTET STRING)
    if tag == 0x01:                                    # skip a critical flag if there is one
        tag, s, e = _read(der, e)
    _, s, e = _read(der, s)                            # GeneralNames SEQUENCE
    return [der[cs:ce].decode("ascii").lower() for t, cs, ce in _children(der, s, e) if t == 0x82]


def cert_expiry(cert_pem):
    """Not-after date of a PEM certificate."""
    der = ssl.PEM_cert_to_DER_cert(cert_pem)
    _, s, e = _read(der, 0)
    _, ts, te = _children(der, s, e)[0]                 # tbsCertificate
    fields = _children(der, ts, te)
    if fields[0][0] == 0xA0:                            # skip explicit version
        fields = fields[1:]
    _, vs, ve = fields[3]                               # serial, sigalg, issuer, validity
    tag, s, e = _children(der, vs, ve)[1]
    text = der[s:e].decode("ascii")
    fmt = "%y%m%d%H%M%SZ" if tag == 0x17 else "%Y%m%d%H%M%SZ"
    return dt.datetime.strptime(text, fmt).replace(tzinfo=dt.timezone.utc)


# ---------------------------------------------------------------- key storage

def _dpapi():
    from ..protect import DpapiProtector
    return DpapiProtector(b"pam2pc-workbench-tls")


def _save_key(folder, key_pem):
    if sys.platform == "win32":
        (folder / KEY_DPAPI).write_text(_dpapi().protect(key_pem, "workbench-key"), encoding="ascii")
    else:
        path = folder / KEY_PEM
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(key_pem)


def _load_key(folder):
    if sys.platform == "win32":
        path = folder / KEY_DPAPI
        return _dpapi().unprotect(path.read_text(encoding="ascii"), "workbench-key") if path.exists() else None
    path = folder / KEY_PEM
    return path.read_text() if path.exists() else None


def _wipe(path):
    try:
        size = path.stat().st_size
        with open(path, "r+b") as fh:
            fh.write(secrets.token_bytes(size))
            fh.flush()
            os.fsync(fh.fileno())
    except OSError:
        pass
    try:
        path.unlink()
    except OSError:
        pass


def ensure_certificate(workspace, renew=False):
    """Returns (cert_path, key_pem, created). Makes a new pair when missing, unreadable, near expiry,
    or made for another computer name (or before the name was put in)."""
    folder = Path(workspace) / "tls"
    folder.mkdir(parents=True, exist_ok=True)
    cert_path = folder / CERT_NAME
    if not renew and cert_path.exists():
        try:
            key_pem = _load_key(folder)
            pem = cert_path.read_text()
            left = cert_expiry(pem) - dt.datetime.now(dt.timezone.utc)
            named = set(machine_names()) <= set(cert_dns_names(pem))     # same computer name
            if key_pem and named and left > dt.timedelta(days=RENEW_DAYS):
                return cert_path, key_pem, False
        except Exception:   # noqa: BLE001 - unreadable (other Windows user, damaged): make a new one
            pass
    key = generate_rsa()
    key_pem = _pem("RSA PRIVATE KEY", key_der(key))
    cert_pem = _pem("CERTIFICATE", make_certificate(key))
    _save_key(folder, key_pem)
    cert_path.write_text(cert_pem, encoding="ascii")
    return cert_path, key_pem, True


def _context(cert_path, key_pem):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # The decrypted key goes next to the certificate, in <workspace>/tls, which is locked to
    # the owner and SYSTEM (claim_workspace), not in %TEMP%, which may be shared.
    tmp = Path(tempfile.mkdtemp(prefix="load-", dir=Path(cert_path).parent))
    key_file = tmp / "k.pem"
    try:
        fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(key_pem)
        ctx.load_cert_chain(str(cert_path), str(key_file))
    finally:
        _wipe(key_file)
        try:
            tmp.rmdir()
        except OSError:
            pass
    return ctx


def server_context(workspace, renew=False):
    """An ssl.SSLContext for the Workbench server, plus (cert_path, created)."""
    cert_path, key_pem, created = ensure_certificate(workspace, renew)
    try:
        ctx = _context(cert_path, key_pem)
    except ssl.SSLError:
        if created:
            raise
        cert_path, key_pem, created = ensure_certificate(workspace, renew=True)   # damaged pair
        ctx = _context(cert_path, key_pem)
    return ctx, cert_path, created


def fingerprint(cert_path):
    der = ssl.PEM_cert_to_DER_cert(Path(cert_path).read_text())
    h = hashlib.sha256(der).hexdigest().upper()
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


def trust_certificate(cert_path):
    """Adds the certificate to the current Windows user's Trusted Root store (Windows asks to confirm)."""
    if sys.platform != "win32":
        raise TlsError("--trust-cert works on Windows only. Elsewhere, trust the file in your browser.")
    done = subprocess.run(["certutil", "-user", "-addstore", "Root", str(cert_path)],
                          capture_output=True, text=True)
    if done.returncode != 0:
        raise TlsError(f"certutil could not add the certificate: {(done.stdout + done.stderr).strip()}")
