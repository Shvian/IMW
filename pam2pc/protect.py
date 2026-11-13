"""Secret protection for values stored in the local database.

dpapi    Windows DPAPI (CryptProtectData) through ctypes, standard library only.
         A value can be decrypted only by the same Windows account on the same
         machine (or the account's roaming profile in a domain). Each value is
         bound to the database salt and its record id as extra entropy, so a
         blob copied into another database or row will not decrypt.
plain    NO protection. Only for tests and demos on non-Windows machines; the
         CLI requires --insecure-plaintext-secrets to choose it.
"""

import base64
import os
import sys


class ProtectError(Exception):
    pass


class DpapiProtector:
    name = "dpapi"

    def __init__(self, salt):
        if sys.platform != "win32":
            raise ProtectError("Windows DPAPI is only available on Windows. Run on the Windows "
                               "migration host, or use --no-secrets to stage metadata only.")
        import ctypes
        from ctypes import wintypes

        class Blob(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

        self._ct, self._Blob = ctypes, Blob
        self._crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        # Full prototypes, so 64-bit Python passes every pointer and flag at its real width.
        pblob = ctypes.POINTER(Blob)
        for fn in (self._crypt32.CryptProtectData, self._crypt32.CryptUnprotectData):
            fn.restype = wintypes.BOOL
        self._crypt32.CryptProtectData.argtypes = [pblob, wintypes.LPCWSTR, pblob, ctypes.c_void_p,
                                                   ctypes.c_void_p, wintypes.DWORD, pblob]
        self._crypt32.CryptUnprotectData.argtypes = [pblob, ctypes.POINTER(wintypes.LPWSTR), pblob,
                                                     ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, pblob]
        self._kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        self._kernel32.LocalFree.restype = ctypes.c_void_p
        self._salt = salt

    def _blob(self, data):
        buf = self._ct.create_string_buffer(data, len(data))
        return self._Blob(len(data), self._ct.cast(buf, self._ct.POINTER(self._ct.c_char))), buf

    def _call(self, fn, data, entropy, protect):
        ct = self._ct
        inb, b1 = self._blob(data)
        ent, b2 = self._blob(entropy)
        out = self._Blob()
        flags = 0x1  # CRYPTPROTECT_UI_FORBIDDEN
        try:
            if protect:
                ok = fn(ct.byref(inb), "pam2pc", ct.byref(ent), None, None, flags, ct.byref(out))
            else:
                ok = fn(ct.byref(inb), None, ct.byref(ent), None, None, flags, ct.byref(out))
            if not ok:
                raise ProtectError(f"DPAPI call failed (Windows error {ct.get_last_error()}). A database "
                                   "can only be decrypted by the Windows account that created it.")
            try:
                return ct.string_at(out.pbData, out.cbData)
            finally:
                # Zero the Windows-side copy (the plaintext, when decrypting) before freeing it.
                if out.pbData and out.cbData:
                    ct.memset(out.pbData, 0, out.cbData)
                self._kernel32.LocalFree(ct.cast(out.pbData, ct.c_void_p))
        finally:
            # Our own input copies (the plaintext, when encrypting). The Python str/bytes the
            # caller holds are immutable and cannot be wiped; Python frees them as usual.
            ct.memset(b1, 0, len(b1))
            ct.memset(b2, 0, len(b2))

    def protect(self, plaintext, record_id):
        blob = self._call(self._crypt32.CryptProtectData, plaintext.encode("utf-8"),
                          self._salt + record_id.encode("utf-8"), True)
        return "dpapi:" + base64.b64encode(blob).decode("ascii")

    def unprotect(self, stored, record_id):
        if not stored.startswith("dpapi:"):
            raise ProtectError("value was not stored with DPAPI")
        data = self._call(self._crypt32.CryptUnprotectData, base64.b64decode(stored[6:]),
                          self._salt + record_id.encode("utf-8"), False)
        return data.decode("utf-8")


class PlainProtector:
    """No protection at all. Tests and non-Windows demos only."""
    name = "plain"

    def __init__(self, salt):
        self._salt = salt

    def protect(self, plaintext, record_id):
        return "plain:" + plaintext

    def unprotect(self, stored, record_id):
        if not stored.startswith("plain:"):
            raise ProtectError("value was not stored as plain text")
        return stored[6:]


PROTECTORS = {"dpapi": DpapiProtector, "plain": PlainProtector}


def new_salt():
    return os.urandom(16)


def get_protector(name, salt):
    try:
        return PROTECTORS[name](salt)
    except KeyError:
        raise ProtectError(f"unknown protector '{name}'")
