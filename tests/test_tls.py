"""Self-signed HTTPS certificate for the Workbench (pure Python RSA and X.509)."""

import datetime as dt
import shutil
import ssl
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from imw.ui import tls


class Certificate(unittest.TestCase):
    def setUp(self):
        self.ws = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.ws, ignore_errors=True)

    def test_made_once_then_reused(self):
        cert, key, created = tls.ensure_certificate(self.ws)
        self.assertTrue(created)
        self.assertIn("BEGIN RSA PRIVATE KEY", key)
        left = tls.cert_expiry(cert.read_text()) - dt.datetime.now(dt.timezone.utc)
        self.assertGreater(left, dt.timedelta(days=390))
        self.assertLess(left, dt.timedelta(days=398))
        again = tls.ensure_certificate(self.ws)
        self.assertFalse(again[2])
        self.assertEqual(again[1], key)
        self.assertTrue(tls.ensure_certificate(self.ws, renew=True)[2])

    def test_python_ssl_accepts_it_for_127_0_0_1_and_localhost(self):
        ctx, cert, _ = tls.server_context(self.ws)
        self.assertEqual(list((self.ws / "tls").iterdir()).__len__(), 2)   # no key file left behind
        client = ssl.create_default_context(cafile=str(cert))
        self.assertEqual(len(tls.fingerprint(cert)), 95)
        self.assertIsInstance(ctx, ssl.SSLContext)
        import socket
        import threading
        srv = socket.create_server(("127.0.0.1", 0))
        port = srv.getsockname()[1]

        def accept():
            conn, _ = srv.accept()
            with ctx.wrap_socket(conn, server_side=True) as s:
                s.recv(1)

        t = threading.Thread(target=accept, daemon=True)
        t.start()
        for host in ("127.0.0.1", "localhost"):
            if host == "localhost":
                t = threading.Thread(target=accept, daemon=True)
                t.start()
            with socket.create_connection(("127.0.0.1", port)) as raw:
                with client.wrap_socket(raw, server_hostname=host) as s:    # checks name and signature
                    self.assertEqual(s.version() in ("TLSv1.2", "TLSv1.3"), True)
                    s.send(b"x")
        srv.close()

    def test_named_after_this_computer(self):
        cert, _, _ = tls.ensure_certificate(self.ws)
        names = tls.cert_dns_names(cert.read_text())
        self.assertTrue(set(tls.machine_names()) <= set(names))
        self.assertIn("localhost", names)
        with mock.patch.object(tls, "machine_names", lambda: ["jumphost01.corp.example.com", "jumphost01"]):
            cert, _, created = tls.ensure_certificate(self.ws)      # renamed computer: new certificate
            self.assertTrue(created)
            self.assertEqual(tls.cert_dns_names(cert.read_text())[:2], ["jumphost01.corp.example.com", "jumphost01"])
            self.assertFalse(tls.ensure_certificate(self.ws)[2])
            ctx, cert, _ = tls.server_context(self.ws)
            self._handshake(ctx, cert, "jumphost01.corp.example.com")

    def _handshake(self, ctx, cert, host):
        import socket
        import threading
        client = ssl.create_default_context(cafile=str(cert))
        srv = socket.create_server(("127.0.0.1", 0))

        def accept():
            conn, _ = srv.accept()
            with ctx.wrap_socket(conn, server_side=True) as s:
                s.recv(1)
        threading.Thread(target=accept, daemon=True).start()
        with socket.create_connection(("127.0.0.1", srv.getsockname()[1])) as raw:
            with client.wrap_socket(raw, server_hostname=host) as s:     # checks the name and the signature
                s.send(b"x")
        srv.close()

    def test_damaged_key_makes_a_new_pair(self):
        cert, _, _ = tls.ensure_certificate(self.ws)
        before = cert.read_text()
        (self.ws / "tls" / (tls.KEY_DPAPI if sys.platform == "win32" else tls.KEY_PEM)).write_text("rubbish")
        _, cert, created = tls.server_context(self.ws)
        self.assertTrue(created)
        self.assertNotEqual(cert.read_text(), before)

    @unittest.skipUnless(shutil.which("openssl"), "openssl not installed")
    def test_openssl_verifies_signature(self):
        cert, _, _ = tls.ensure_certificate(self.ws)
        done = subprocess.run(["openssl", "verify", "-CAfile", str(cert), "-purpose", "sslserver", str(cert)],
                              capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)


if __name__ == "__main__":
    unittest.main()
