"""Self-signed HTTPS certificate for the Workbench (pure Python RSA and X.509)."""

import datetime as dt
import shutil
import ssl
import subprocess
import tempfile
import unittest
from pathlib import Path

from pam2pc.ui import tls


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

    def test_damaged_key_makes_a_new_pair(self):
        cert, _, _ = tls.ensure_certificate(self.ws)
        before = cert.read_text()
        (self.ws / "tls" / tls.KEY_PEM).write_text("rubbish")
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
