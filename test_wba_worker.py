"""
Parity test: the Cloudflare Worker (wba-directory-worker/worker.js, run under Node's
WebCrypto) must produce a directory response that tools/wba.py verifies, with the same
keyid Python computes. Run: python tools/test_wba_worker.py   (needs node on PATH)
"""

import base64
import json
import os
import shutil
import subprocess
import sys
import unittest

from cryptography.hazmat.primitives import serialization

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wba  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
WORKER_DIR = os.path.join(HERE, "wba_directory_worker")


@unittest.skipUnless(shutil.which("node"), "node not installed")
class WorkerParity(unittest.TestCase):
    def test_worker_directory_verifies_in_python(self):
        priv = wba.generate_private_key()          # throwaway key, never the real one
        der = priv.private_bytes(serialization.Encoding.DER,
                                 serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption())
        kid = wba.thumbprint(wba.public_jwk(priv.public_key()))
        authority = "marketfauna-wba-directory.example.workers.dev"
        out = subprocess.run(
            ["node", "test-parity.mjs", base64.b64encode(der).decode(), authority],
            cwd=WORKER_DIR, capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(out.returncode, 0, out.stderr)
        res = json.loads(out.stdout.strip().splitlines()[-1])
        self.assertEqual(res["status"], 200)
        self.assertEqual(res["redirect"], 302)
        self.assertEqual(res["headers"]["content-type"], wba.DIRECTORY_MEDIA_TYPE)
        self.assertEqual(res["headers"]["cache-control"], "no-store")
        body = json.loads(res["body"])
        self.assertEqual(list(body.keys()), ["keys"])
        self.assertEqual(sorted(body["keys"][0].keys()), ["crv", "kty", "x"])   # no d, ever
        self.assertNotIn('"d"', res["body"])
        valid, reasons = wba.verify_directory_response(authority, res["headers"], res["body"].encode())
        self.assertEqual(list(valid), [kid], reasons)
        # the same response is not valid for a different authority (binding to the directory host)
        valid, _ = wba.verify_directory_response("other.example", res["headers"], res["body"].encode())
        self.assertEqual(valid, {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
