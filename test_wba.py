"""
Tests for wba.py. Run: python tools/test_wba.py

Covers: the verifier against Cloudflare's live signed directory (captured 2026-09-13
08:58:54 GMT from http-message-signatures-example.research.cloudflare.com, signed with
the RFC 9421 Appendix B.1.4 Ed25519 test key), request sign/verify, expiry, tampering,
wrong key, and a local controlled endpoint: a directory server plus a verifying server,
with the collector-style client signing its requests.
"""

import http.server
import json
import os
import sys
import threading
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wba  # noqa: E402

CF_AUTHORITY = "http-message-signatures-example.research.cloudflare.com"
CF_HEADERS = {
    "content-type": "application/http-message-signatures-directory+json",
    "signature": "binding0=:LMSL6/1OnK3uVZGyxaaEPiRKS4lv3WhkFvOpcUk+aUjy5AsnepcsQqTtzZR/rmqjs8/hZ+epdAA/eqjGTsTdAQ==:",
    "signature-input": 'binding0=("@authority";req);created=1789289934;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1789290234;tag="http-message-signatures-directory"',
}
CF_BODY = b'{"keys":[{"kid":"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U","kty":"OKP","crv":"Ed25519","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs","nbf":1743465600000}],"purpose":"rag"}'
CF_KID = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"
CF_FETCH_TIME = 1789289934  # the response's own created value; fetched within its window


class CloudflareSample(unittest.TestCase):
    def test_thumbprint_matches_cloudflare_kid(self):
        jwk = json.loads(CF_BODY)["keys"][0]
        self.assertEqual(wba.thumbprint(jwk), CF_KID)

    def test_live_directory_signature_verifies(self):
        valid, reasons = wba.verify_directory_response(CF_AUTHORITY, CF_HEADERS, CF_BODY, now=CF_FETCH_TIME + 5)
        self.assertEqual(list(valid), [CF_KID], reasons)

    def test_live_directory_rejected_for_other_authority(self):
        valid, reasons = wba.verify_directory_response("example.com", CF_HEADERS, CF_BODY, now=CF_FETCH_TIME + 5)
        self.assertEqual(valid, {})
        self.assertIn("binding0: signature invalid", reasons)

    def test_live_directory_rejected_after_expiry(self):
        valid, reasons = wba.verify_directory_response(CF_AUTHORITY, CF_HEADERS, CF_BODY, now=1789290235)
        self.assertEqual(valid, {})


class Requests(unittest.TestCase):
    def setUp(self):
        self.priv = wba.generate_private_key()
        self.jwk = wba.public_jwk(self.priv.public_key())
        self.kid = wba.thumbprint(self.jwk)
        self.keys = {self.kid: self.priv.public_key()}
        self.url = "https://api.github.com/search/repositories?q=agent"

    def test_valid_request(self):
        h = wba.sign_request(self.priv, self.kid, "GET", self.url, "https://marketfauna.com", now=1000)
        self.assertEqual(h["Signature-Agent"], '"https://marketfauna.com"')
        ok, reason, kid = wba.verify_request("GET", self.url, h, self.keys, now=1030)
        self.assertTrue(ok, reason)
        self.assertEqual(kid, self.kid)

    def test_expired_request_fails(self):
        h = wba.sign_request(self.priv, self.kid, "GET", self.url, "https://marketfauna.com", now=1000, expires_in=60)
        ok, reason, _ = wba.verify_request("GET", self.url, h, self.keys, now=1061)
        self.assertFalse(ok)
        self.assertEqual(reason, "expired")

    def test_tampered_authority_fails(self):
        h = wba.sign_request(self.priv, self.kid, "GET", self.url, "https://marketfauna.com", now=1000)
        ok, reason, _ = wba.verify_request("GET", "https://evil.example/search", h, self.keys, now=1010)
        self.assertFalse(ok)
        self.assertTrue(reason.startswith("signature invalid"), reason)

    def test_tampered_signature_agent_fails(self):
        h = wba.sign_request(self.priv, self.kid, "GET", self.url, "https://marketfauna.com", now=1000)
        h["Signature-Agent"] = '"https://someone-else.example"'
        ok, reason, _ = wba.verify_request("GET", self.url, h, self.keys, now=1010)
        self.assertFalse(ok)

    def test_wrong_key_fails(self):
        other = wba.generate_private_key()
        h = wba.sign_request(other, self.kid, "GET", self.url, "https://marketfauna.com", now=1000)
        ok, reason, _ = wba.verify_request("GET", self.url, h, self.keys, now=1010)
        self.assertFalse(ok)

    def test_unknown_keyid_fails(self):
        h = wba.sign_request(self.priv, "nope", "GET", self.url, "https://marketfauna.com", now=1000)
        ok, reason, _ = wba.verify_request("GET", self.url, h, self.keys, now=1010)
        self.assertEqual(reason, "unknown keyid")

    def test_wrong_tag_fails(self):
        h = wba.sign_request(self.priv, self.kid, "GET", self.url, "https://marketfauna.com", now=1000)
        h["Signature-Input"] = h["Signature-Input"].replace('tag="web-bot-auth"', 'tag="other"')
        ok, reason, _ = wba.verify_request("GET", self.url, h, self.keys, now=1010)
        self.assertEqual(reason, "wrong tag")

    def test_directory_roundtrip(self):
        body = wba.directory_body([self.jwk])
        h = wba.sign_directory_response(self.priv, self.kid, "marketfauna.com", now=1000)
        self.assertEqual(h["Cache-Control"], "no-store")
        valid, reasons = wba.verify_directory_response("marketfauna.com", h, body, now=1010)
        self.assertEqual(list(valid), [self.kid], reasons)
        valid, reasons = wba.verify_directory_response("marketfauna.com", h, body, now=2000)
        self.assertEqual(valid, {})
        # a key the response does not sign for is ignored
        stranger = wba.public_jwk(wba.generate_private_key().public_key())
        body2 = wba.directory_body([self.jwk, stranger])
        valid, _ = wba.verify_directory_response("marketfauna.com", h, body2, now=1010)
        self.assertEqual(list(valid), [self.kid])

    def test_valid_signature_without_agent_binding_is_rejected(self):
        import base64

        # Cryptographically valid, but identity can be changed without resigning.
        idents = ['"@authority"']
        params = [("alg", "ed25519"), ("keyid", self.kid),
                  ("tag", wba.REQUEST_TAG), ("created", 1000), ("expires", 1060)]
        ser = wba.serialize_params(idents, params)
        components = [(i, wba.component_value(i, "GET", self.url, {})) for i in idents]
        sig = self.priv.sign(wba.signature_base(components, ser))
        h = {"Signature-Input": "sig1=" + ser,
             "Signature": "sig1=:" + base64.b64encode(sig).decode() + ":",
             "Signature-Agent": '"https://other.example"'}
        ok, reason, _ = wba.verify_request("GET", self.url, h, self.keys, now=1010)
        self.assertFalse(ok)
        self.assertEqual(reason, "signature-agent not covered")


# --------------------------------------------------------------------------- controlled endpoint

class _Quiet(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass


def _directory_handler(priv, kid, jwk):
    class H(_Quiet):
        def do_GET(self):
            if self.path != wba.DIRECTORY_PATH:
                self.send_response(404); self.end_headers(); return
            body = wba.directory_body([jwk])
            hdrs = wba.sign_directory_response(priv, kid, self.headers["Host"])
            self.send_response(200)
            for k, v in hdrs.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    return H


def _verifier_handler(seen):
    """Verifies each request by fetching the directory named in Signature-Agent."""
    class H(_Quiet):
        def do_GET(self):
            headers = {k: v for k, v in self.headers.items()}
            url = "http://{}{}".format(self.headers["Host"], self.path)
            agent = headers.get("Signature-Agent", "").strip('"')
            keys = {}
            if agent:
                req = urllib.request.Request(agent + wba.DIRECTORY_PATH,
                                             headers={"Accept": wba.DIRECTORY_MEDIA_TYPE})
                with urllib.request.urlopen(req, timeout=5) as r:
                    dh = {k: v for k, v in r.headers.items()}
                    keys, _ = wba.verify_directory_response(r.headers["Host"] if "Host" in r.headers else
                                                            agent.split("//")[1], dh, r.read())
            ok, reason, kid = wba.verify_request("GET", url, headers, keys)
            seen.append((ok, reason, kid))
            self.send_response(200 if ok else 401)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write("{} {} {}".format("verified" if ok else "rejected", reason, kid).encode())
    return H


class ControlledEndpoint(unittest.TestCase):
    def test_end_to_end(self):
        priv = wba.generate_private_key()
        jwk = wba.public_jwk(priv.public_key())
        kid = wba.thumbprint(jwk)
        seen = []
        dsrv = http.server.HTTPServer(("127.0.0.1", 0), _directory_handler(priv, kid, jwk))
        vsrv = http.server.HTTPServer(("127.0.0.1", 0), _verifier_handler(seen))
        for s in (dsrv, vsrv):
            threading.Thread(target=s.serve_forever, daemon=True).start()
        try:
            agent = "http://127.0.0.1:{}".format(dsrv.server_address[1])   # https in production
            target = "http://127.0.0.1:{}/collect".format(vsrv.server_address[1])

            # signed request from the collector-style client
            h = wba.sign_request(priv, kid, "GET", target, agent)
            with urllib.request.urlopen(urllib.request.Request(target, headers=h), timeout=5) as r:
                self.assertEqual(r.status, 200)
                self.assertTrue(r.read().startswith(b"verified ok " + kid.encode()))

            # unsigned request is rejected
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(urllib.request.Request(target), timeout=5)
            self.assertEqual(cm.exception.code, 401)

            # expired signature is rejected
            h = wba.sign_request(priv, kid, "GET", target, agent, now=1000, expires_in=1)
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(urllib.request.Request(target, headers=h), timeout=5)
            self.assertEqual(cm.exception.code, 401)
            self.assertEqual(seen[-1][1], "expired")

            # tampered: signature made for another authority
            h = wba.sign_request(priv, kid, "GET", "http://other.example/collect", agent)
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(urllib.request.Request(target, headers=h), timeout=5)
            self.assertEqual(cm.exception.code, 401)
            self.assertTrue(seen[-1][1].startswith("signature invalid"))

            # key not in the directory: signer whose key is not published
            stranger = wba.generate_private_key()
            skid = wba.thumbprint(wba.public_jwk(stranger.public_key()))
            h = wba.sign_request(stranger, skid, "GET", target, agent)
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(urllib.request.Request(target, headers=h), timeout=5)
            self.assertEqual(seen[-1][1], "unknown keyid")
        finally:
            dsrv.shutdown(); vsrv.shutdown()


if __name__ == "__main__":
    unittest.main(verbosity=2)
