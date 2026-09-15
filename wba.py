"""
Web Bot Auth for the Bot Barometer collector.

Implements the pieces Cloudflare's Web Bot Auth reference requires
(developers.cloudflare.com/bots/reference/bot-verification/web-bot-auth/, read 2026-09-13):

  * Ed25519 key handling and the RFC 7638 JWK thumbprint used as keyid.
  * RFC 9421 HTTP Message Signatures over derived components and headers,
    with the web-bot-auth tag on requests.
  * Signed key-directory responses (tag http-message-signatures-directory,
    component "@authority";req) for /.well-known/http-message-signatures-directory.
  * Verification of both, used by the local controlled endpoint in test_wba.py.

Only the public key ever leaves this machine. The private key lives outside
any repository (see PRIVATE_KEY_ENV); nothing here prints or logs it.
"""

import base64
import hashlib
import json
import os
import re
import time
import urllib.parse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

PRIVATE_KEY_ENV = "MARKETFAUNA_WBA_PRIVATE_KEY_PEM"   # PEM text, or a path to a PEM file
DIRECTORY_PATH = "/.well-known/http-message-signatures-directory"
DIRECTORY_MEDIA_TYPE = "application/http-message-signatures-directory+json"
REQUEST_TAG = "web-bot-auth"
DIRECTORY_TAG = "http-message-signatures-directory"


# --------------------------------------------------------------------------- keys

def generate_private_key():
    return Ed25519PrivateKey.generate()


def private_key_to_pem(priv):
    return priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def load_private_key(pem_or_path=None):
    """PEM text or a path; falls back to PRIVATE_KEY_ENV. Returns None if absent."""
    src = pem_or_path or os.environ.get(PRIVATE_KEY_ENV)
    if not src:
        return None
    if "BEGIN" not in src and os.path.exists(src):
        with open(src, "rb") as f:
            data = f.read()
    else:
        data = src.encode()
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("not an Ed25519 private key")
    return key


def public_jwk(pub):
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw)}


def thumbprint(jwk):
    """RFC 7638 thumbprint; for OKP the members are crv, kty, x in lexicographic order."""
    canonical = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]},
        separators=(",", ":"), sort_keys=True,
    ).encode()
    return _b64url(hashlib.sha256(canonical).digest())


def public_key_from_jwk(jwk):
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or "x" not in jwk:
        raise ValueError("unsupported JWK")
    return Ed25519PublicKey.from_public_bytes(_b64url_decode(jwk["x"]))


def _b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64url_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# --------------------------------------------------------------------------- RFC 9421 base

def signature_base(components, params_serialized):
    """
    components: list of (serialized identifier, value), e.g. ('"@authority"', 'example.com')
    params_serialized: the exact Signature-Input member value, e.g.
        ("@authority" "signature-agent");alg="ed25519";keyid="...";created=1;expires=2
    """
    lines = ["{}: {}".format(ident, value) for ident, value in components]
    lines.append('"@signature-params": {}'.format(params_serialized))
    return "\n".join(lines).encode("ascii")


def serialize_params(identifiers, params):
    inner = "(" + " ".join(identifiers) + ")"
    parts = []
    for k, v in params:
        if isinstance(v, int):
            parts.append("{}={}".format(k, v))
        else:
            parts.append('{}="{}"'.format(k, v))
    return inner + "".join(";" + p for p in parts)


_MEMBER_RE = re.compile(r'^\s*([A-Za-z0-9_-]+)=(.*)$', re.S)
_INNER_RE = re.compile(r'^\((.*?)\)(.*)$', re.S)
_IDENT_RE = re.compile(r'"([^"]+)"((?:;[a-z]+(?:=(?:"[^"]*"|[^;\s)]+))?)*)')
_PARAM_RE = re.compile(r';([a-z]+)(?:=("(?:[^"\\]|\\.)*"|[^;]+))?')


def parse_signature_input(value):
    """Return (label, params_serialized, [serialized identifiers], {param: value})."""
    m = _MEMBER_RE.match(value)
    if not m:
        raise ValueError("bad Signature-Input")
    label, rest = m.group(1), m.group(2).strip()
    m2 = _INNER_RE.match(rest)
    if not m2:
        raise ValueError("bad Signature-Input inner list")
    idents = ['"{}"{}'.format(name, p) for name, p in _IDENT_RE.findall(m2.group(1))]
    params = {}
    for k, v in _PARAM_RE.findall(m2.group(2)):
        if v == "":
            params[k] = True
        elif v.startswith('"'):
            params[k] = v[1:-1]
        else:
            params[k] = int(v) if v.isdigit() else v
    return label, rest, idents, params


def parse_signature(value, label):
    m = re.search(r'(?:^|,)\s*' + re.escape(label) + r'=:([A-Za-z0-9+/=]+):', value)
    if not m:
        raise ValueError("no signature for label " + label)
    return base64.b64decode(m.group(1))


def component_value(ident, method, url, headers, req_url=None):
    """Value of one serialized component identifier for the message described."""
    name = ident.split('"')[1]
    is_req = ";req" in ident
    target = req_url if is_req and req_url else url
    parts = urllib.parse.urlsplit(target)
    if name == "@authority":
        return parts.netloc.lower()
    if name == "@method":
        return method.upper()
    if name == "@path":
        return parts.path or "/"
    if name == "@scheme":
        return parts.scheme.lower()
    if name == "@target-uri":
        return target
    if name == "@query":
        return "?" + parts.query
    if name.startswith("@"):
        raise ValueError("unsupported derived component " + name)
    lookup = {k.lower(): v for k, v in headers.items()}
    if name not in lookup:
        raise ValueError("missing header " + name)
    return " ".join(lookup[name].split())


# --------------------------------------------------------------------------- requests

def sign_request(priv, kid, method, url, agent_url, expires_in=60, now=None, label="sig1"):
    """Headers to attach to an outgoing request: Signature-Input, Signature, Signature-Agent."""
    now = int(now if now is not None else time.time())
    agent_header = '"{}"'.format(agent_url)
    headers = {"Signature-Agent": agent_header}
    idents = ['"@authority"', '"signature-agent"']
    params = [("alg", "ed25519"), ("keyid", kid),
              ("nonce", base64.b64encode(os.urandom(48)).decode()),
              ("tag", REQUEST_TAG), ("created", now), ("expires", now + expires_in)]
    ser = serialize_params(idents, params)
    comps = [(i, component_value(i, method, url, headers)) for i in idents]
    sig = priv.sign(signature_base(comps, ser))
    headers["Signature-Input"] = "{}={}".format(label, ser)
    headers["Signature"] = "{}=:{}:".format(label, base64.b64encode(sig).decode())
    return headers


def verify_request(method, url, headers, keys_by_kid, now=None, expected_tag=REQUEST_TAG):
    """Return (ok, reason, kid). keys_by_kid: {thumbprint: Ed25519PublicKey}."""
    now = int(now if now is not None else time.time())
    lookup = {k.lower(): v for k, v in headers.items()}
    try:
        label, ser, idents, params = parse_signature_input(lookup["signature-input"])
        sig = parse_signature(lookup["signature"], label)
    except (KeyError, ValueError) as e:
        return False, "malformed: {}".format(e), None
    if params.get("tag") != expected_tag:
        return False, "wrong tag", params.get("keyid")
    if params.get("alg", "ed25519") != "ed25519":
        return False, "unsupported alg", params.get("keyid")
    if '"@authority"' not in idents:
        return False, "@authority not covered", params.get("keyid")
    if '"signature-agent"' not in idents:
        return False, "signature-agent not covered", params.get("keyid")
    if "created" not in params or "expires" not in params:
        return False, "created/expires missing", params.get("keyid")
    if now < params["created"] - 60:
        return False, "created in the future", params.get("keyid")
    if now > params["expires"]:
        return False, "expired", params.get("keyid")
    kid = params.get("keyid")
    pub = keys_by_kid.get(kid)
    if pub is None:
        return False, "unknown keyid", kid
    try:
        comps = [(i, component_value(i, method, url, headers)) for i in idents]
        pub.verify(sig, signature_base(comps, ser))
    except Exception as e:
        return False, "signature invalid: {}".format(type(e).__name__), kid
    return True, "ok", kid


# --------------------------------------------------------------------------- directory

def directory_body(jwks):
    return json.dumps({"keys": jwks}, separators=(",", ":")).encode()


def sign_directory_response(priv, kid, request_authority, expires_in=300, now=None, label="sig1"):
    """Response headers for the key directory, one signature for this key."""
    now = int(now if now is not None else time.time())
    idents = ['"@authority";req']
    params = [("alg", "ed25519"), ("keyid", kid),
              ("nonce", base64.b64encode(os.urandom(48)).decode()),
              ("tag", DIRECTORY_TAG), ("created", now), ("expires", now + expires_in)]
    ser = serialize_params(idents, params)
    comps = [('"@authority";req', request_authority.lower())]
    sig = priv.sign(signature_base(comps, ser))
    return {
        "Content-Type": DIRECTORY_MEDIA_TYPE,
        "Signature-Input": "{}={}".format(label, ser),
        "Signature": "{}=:{}:".format(label, base64.b64encode(sig).decode()),
        # A cached response must not outlive its short-lived signature.
        "Cache-Control": "no-store",
    }


def verify_directory_response(request_authority, headers, body, now=None):
    """
    Return (valid_keys_by_kid, reasons). A key counts only if the response carries a
    valid signature made with it (draft-meunier-http-message-signatures-directory-03 s.5.2).
    """
    now = int(now if now is not None else time.time())
    lookup = {k.lower(): v for k, v in headers.items()}
    reasons = []
    if not lookup.get("content-type", "").split(";")[0].strip() == DIRECTORY_MEDIA_TYPE:
        reasons.append("wrong content-type")
        return {}, reasons
    try:
        doc = json.loads(body)
        jwks = doc["keys"]
    except Exception as e:
        return {}, ["malformed body: {}".format(e)]
    keys = {}
    for jwk in jwks:
        try:
            keys[thumbprint(jwk)] = public_key_from_jwk(jwk)
        except Exception:
            reasons.append("skipped non-Ed25519 key")
    valid = {}
    # one member per signature; split Signature-Input on top-level commas
    for member in re.split(r',(?=\s*[A-Za-z0-9_-]+=\()', lookup.get("signature-input", "")):
        if not member.strip():
            continue
        try:
            label, ser, idents, params = parse_signature_input(member)
            sig = parse_signature(lookup.get("signature", ""), label)
        except ValueError as e:
            reasons.append("malformed member: {}".format(e))
            continue
        if params.get("tag") != DIRECTORY_TAG:
            reasons.append("{}: wrong tag".format(label)); continue
        if idents != ['"@authority";req']:
            reasons.append("{}: unexpected components {}".format(label, idents)); continue
        if now > params.get("expires", 0) or now < params.get("created", 0) - 60:
            reasons.append("{}: outside created/expires".format(label)); continue
        pub = keys.get(params.get("keyid"))
        if pub is None:
            reasons.append("{}: keyid not in directory".format(label)); continue
        try:
            pub.verify(sig, signature_base([('"@authority";req', request_authority.lower())], ser))
        except Exception:
            reasons.append("{}: signature invalid".format(label)); continue
        valid[params["keyid"]] = pub
    return valid, reasons


# --------------------------------------------------------------------------- CLI

def _main(argv):
    import argparse
    ap = argparse.ArgumentParser(description="Web Bot Auth helper (keys stay local).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("keygen", help="write a new private key PEM to PATH and print the public JWK")
    g.add_argument("path")
    p = sub.add_parser("pub", help="print public JWK and thumbprint for the key in PATH or env")
    p.add_argument("path", nargs="?")
    a = ap.parse_args(argv)
    if a.cmd == "keygen":
        if os.path.exists(a.path):
            raise SystemExit("refusing to overwrite " + a.path)
        priv = generate_private_key()
        os.makedirs(os.path.dirname(os.path.abspath(a.path)), exist_ok=True)
        with open(a.path, "w", newline="\n") as f:
            f.write(private_key_to_pem(priv))
        jwk = public_jwk(priv.public_key())
        print(json.dumps({"jwk": jwk, "kid": thumbprint(jwk)}, indent=1))
    elif a.cmd == "pub":
        priv = load_private_key(a.path)
        if priv is None:
            raise SystemExit("no key")
        jwk = public_jwk(priv.public_key())
        print(json.dumps({"jwk": jwk, "kid": thumbprint(jwk)}, indent=1))


if __name__ == "__main__":
    import sys
    _main(sys.argv[1:])
