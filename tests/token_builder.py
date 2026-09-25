"""Test-kit: builds REAL RFC3161-shaped CMS SignedData tokens with pure stdlib.

The tokens produced by ``build_timestamp_token`` are structurally genuine
(CMS ContentInfo → SignedData → SignerInfo with signedAttrs, embedded DER
X.509 certificate, RSA PKCS#1 v1.5 signature over the DER-encoded SET OF
signed attributes) — so the verifier's hand-rolled DER/CMS walk is exercised
against real bytes rather than mocks. Keys are 1024-bit RSA because the
builder only needs to be fast, not secure.
"""
from __future__ import annotations

import base64
import hashlib
import math
import os
import random
from datetime import datetime, timedelta, timezone

# Minimal DER encoding helpers (encoder side; the verifier has the decoder).
def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _len(len(content)) + content


def _oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    body = bytearray([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        chunk = bytearray()
        chunk.append(p & 0x7F)
        p >>= 7
        while p:
            chunk.append(0x80 | (p & 0x7F))
            p >>= 7
        body.extend(reversed(chunk))
    return _tlv(0x06, bytes(body))


def _bit_string(content: bytes) -> bytes:
    return _tlv(0x03, b"\x00" + content)


def _sequence(*elements: bytes) -> bytes:
    return _tlv(0x30, b"".join(elements))


def _explicit_zero(inner: bytes) -> bytes:
    # [0] EXPLICIT: an outer TLV with context tag 0xA0 wrapping ``inner``.
    return _tlv(0xA0, inner)


def _implicit_attrs(raw_attrs: bytes) -> bytes:
    # signedAttrs [0] IMPLICIT SET OF — take the SET OF encoding and swap tag byte.
    return bytes([0xA0]) + raw_attrs[1:]


# RSA keygen / PKCS#1 v1.5 signing (stdlib big-int arithmetic, test-grade).
def _is_probable_prime(n: int, rounds: int = 24) -> bool:
    if n < 2:
        return False
    small = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for p in small:
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits: int, rng: random.Random) -> int:
    while True:
        cand = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(cand):
            return cand


def generate_rsa_key(bits: int = 1024, seed: int | None = None) -> dict:
    """Generate a small test RSA key: {'n', 'e', 'd', 'p', 'q'}."""
    rng = random.Random(seed if seed is not None else os.urandom(16))
    e = 65537
    while True:
        p = _gen_prime(bits // 2, rng)
        q = _gen_prime(bits // 2, rng)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) != 1:
            continue
        d = pow(e, -1, phi)
        return {"n": n, "e": e, "d": d, "p": p, "q": q}


def _int_bytes(n: int) -> bytes:
    raw = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return raw


def rsa_sign_pkcs1v15(key: dict, message_hash: bytes, hash_name: str) -> bytes:
    """RSASSA-PKCS1-v1_5 signature over an already-computed hash."""
    k = (key["n"].bit_length() + 7) // 8
    prefixes = {
        "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
        "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
        "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
    }
    prefix = prefixes[hash_name]
    em = (
        b"\x00\x01"
        + b"\xff" * (k - 3 - len(prefix) - len(message_hash))
        + b"\x00"
        + prefix
        + message_hash
    )
    m = int.from_bytes(em, "big")
    return pow(m, key["d"], key["n"]).to_bytes(k, "big")


# DigestInfo prefixes shared with the verifier's expected-EM comparison.
_DIGEST_INFO_PREFIX = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}

_TST_INFO_OID = "1.2.840.113549.1.9.16.1.4"  # id-ct-TSTInfo
_OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
_OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
_OID_CONTENT_TYPE_ATTR = "1.2.840.113549.1.9.3"  # id-contentType signed attribute


def _utc_time(dt: datetime) -> bytes:
    return _tlv(0x17, dt.strftime("%y%m%d%H%M%SZ").encode("ascii"))


def make_self_signed_cert(key: dict, common_name: str = "Test TSA") -> bytes:
    """Build a minimal DER X.509 self-signed certificate for the RSA key.

    Only the fields the verifier walks are populated: serial, issuer/subject
    DN (CN), validity (UTCTime pair), SPKI (RSA), and a sha256WithRSA
    self-signature over the TBSCertificate. Extensions (SKI) are omitted —
    issuer-and-serial SignerIdentifier matching is the default path.
    """
    name = _sequence(_tlv(0x31, _sequence(_oid("2.5.4.3"), _tlv(0x0C, common_name.encode("ascii")))))
    now = datetime.now(timezone.utc)
    validity = _sequence(_utc_time(now - timedelta(days=1)), _utc_time(now + timedelta(days=365)))
    spki = _sequence(
        _sequence(_oid("1.2.840.113549.1.1.1"), _tlv(0x05, b"")),
        _bit_string(_sequence(_tlv(0x02, _int_bytes(key["n"])), _tlv(0x02, _int_bytes(key["e"])))),
    )
    tbs = _sequence(
        _tlv(0x02, _int_bytes(0x1234)),
        _sequence(_oid("1.2.840.113549.1.1.11"), _tlv(0x05, b"")),
        name,
        validity,
        name,
        spki,
    )
    sig = rsa_sign_pkcs1v15(key, hashlib.sha256(tbs).digest(), "sha256")
    return _sequence(tbs, _sequence(_oid("1.2.840.113549.1.1.11"), _tlv(0x05, b"")), _bit_string(sig))


def build_timestamp_token(
    root_hash_hex: str,
    key: dict,
    cert_der: bytes,
    *,
    hash_name: str = "sha256",
    tamper_signature: bool = False,
    wrong_root: bool = False,
) -> str:
    """Build a base64 RFC3161 TimeStampToken (CMS SignedData) attesting
    ``root_hash_hex`` (or a wrong hash, or a tampered signature, for negative tests)."""
    digest_fn = getattr(hashlib, hash_name)
    imprint_hex = ("cc" * 32) if wrong_root else root_hash_hex
    # messageImprint hash OID per hash_name
    digest_oids = {
        "sha256": "2.16.840.1.101.3.4.2.1",
        "sha384": "2.16.840.1.101.3.4.2.2",
        "sha512": "2.16.840.1.101.3.4.2.3",
    }
    message_imprint = _sequence(
        _sequence(_oid(digest_oids[hash_name]), _tlv(0x05, b"")),
        _tlv(0x04, bytes.fromhex(imprint_hex)),
    )
    tst_info = _sequence(
        _tlv(0x02, b"\x01"),               # version v1
        _oid("1.2.3.4.5"),                 # policy
        message_imprint,
        _tlv(0x02, _int_bytes(1)),         # serialNumber
        _utc_time(datetime.now(timezone.utc)),  # genTime
    )
    tst_der = tst_info  # already a DER sequence
    msg_digest = digest_fn(tst_der).digest()

    content_type_attr = _sequence(
        _oid(_OID_CONTENT_TYPE_ATTR),
        _tlv(0x31, _oid(_TST_INFO_OID)),
    )
    message_digest_attr = _sequence(
        _oid(_OID_MESSAGE_DIGEST),
        _tlv(0x31, _tlv(0x04, msg_digest)),
    )
    signed_attrs = _tlv(0x31, content_type_attr + message_digest_attr)
    tbs = signed_attrs  # SET OF DER encoding is exactly what is signed
    signature = rsa_sign_pkcs1v15(key, digest_fn(tbs).digest(), hash_name)
    if tamper_signature:
        signature = bytes([signature[0] ^ 0xFF]) + signature[1:]

    # IssuerAndSerialNumber from the embedded cert
    cert_tlv, _ = _read_tlv_for_tests(cert_der)
    cert_kids = _read_children_for_tests(cert_tlv)
    tbs_cert = cert_kids[0]
    tbs_kids = _read_children_for_tests(tbs_cert)
    serial = tbs_kids[tbs_kids[0].tag == 0xA0 and 1 or 0]
    issuer = tbs_kids[(tbs_kids[0].tag == 0xA0 and 1 or 0) + 2]

    sid = _sequence(issuer.raw, _tlv(0x02, serial.content))
    sig_algos = {
        "sha256": "1.2.840.113549.1.1.11",
        "sha384": "1.2.840.113549.1.1.12",
        "sha512": "1.2.840.113549.1.1.13",
    }
    signer_info = _sequence(
        _tlv(0x02, b"\x01"),               # version
        sid,
        _sequence(_oid(digest_oids[hash_name]), _tlv(0x05, b"")),
        _implicit_attrs(signed_attrs),
        _sequence(_oid(sig_algos[hash_name]), _tlv(0x05, b"")),
        _tlv(0x04, signature),
    )
    encap = _sequence(_oid(_TST_INFO_OID), _explicit_zero(_tlv(0x04, tst_der)))
    signed_data = _sequence(
        _tlv(0x02, b"\x03"),               # version v3
        _tlv(0x31, _sequence(_oid(digest_oids[hash_name]), _tlv(0x05, b""))),  # digestAlgorithms
        encap,
        _explicit_zero(cert_der),          # certificates [0]
        _tlv(0x31, signer_info),           # signerInfos SET
    )
    content_info = _sequence(_oid(_OID_SIGNED_DATA), _explicit_zero(signed_data))
    return base64.b64encode(content_info).decode("ascii")


# Small reader shims so the builder can parse the cert it just built (the
# verifier package owns the real decoder; tests import these to locate the
# issuer/serial fields without re-implementing a parser).
def _read_tlv_for_tests(data: bytes, offset: int = 0):
    from evidence_verify.verify import _read_tlv
    return _read_tlv(data, offset)


def _read_children_for_tests(tlv):
    from evidence_verify.verify import _read_children
    return _read_children(tlv)
