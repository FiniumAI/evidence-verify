"""Offline verifier for tamper-evident evidence packs (format v0.2 / case-v0.2).

Re-hashes every file listed in the pack's hash manifest (``hash_manifest.json``
for a per-bundle pack, ``case_hash_manifest.json`` for a per-case pack,
``referral_manifest.json`` for a referral pack — the algorithm is identical for
all three), recomputes the aggregate root hash, and checks that no required
file is missing and no unlisted file was slipped in. Exits 0 on a valid pack,
non-zero on any tamper/missing/extra file.

Integrity is the pass/fail axis. Completeness (``pack_complete`` + reason), the
timestamp axis (``timestamp_status``/``timestamp_state``/``timestamp_checks``),
and the evidence-ladder stage (``evidence_stage``, from metadata.json) are all
*surfaced, not enforced*: a verified-but-incomplete or verified-but-not-
token-signature-verified pack still exits 0 with a WARN — the only timestamp
conditions that fail integrity are a definite root-hash mismatch or a granted
token whose bytes are simply missing.

Self-contained and standard-library only: the RFC3161/CMS parsing and the RSA
PKCS#1 v1.5 signature checks below are hand-rolled DER walking, with no
third-party dependencies, so a recipient can run it fully offline.

Usage:
    python -m evidence_verify /path/to/pack.zip
    python -m evidence_verify /path/to/pack.zip --json
    python -m evidence_verify /path/to/unpacked/pack-dir
    python -m evidence_verify /path/to/pack.zip --tsa-ca anchor.pem
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import zipfile
from pathlib import Path

# --------------------------------------------------------------------------- #
# Hand-rolled DER reader (read-only; what CMS/X.509 walking this verifier needs)
# --------------------------------------------------------------------------- #
class _DerError(ValueError):
    """Raised when DER bytes do not match the structure this parser expects."""


class _Tlv:
    """One parsed DER tag-length-value element (raw keeps the exact encoding)."""

    __slots__ = ("tag", "content", "raw")

    def __init__(self, tag: int, content: bytes, raw: bytes):
        self.tag = tag
        self.content = content
        self.raw = raw


def _read_tlv(data: bytes, offset: int) -> tuple[_Tlv, int]:
    """Parse one TLV at ``offset``; return (element, next_offset)."""
    start = offset
    if offset >= len(data):
        raise _DerError("truncated: no tag byte")
    tag = data[offset]
    offset += 1
    if tag & 0x1F == 0x1F:
        raise _DerError("multi-byte tags unsupported")
    if offset >= len(data):
        raise _DerError("truncated: no length byte")
    first = data[offset]
    offset += 1
    if first < 0x80:
        length = first
    elif first == 0x80:
        raise _DerError("indefinite lengths unsupported")
    else:
        n = first & 0x7F
        if n > 4:
            raise _DerError("length too large")
        if offset + n > len(data):
            raise _DerError("truncated length")
        length = int.from_bytes(data[offset:offset + n], "big")
        offset += n
    if offset + length > len(data):
        raise _DerError("truncated content")
    content = data[offset:offset + length]
    end = offset + length
    return _Tlv(tag, content, data[start:end]), end


def _read_children(tlv: _Tlv) -> list[_Tlv]:
    """Parse the content of a constructed element into its child elements."""
    out: list[_Tlv] = []
    off = 0
    while off < len(tlv.content):
        child, off = _read_tlv(tlv.content, off)
        out.append(child)
    return out


def _decode_oid(tlv: _Tlv) -> str:
    """Decode a primitive OID element into dotted-decimal string form."""
    if tlv.tag != 0x06 or not tlv.content:
        raise _DerError("not an OID element")
    first = tlv.content[0]
    parts = [first // 40, first % 40]
    val = 0
    pending = False
    for byte in tlv.content[1:]:
        val = (val << 7) | (byte & 0x7F)
        pending = bool(byte & 0x80)
        if not pending:
            parts.append(val)
            val = 0
    if pending:
        raise _DerError("truncated OID sub-identifier")
    return ".".join(str(p) for p in parts)


# --------------------------------------------------------------------------- #
# Algorithm OIDs (digest + RSA signature algorithms this verifier can check;
# anything else degrades the signature check to "unavailable" — it is never
# reported as "failed" purely because we don't support the algorithm).
# --------------------------------------------------------------------------- #
# Hex-digest hashlib callables (spec: sha256/384/512 only).
_DIGEST_HASHLIB = {
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
}

# Digest algorithm OID -> hashlib name.
_DIGEST_OID_MAP = {
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
}

# Signature algorithm OID (RSA PKCS#1 v1.5) -> hash name.
_SIG_ALGO_MAP = {
    "1.2.840.113549.1.1.11": "sha256",  # sha256WithRSAEncryption
    "1.2.840.113549.1.1.12": "sha384",  # sha384WithRSAEncryption
    "1.2.840.113549.1.1.13": "sha512",  # sha512WithRSAEncryption
}

# DER DigestInfo prefixes (SEQUENCE{AlgorithmIdentifier, OCTET STRING} header
# without the digest bytes) for the supported hashes.
_DIGEST_INFO_PREFIX = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}

_OCTET_STR = 0x04
_SEQUENCE = 0x30
_SET_OF = 0x31
_OID = 0x06
_INTEGER = 0x02
_BIT_STR = 0x03

# OIDs used by the CMS walk.
_OID_SIGNED_DATA = "1.2.840.113549.1.7.2"        # id-signedData (CMS ContentInfo)
_OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"     # rsaEncryption (SubjectPublicKeyInfo)
_OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"     # id-messageDigest signed attribute
_OID_SUBJECT_KEY_ID = "2.5.29.14"                # subjectKeyIdentifier extension


def _rsa_pkcs1v15_verify(
    n: int, e: int, signature: bytes, message_hash: bytes, hash_name: str,
) -> bool:
    """RSASSA-PKCS1-v1_5 signature verification with big-int modexp.

    Strict expected-EM comparison (RFC 8017 §8.2.2): the encoded message must
    be exactly ``00 01 FF..FF 00 DigestInfo(prefix+digest)``. Returns False on
    any length or padding mismatch.
    """
    k = (n.bit_length() + 7) // 8
    prefix = _DIGEST_INFO_PREFIX[hash_name]
    if k < 3 + 8 + len(prefix) + len(message_hash):
        return False  # modulus too small for this hash
    if len(signature) != k:
        return False
    s = int.from_bytes(signature, "big")
    if s >= n:
        return False
    em = pow(s, e, n).to_bytes(k, "big")
    expected = (
        b"\x00\x01"
        + b"\xff" * (k - 3 - len(prefix) - len(message_hash))
        + b"\x00"
        + prefix
        + message_hash
    )
    return em == expected


class _Certificate:
    """Minimal parsed X.509 certificate (RSA keys only), for token checks.

    ``key`` is ``(n, e)`` for RSA public keys, or ``None`` when the SPKI is
    not RSA (ECDSA/Ed25519/... → the signature check degrades to
    "unavailable", never "failed", for lack of support). Raw DER of the issuer
    and subject DNs is kept for the single-hop anchor comparison.
    """

    def __init__(self, der: bytes):
        self.der = der
        top, _ = _read_tlv(der, 0)
        if top.tag != _SEQUENCE:
            raise _DerError("Certificate must be a SEQUENCE")
        kids = _read_children(top)
        if len(kids) != 3:
            raise _DerError("Certificate must have exactly 3 elements")
        tbs, sig_alg, sig_val = kids
        if tbs.tag != _SEQUENCE:
            raise _DerError("tbsCertificate must be a SEQUENCE")
        # signatureAlgorithm: SEQUENCE { OID, params }
        self.sig_hash_name = None
        sa_kids = _read_children(sig_alg)
        if sa_kids and sa_kids[0].tag == _OID:
            self.sig_hash_name = _SIG_ALGO_MAP.get(_decode_oid(sa_kids[0]))
        # signatureValue: BIT STRING (unused bits must be 0)
        if sig_val.tag != _BIT_STR or not sig_val.content or sig_val.content[0] != 0:
            raise _DerError("signatureValue must be a BIT STRING with 0 unused bits")
        self.signature = sig_val.content[1:]
        self.tbs_raw = tbs.raw

        tkids = _read_children(tbs)
        i = 0
        if tkids and tkids[0].tag == 0xA0:  # optional [0] version
            i = 1
        if len(tkids) < i + 6:
            raise _DerError("tbsCertificate too short")
        # order: serialNumber, signature, issuer, validity, subject, spki, ...
        if tkids[i].tag != _INTEGER:
            raise _DerError("serialNumber must be an INTEGER")
        self.serial = int.from_bytes(tkids[i].content, "big")
        self.issuer_raw = tkids[i + 2].raw
        self.subject_raw = tkids[i + 4].raw
        spki = tkids[i + 5]

        # subjectKeyIdentifier extension ([3] EXPLICIT SEQUENCE OF Extension), if present.
        self.key_identifier = None
        for container in tkids[i + 6:]:
            if container.tag != 0xA3:
                continue
            ext_seq, _ = _read_tlv(container.content, 0)
            for ext in _read_children(ext_seq):
                if ext.tag != _SEQUENCE:
                    continue
                ekids = _read_children(ext)
                if len(ekids) < 3 or ekids[0].tag != _OID:
                    continue
                if _decode_oid(ekids[0]) != _OID_SUBJECT_KEY_ID:
                    continue
                # extnValue OCTET STRING wrapping a bare OCTET STRING (the key id)
                if ekids[2].tag == _OCTET_STR:
                    inner, _ = _read_tlv(ekids[2].content, 0)
                    if inner.tag == _OCTET_STR:
                        self.key_identifier = inner.content

        # SubjectPublicKeyInfo -> RSA (n, e)
        self.key = None
        pk_kids = _read_children(spki)
        if len(pk_kids) == 2 and pk_kids[0].tag == _SEQUENCE:
            alg_kids = _read_children(pk_kids[0])
            if alg_kids and alg_kids[0].tag == _OID and _decode_oid(alg_kids[0]) == _OID_RSA_ENCRYPTION:
                if pk_kids[1].tag == _BIT_STR and pk_kids[1].content and pk_kids[1].content[0] == 0:
                    pub, _ = _read_tlv(pk_kids[1].content[1:], 0)
                    if pub.tag != _SEQUENCE:
                        raise _DerError("RSAPublicKey must be a SEQUENCE")
                    rk = _read_children(pub)
                    if len(rk) != 2 or rk[0].tag != _INTEGER or rk[1].tag != _INTEGER:
                        raise _DerError("RSAPublicKey must hold (modulus, exponent)")
                    self.key = (
                        int.from_bytes(rk[0].content, "big"),
                        int.from_bytes(rk[1].content, "big"),
                    )


def _parse_signer_info(si_tlv: _Tlv) -> dict:
    """Extract the fields the verifier needs from one CMS SignerInfo element."""
    if si_tlv.tag != _SEQUENCE:
        raise _DerError("SignerInfo must be a SEQUENCE")
    kids = _read_children(si_tlv)
    if len(kids) < 5:
        raise _DerError("SignerInfo too short")
    # order: version, sid, digestAlgorithm, [signedAttrs [0]], signatureAlgorithm, signature
    sid = kids[1]

    digest_name = None
    da_kids = _read_children(kids[2])
    if da_kids and da_kids[0].tag == _OID:
        digest_name = _DIGEST_OID_MAP.get(_decode_oid(da_kids[0]))

    # SignerIdentifier: CHOICE issuerAndSerialNumber (SEQUENCE) | subjectKeyIdentifier ([0] primitive)
    sid_parsed = None
    if sid.tag == _SEQUENCE:
        sk = _read_children(sid)
        if len(sk) != 2 or sk[0].tag != _SEQUENCE or sk[1].tag != _INTEGER:
            raise _DerError("bad IssuerAndSerialNumber")
        sid_parsed = {"issuer_raw": sk[0].raw, "serial": int.from_bytes(sk[1].content, "big")}
    elif sid.tag == 0x80:
        sid_parsed = {"ski": sid.content}

    idx = 3
    signed_attrs_tbs = None
    message_digest = None
    if kids[idx].tag == 0xA0:  # signedAttrs [0] IMPLICIT SET OF Attribute
        raw = kids[idx].raw
        # The signature is computed over the SET OF encoding: the implicit [0]
        # context tag byte is replaced by the universal SET OF tag (0x31).
        signed_attrs_tbs = bytes([_SET_OF]) + raw[1:]
        for attr in _read_children(kids[idx]):
            if attr.tag != _SEQUENCE:
                continue
            akids = _read_children(attr)
            if len(akids) < 2 or akids[0].tag != _OID:
                continue
            if _decode_oid(akids[0]) != _OID_MESSAGE_DIGEST:
                continue
            values = _read_children(akids[1])
            if values and values[0].tag == _OCTET_STR:
                message_digest = values[0].content

    if idx >= len(kids) or idx + 1 >= len(kids):
        raise _DerError("SignerInfo missing signature fields")
    sig_alg = kids[idx + (1 if signed_attrs_tbs is not None else 0)]
    sig_octets = kids[idx + (1 if signed_attrs_tbs is not None else 0) + 1]
    # recompute idx cleanly (the expression above only works when attrs absent/present matches)
    idx = idx + (1 if signed_attrs_tbs is not None else 0)
    sig_alg = kids[idx]
    sig_octets = kids[idx + 1]
    if sig_alg.tag != _SEQUENCE or sig_octets.tag != _OCTET_STR:
        raise _DerError("bad signatureAlgorithm/signature elements")

    sig_algo_hash = None
    sa_kids = _read_children(sig_alg)
    if sa_kids and sa_kids[0].tag == _OID:
        sig_algo_hash = _SIG_ALGO_MAP.get(_decode_oid(sa_kids[0]))

    return {
        "sid": sid_parsed,
        "digest_name": digest_name,
        "signed_attrs_tbs": signed_attrs_tbs,
        "message_digest": message_digest,
        "sig_algo_hash": sig_algo_hash,
        "signature": sig_octets.content,
    }


def _parse_timestamp_token(token_der: bytes) -> dict:
    """Parse an RFC3161 TimeStampToken (CMS ContentInfo -> SignedData).

    Returns a dict with the eContent bytes, the message-imprint digest hex, the
    parsed SignerInfo dicts, and the embedded certificate elements. Raises
    ``_DerError`` on anything that does not match the expected shape.
    """
    ci, end = _read_tlv(token_der, 0)
    if end != len(token_der):
        raise _DerError("trailing bytes after ContentInfo")
    if ci.tag != _SEQUENCE:
        raise _DerError("ContentInfo must be a SEQUENCE")
    ci_kids = _read_children(ci)
    if len(ci_kids) != 2 or ci_kids[0].tag != _OID:
        raise _DerError("bad ContentInfo")
    if _decode_oid(ci_kids[0]) != _OID_SIGNED_DATA:
        raise _DerError("contentType is not signedData")
    if ci_kids[1].tag != 0xA0:
        raise _DerError("[0] EXPLICIT content expected")
    sd, _ = _read_tlv(ci_kids[1].content, 0)
    if sd.tag != _SEQUENCE:
        raise _DerError("SignedData must be a SEQUENCE")
    sd_kids = _read_children(sd)
    if len(sd_kids) < 4:
        raise _DerError("SignedData too short")
    # order: version, digestAlgorithms, encapContentInfo, [certificates [0]],
    # [crls [1]], signerInfos
    idx = 3
    cert_tlvs = []
    if idx < len(sd_kids) and sd_kids[idx].tag == 0xA0:
        cert_tlvs = [c for c in _read_children(sd_kids[idx]) if c.tag == _SEQUENCE]
        idx += 1
    if idx < len(sd_kids) and sd_kids[idx].tag == 0xA1:
        idx += 1  # crls — not used
    if idx >= len(sd_kids) or sd_kids[idx].tag != _SET_OF:
        raise _DerError("signerInfos must be a SET")
    signer_infos = [_parse_signer_info(si) for si in _read_children(sd_kids[idx])]

    # encapContentInfo: SEQUENCE { eContentType OID, eContent [0] EXPLICIT OCTET STRING }
    eci = sd_kids[2]
    if eci.tag != _SEQUENCE:
        raise _DerError("encapContentInfo must be a SEQUENCE")
    eci_kids = _read_children(eci)
    if not eci_kids or eci_kids[0].tag != _OID:
        raise _DerError("bad encapContentInfo")
    econtent = None
    if len(eci_kids) >= 2 and eci_kids[1].tag == 0xA0:
        octets, _ = _read_tlv(eci_kids[1].content, 0)
        if octets.tag != _OCTET_STR:
            raise _DerError("eContent must be an OCTET STRING")
        econtent = octets.content

    # TSTInfo (inside eContent): SEQUENCE { version, policy, messageImprint, ... }
    # messageImprint: SEQUENCE { hashAlgorithm AlgId, hashedMessage OCTET STRING }
    imprint_hex = None
    if econtent is not None:
        tst, _ = _read_tlv(econtent, 0)
        if tst.tag != _SEQUENCE:
            raise _DerError("TSTInfo must be a SEQUENCE")
        tst_kids = _read_children(tst)
        if len(tst_kids) < 3:
            raise _DerError("TSTInfo too short")
        mi = tst_kids[2]
        if mi.tag != _SEQUENCE:
            raise _DerError("messageImprint must be a SEQUENCE")
        mi_kids = _read_children(mi)
        if len(mi_kids) < 2 or mi_kids[0].tag != _SEQUENCE or mi_kids[1].tag != _OCTET_STR:
            raise _DerError("bad messageImprint")
        imprint_hex = mi_kids[1].content.hex()

    return {
        "econtent": econtent,
        "imprint_hex": imprint_hex,
        "signer_infos": signer_infos,
        "certificates": cert_tlvs,
    }


def _find_signer_cert(cert_tlvs: list, sid: dict | None):
    """Locate the embedded certificate element matching the SignerInfo ``sid``."""
    if sid is None:
        return None
    for tlv in cert_tlvs:
        try:
            cert = _Certificate(tlv.raw)
        except _DerError:
            continue
        if "issuer_raw" in sid:
            if cert.issuer_raw == sid["issuer_raw"] and cert.serial == sid["serial"]:
                return cert
        elif "ski" in sid:
            if cert.key_identifier is not None and cert.key_identifier == sid["ski"]:
                return cert
    return None


# --------------------------------------------------------------------------- #
# Timestamp axis (RFC3161 token imprint / signature / chain checks)
# --------------------------------------------------------------------------- #
def _stamped_digest(token_b64: str) -> str | None:
    """Hex message-imprint digest inside an RFC3161 token, or None if unparseable."""
    try:
        token_der = base64.b64decode(token_b64, validate=True)
        return _parse_timestamp_token(token_der)["imprint_hex"]
    except Exception:
        return None


# Master switch for the token signature/chain checks. There are no optional
# third-party dependencies in this port (everything is stdlib), but the flag
# keeps the degradation path testable: when off, signature checks report
# "unavailable" without affecting the integrity pass/fail axis.
_SIGNATURE_CHECKS_ENABLED = True


def _verify_token_signature(token_b64: str, tsa_ca_certs: list | None) -> tuple[str, str]:
    """Best-effort CMS SignerInfo verification of an RFC3161 TimeStampToken.

    Checks (1) the CMS ``messageDigest`` signed attribute equals the hash of
    the TSTInfo eContent bytes, and (2) the signature over the DER-encoded
    signed attributes verifies against the signer certificate embedded in the
    token (RSA PKCS#1 v1.5, SHA-256/384/512 only; other key or algorithm
    choices degrade to "unavailable").

    This is NOT full RFC 5280 certificate path/policy validation: no CRL/OCSP
    checking, no policy constraints, and (with --tsa-ca) only a single-hop
    "does the signer cert chain directly to this one trust anchor" check.

    Returns (signature_state, chain_state); "unavailable" (never "failed") on
    anything this offline check cannot evaluate — checks disabled, more/less
    than one SignerInfo, missing signed attributes, an unsupported signature
    algorithm, or a signer cert that can't be located among the embedded certs.
    """
    if not _SIGNATURE_CHECKS_ENABLED:
        return "unavailable", "not_checked"

    try:
        token_der = base64.b64decode(token_b64, validate=True)
        parsed = _parse_timestamp_token(token_der)
    except Exception:
        return "unavailable", "not_checked"

    signer_infos = parsed["signer_infos"]
    if len(signer_infos) != 1:
        return "unavailable", "not_checked"
    si = signer_infos[0]
    econtent = parsed["econtent"]
    if not econtent:
        return "unavailable", "not_checked"

    digest_name = si["digest_name"]
    digest_fn = _DIGEST_HASHLIB.get(digest_name)
    if digest_fn is None:
        return "unavailable", "not_checked"

    message_digest = si["message_digest"]
    tbs = si["signed_attrs_tbs"]
    if message_digest is None or tbs is None:
        return "unavailable", "not_checked"

    if digest_fn(econtent).digest() != message_digest:
        return "failed", "not_checked"

    signer_cert = _find_signer_cert(parsed["certificates"], si["sid"])
    if signer_cert is None or signer_cert.key is None:
        return "unavailable", "not_checked"

    hash_name = si["sig_algo_hash"]
    if hash_name is None or hash_name not in _DIGEST_HASHLIB:
        return "unavailable", "not_checked"

    n, e = signer_cert.key
    if not _rsa_pkcs1v15_verify(n, e, si["signature"], digest_fn(tbs).digest(), digest_name):
        return "failed", "not_checked"

    if not tsa_ca_certs:
        return "ok", "not_checked"
    return "ok", ("ok" if _chains_to_anchor(signer_cert, tsa_ca_certs) else "failed")


def _chains_to_anchor(signer_cert: _Certificate, anchors: list) -> bool:
    """Single-hop trust check only (see _verify_token_signature docstring):
    the signer cert's issuer DN matches an anchor's subject DN (byte-for-byte
    DER comparison), and that anchor's public key verifies the signer cert's
    own signature. This is NOT full RFC 5280 path/policy validation — no
    CRL/OCSP, no path length or policy constraints, no support for
    intermediate chains beyond this one hop.
    """
    for anchor in anchors:
        if not isinstance(anchor, _Certificate):
            continue
        if signer_cert.issuer_raw != anchor.subject_raw:
            continue
        if anchor.key is None or signer_cert.sig_hash_name is None:
            continue
        n, e = anchor.key
        if not _rsa_pkcs1v15_verify(
            n, e, signer_cert.signature,
            _DIGEST_HASHLIB[signer_cert.sig_hash_name](signer_cert.tbs_raw).digest(),
            signer_cert.sig_hash_name,
        ):
            continue
        return True
    return False


def _load_tsa_ca(path: str | Path) -> list:
    """Load one or more PEM-encoded trust anchor certificates for --tsa-ca."""
    data = Path(path).read_text()
    certs = []
    blocks = data.split("-----BEGIN CERTIFICATE-----")[1:]
    if not blocks:
        raise ValueError(f"no CERTIFICATE blocks found in {path}")
    for block in blocks:
        end = block.find("-----END CERTIFICATE-----")
        if end == -1:
            raise ValueError("unterminated CERTIFICATE block")
        b64 = "".join(block[:end].split())
        certs.append(_Certificate(base64.b64decode(b64)))
    return certs


# --------------------------------------------------------------------------- #
# Pack verification
# --------------------------------------------------------------------------- #
class _PackSource:
    """Uniform read access over a pack ZIP or an unpacked pack directory."""

    def __init__(self, path: Path):
        self.path = path
        self._zf: zipfile.ZipFile | None = None
        self._root: Path | None = None
        if path.is_dir():
            self._root = path
            self.names = sorted(
                p.relative_to(path).as_posix() for p in path.rglob("*") if p.is_file()
            )
        else:
            self._zf = zipfile.ZipFile(path)  # raises BadZipFile on non-ZIP input
            self.names = self._zf.namelist()

    def read(self, name: str) -> bytes:
        if self._root is not None:
            return (self._root / name).read_bytes()
        assert self._zf is not None
        return self._zf.read(name)

    def close(self) -> None:
        if self._zf is not None:
            self._zf.close()

    def __enter__(self) -> "_PackSource":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def verify_pack_bytes(data: bytes, tsa_ca_certs: list | None = None) -> tuple[bool, list[str], dict]:
    """Verify a pack held in memory (e.g. an HTTP upload). Same semantics as verify_pack."""
    import io

    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return False, ["not a valid ZIP file"], {}
    src = _PackSource.__new__(_PackSource)
    src.path = Path("<memory>")
    src._root = None
    src._zf = zf
    src.names = zf.namelist()
    return _verify_source(src, tsa_ca_certs)


def verify_pack(zip_path: str | Path, tsa_ca_certs: list | None = None) -> tuple[bool, list[str], dict]:
    """Return (ok, problems, manifest). ``ok`` is True only if problems is empty.

    ``zip_path`` may be a pack ZIP or an unpacked pack directory (identical
    layout, verified identically). ``tsa_ca_certs``, if given, is a list of
    ``_Certificate`` trust anchors for the (optional, single-hop) timestamp
    signer chain check — see ``--tsa-ca`` / ``_chains_to_anchor``.
    """
    zip_path = Path(zip_path)
    if not zip_path.exists():
        return False, [f"pack not found: {zip_path}"], {}
    try:
        src = _PackSource(zip_path)
    except zipfile.BadZipFile:
        return False, ["not a valid ZIP file"], {}
    return _verify_source(src, tsa_ca_certs)


def _verify_source(src: _PackSource, tsa_ca_certs: list | None = None) -> tuple[bool, list[str], dict]:
    problems: list[str] = []
    with src:
        names = set(src.names)
        # Manifest selection (top level only): a referral pack carries
        # ``referral_manifest.json`` (hash coverage over every other file in
        # the pack, including the nested case pack's own manifests); a per-case
        # pack carries ``case_hash_manifest.json``; a per-bundle pack carries
        # ``hash_manifest.json``. The verification algorithm is identical for
        # all three — only the manifest filename differs.
        if "referral_manifest.json" in names:
            manifest_name = "referral_manifest.json"
        elif "case_hash_manifest.json" in names:
            manifest_name = "case_hash_manifest.json"
        elif "hash_manifest.json" in names:
            manifest_name = "hash_manifest.json"
        else:
            return False, [
                "no referral_manifest.json, case_hash_manifest.json, or "
                "hash_manifest.json — not a v0.2 pack"
            ], {}

        try:
            manifest = json.loads(src.read(manifest_name))
        except json.JSONDecodeError as e:
            return False, [f"{manifest_name} is not valid JSON: {e}"], {}

        listed: dict = manifest.get("files", {})

        # 1. required files present
        for rf in manifest.get("required_files", []):
            if rf == manifest_name:
                continue
            if rf not in names:
                problems.append(f"required file missing: {rf}")

        # 2. no unlisted files smuggled in (manifest itself is not self-listed).
        #    For a case pack the nested per-bundle ``bundles/<id>/hash_manifest.json``
        #    files ARE regular listed files — only the top-level ``manifest_name``
        #    is excluded, so they are hashed/checked normally.
        for n in names:
            if n == manifest_name:
                continue
            if n not in listed:
                problems.append(f"unlisted file present in pack: {n}")

        # 3. per-file hash check
        recomputed: dict[str, str] = {}
        for path, expected in listed.items():
            if path not in names:
                problems.append(f"listed file missing from zip: {path}")
                continue
            actual = hashlib.sha256(src.read(path)).hexdigest()
            recomputed[path] = actual
            if actual != expected:
                problems.append(f"hash mismatch: {path}")

        # 4. aggregate root hash recomputed from the ACTUAL bytes
        # NOTE: this aggregation MUST stay byte-for-byte in lock-step with the
        # root-hash computation defined in PACK-FORMAT.md. It is intentionally
        # self-contained (no pack-producer imports) so a recipient can run it
        # offline against packs produced independently.
        payload = "\n".join(
            f"{p}:{recomputed.get(p, 'MISSING')}" for p in sorted(listed)
        )
        root = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        if root != manifest.get("root_hash"):
            problems.append("root_hash mismatch")

        # 5. timestamp axis: integrity failure only on a definite root-hash
        # mismatch or a granted-but-missing token. Everything else (including
        # an unverifiable token) is surfaced via timestamp_state/timestamp_checks
        # without affecting ok/exit code — see _timestamp_state().
        ts_problem, ts_state, ts_checks = _timestamp_state(
            manifest.get("timestamp_status") or {}, root, tsa_ca_certs,
        )
        if ts_problem:
            problems.append(ts_problem)
        manifest = dict(manifest)
        manifest["timestamp_state"] = ts_state
        manifest["timestamp_checks"] = ts_checks

        # 6. evidence_ladder stage: informational only, never a pass/fail axis.
        # Present in a per-bundle pack's metadata.json; a case pack has no
        # top-level metadata.json (its stages live per-bundle under
        # bundles/<id>/metadata.json), so this is None for a case pack.
        evidence_stage = None
        if "metadata.json" in names:
            try:
                meta = json.loads(src.read("metadata.json"))
                evidence_stage = (meta.get("evidence_ladder") or {}).get("pack_stage")
            except json.JSONDecodeError:
                evidence_stage = None
        manifest["evidence_stage"] = evidence_stage

    return (len(problems) == 0), problems, manifest


def _verify_timestamp(timestamp_status: dict, root_hash: str) -> str | None:
    """Return a problem string only on a definite timestamp/root mismatch.

    Retained with its original narrow signature for backward compatibility
    (callers may use this directly). ``_timestamp_state`` below is the full
    tri-axis check used by ``verify_pack``/the CLI; this function is a thin
    wrapper around it that discards the state/checks.
    """
    problem, _state, _checks = _timestamp_state(timestamp_status, root_hash, None)
    return problem


def _timestamp_state(
    timestamp_status: dict, root_hash: str, tsa_ca_certs: list | None = None,
) -> tuple[str | None, str, dict]:
    """Return (problem, timestamp_state, timestamp_checks).

    ``problem`` is non-None ONLY for a definite root-hash mismatch or a
    granted-but-missing token — these remain the sole timestamp-related pack
    integrity failures (unchanged from the original, narrower check). Every
    other outcome — including a present-but-unverifiable token — is surfaced
    via ``timestamp_state``/``timestamp_checks`` without affecting ok/exit code.

    States: not_configured | disabled | error | unavailable (passthrough of the
    recorded issuance status, whatever it is) | failed | unverifiable |
    token_verified | token_signature_verified (the last four only ever apply to
    a "granted" issuance status).

    ``timestamp_checks`` is ``{"imprint": ..., "signature": ..., "chain": ...}``
    with imprint in {ok, mismatch, unavailable}, signature in {ok, failed,
    unavailable}, chain in {ok, failed, not_checked}.
    """
    checks = {"imprint": "unavailable", "signature": "unavailable", "chain": "not_checked"}
    status = timestamp_status.get("status") or "not_configured"
    if status != "granted":
        return None, status, checks

    token_b64 = timestamp_status.get("token_b64")
    if not token_b64:
        return "timestamp granted but token missing", "failed", checks

    stamped = _stamped_digest(token_b64)
    if stamped is None:
        return None, "unverifiable", checks  # can't parse offline → unverifiable, not a failure

    if stamped.lower() != (root_hash or "").lower():
        checks["imprint"] = "mismatch"
        problem = f"timestamp attests {stamped[:16]}… but pack root is {(root_hash or '')[:16]}…"
        return problem, "failed", checks

    checks["imprint"] = "ok"

    sig_state, chain_state = _verify_token_signature(token_b64, tsa_ca_certs)
    checks["signature"] = sig_state
    checks["chain"] = chain_state

    if sig_state == "failed":
        return "timestamp token signature invalid", "failed", checks
    if sig_state != "ok":
        return None, "unverifiable", checks
    if chain_state == "ok":
        return None, "token_signature_verified", checks
    return None, "token_verified", checks


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify an evidence pack (v0.2 ZIP or unpacked directory)."
    )
    parser.add_argument("pack", help="Path to the pack .zip or an unpacked pack directory")
    parser.add_argument("--json", action="store_true", help="Emit a JSON result")
    parser.add_argument(
        "--tsa-ca", metavar="PEM_FILE",
        help=(
            "Trust anchor certificate(s) (PEM, optionally concatenated) for the "
            "timestamp signer chain check. Upgrades a verified token's "
            "timestamp_state from token_verified to token_signature_verified if "
            "the signer cert chains to one of these anchors — a single-hop check "
            "only, not full RFC 5280 path/policy validation."
        ),
    )
    args = parser.parse_args()

    tsa_ca_certs = None
    if args.tsa_ca:
        try:
            tsa_ca_certs = _load_tsa_ca(args.tsa_ca)
        except Exception as e:
            print(f"error: --tsa-ca: {e}", file=sys.stderr)
            return 2

    ok, problems, manifest = verify_pack(args.pack, tsa_ca_certs=tsa_ca_certs)

    # A case pack's manifest has no bundle_id (and no case_id); fall back to a
    # neutral "pack" label so the human output is not "bundle=None".
    if manifest.get("bundle_id") is not None:
        label = f"bundle={manifest.get('bundle_id')}"
    elif manifest.get("case_id") is not None:
        label = f"case={manifest.get('case_id')}"
    else:
        label = "pack"

    ts = manifest.get("timestamp_status")
    ts_status = ts.get("status") if isinstance(ts, dict) else ts
    ts_state = manifest.get("timestamp_state")
    ts_checks = manifest.get("timestamp_checks")
    evidence_stage = manifest.get("evidence_stage")

    if args.json:
        print(json.dumps({
            "ok": ok,
            "bundle_id": manifest.get("bundle_id"),
            "root_hash": manifest.get("root_hash"),
            "pack_complete": manifest.get("pack_complete"),
            "pack_complete_reason": manifest.get("pack_complete_reason"),
            "timestamp_status": ts_status,
            "timestamp_state": ts_state,
            "timestamp_checks": ts_checks,
            "evidence_stage": evidence_stage,
            "problems": problems,
        }, indent=2))
    else:
        if ok:
            print(f"PASS  {label} "
                  f"root={(manifest.get('root_hash') or '')[:16]}… "
                  f"pack_complete={manifest.get('pack_complete')}")
            # Honest disclosure: integrity is intact (exit 0), but completeness and
            # timestamping are surfaced, not enforced. A system timestamp proves
            # nothing on its own; qualified timestamping is a separate step.
            print(f"      timestamp_status: {ts_status}")
            print(f"      timestamp_state: {ts_state}")
            if evidence_stage is not None:
                print(f"      evidence_stage: {evidence_stage}")
            if manifest.get("pack_complete") is False:
                reason = manifest.get("pack_complete_reason") or "see capture_failures.json"
                print(f"      WARN  pack is incomplete (integrity still verified): {reason}")
        else:
            print(f"FAIL  {label} — {len(problems)} problem(s):")
            for p in problems:
                print(f"  - {p}")

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
