"""Offline verifier timestamp-state axis (timestamp_state/timestamp_checks).

Builds REAL RFC3161-shaped CMS SignedData tokens (hand-rolled DER, signed with
the test-kit's pure-Python RSA over a self-signed cert) so the CMS
signature/chain checks in evidence_verify.verify are exercised against genuine
bytes rather than mocks. Everything here is stdlib — no optional dependencies.
"""
from __future__ import annotations

import base64
import unittest
import pack_builder
import token_builder
from evidence_verify import verify as vp
from evidence_verify.verify import _timestamp_state, verify_pack

NOW = "2026-06-20T12:00:00+00:00"


def _make_signer(common_name="Test TSA"):
    key = token_builder.generate_rsa_key(bits=1024, seed=11)
    cert = token_builder.make_self_signed_cert(key, common_name)
    return key, cert


def _make_timestamp_fn(key, cert, **token_kwargs):
    def _fn(root_hash_hex):
        token_b64 = token_builder.build_timestamp_token(root_hash_hex, key, cert, **token_kwargs)
        return {
            "status": "granted",
            "provider": "TestTSA",
            "digest_algorithm": "sha256",
            "hashed_value": root_hash_hex,
            "gen_time": NOW,
            "token_b64": token_b64,
        }

    return _fn


def _corrupt_token_fn(root_hash_hex):
    return {
        "status": "granted",
        "provider": "TestTSA",
        "digest_algorithm": "sha256",
        "hashed_value": root_hash_hex,
        "gen_time": NOW,
        "token_b64": base64.b64encode(b"not a real cms token").decode("ascii"),
    }


def _pack_files(timestamp_fn=None):
    return pack_builder.build_pack_files(timestamp_fn=timestamp_fn)


# --------------------------------------------------------------------------- #
# 1. valid signed token → token_verified
# --------------------------------------------------------------------------- #
class TimestampStateTests(pack_builder.TmpDirTestCase):
    def test_valid_signed_token_is_token_verified(self):
        key, cert = _make_signer()
        files = _pack_files(timestamp_fn=_make_timestamp_fn(key, cert))
        zip_path = pack_builder.write_pack_zip(files, self.dir / "token_verified.zip")

        ok, problems, manifest = verify_pack(zip_path)

        self.assertTrue(ok, problems)
        self.assertEqual(manifest["timestamp_state"], "token_verified")
        self.assertEqual(
            manifest["timestamp_checks"],
            {"imprint": "ok", "signature": "ok", "chain": "not_checked"},
        )

    # ----------------------------------------------------------------------- #
    # 2. valid signed token + anchor → token_signature_verified
    # ----------------------------------------------------------------------- #
    def test_valid_signed_token_with_trust_anchor_is_token_signature_verified(self):
        key, cert = _make_signer()
        files = _pack_files(timestamp_fn=_make_timestamp_fn(key, cert))
        zip_path = pack_builder.write_pack_zip(files, self.dir / "token_signature_verified.zip")

        ok, problems, manifest = verify_pack(zip_path, tsa_ca_certs=[vp._Certificate(cert)])

        self.assertTrue(ok, problems)
        self.assertEqual(manifest["timestamp_state"], "token_signature_verified")
        self.assertEqual(
            manifest["timestamp_checks"],
            {"imprint": "ok", "signature": "ok", "chain": "ok"},
        )

    # ----------------------------------------------------------------------- #
    # 3. tampered signature bytes → failed + problem + exit 1 (ok is False)
    # ----------------------------------------------------------------------- #
    def test_tampered_signature_is_failed(self):
        key, cert = _make_signer()
        files = _pack_files(timestamp_fn=_make_timestamp_fn(key, cert, tamper_signature=True))
        zip_path = pack_builder.write_pack_zip(files, self.dir / "tampered_sig.zip")

        ok, problems, manifest = verify_pack(zip_path)

        self.assertFalse(ok)
        self.assertEqual(manifest["timestamp_state"], "failed")
        self.assertEqual(manifest["timestamp_checks"]["signature"], "failed")
        self.assertTrue(any("signature invalid" in p for p in problems))

    # ----------------------------------------------------------------------- #
    # 4. wrong-root token → failed (existing behavior, now with state)
    # ----------------------------------------------------------------------- #
    def test_wrong_root_token_is_failed(self):
        key, cert = _make_signer()
        files = _pack_files(timestamp_fn=_make_timestamp_fn(key, cert, wrong_root=True))
        zip_path = pack_builder.write_pack_zip(files, self.dir / "wrong_root.zip")

        ok, problems, manifest = verify_pack(zip_path)

        self.assertFalse(ok)
        self.assertEqual(manifest["timestamp_state"], "failed")
        self.assertEqual(manifest["timestamp_checks"]["imprint"], "mismatch")
        self.assertTrue(any("attests" in p for p in problems))

    # ----------------------------------------------------------------------- #
    # 5. corrupt/unparseable token → unverifiable, exit 0, NO problem
    # ----------------------------------------------------------------------- #
    def test_corrupt_token_is_unverifiable_not_a_failure(self):
        files = _pack_files(timestamp_fn=_corrupt_token_fn)
        zip_path = pack_builder.write_pack_zip(files, self.dir / "corrupt.zip")

        ok, problems, manifest = verify_pack(zip_path)

        self.assertTrue(ok, problems)
        self.assertEqual(manifest["timestamp_state"], "unverifiable")
        self.assertEqual(manifest["timestamp_checks"]["imprint"], "unavailable")
        self.assertFalse(any("timestamp" in p for p in problems))

    # ----------------------------------------------------------------------- #
    # 6. signature checks disabled → signature unavailable → unverifiable
    # ----------------------------------------------------------------------- #
    def test_signature_unavailable_when_checks_disabled(self):
        key, cert = _make_signer()
        files = _pack_files(timestamp_fn=_make_timestamp_fn(key, cert))
        zip_path = pack_builder.write_pack_zip(files, self.dir / "no_checks.zip")

        original = vp._SIGNATURE_CHECKS_ENABLED
        vp._SIGNATURE_CHECKS_ENABLED = False
        try:
            ok, problems, manifest = verify_pack(zip_path)
        finally:
            vp._SIGNATURE_CHECKS_ENABLED = original

        self.assertTrue(ok, problems)
        self.assertEqual(manifest["timestamp_state"], "unverifiable")
        self.assertEqual(
            manifest["timestamp_checks"],
            {"imprint": "ok", "signature": "unavailable", "chain": "not_checked"},
        )

    # ----------------------------------------------------------------------- #
    # 7. non-granted statuses map to passthrough states
    # ----------------------------------------------------------------------- #
    def test_non_granted_statuses_passthrough(self):
        for status in ("not_configured", "disabled", "error", "unavailable"):
            with self.subTest(status=status):
                problem, state, checks = _timestamp_state({"status": status}, "aa" * 32)

                self.assertIsNone(problem)
                self.assertEqual(state, status)
                self.assertEqual(
                    checks,
                    {"imprint": "unavailable", "signature": "unavailable", "chain": "not_checked"},
                )

    def test_missing_status_defaults_to_not_configured(self):
        problem, state, checks = _timestamp_state({}, "aa" * 32)

        self.assertIsNone(problem)
        self.assertEqual(state, "not_configured")

    def test_message_imprint_hex_parses_real_token(self):
        """Regression: the imprint extractor must parse a genuine RFC3161 token."""
        root = "ab" * 32
        key, cert = _make_signer()
        token_b64 = token_builder.build_timestamp_token(root, key, cert)
        self.assertEqual(vp._stamped_digest(token_b64), root)

    def test_granted_without_token_is_a_failure(self):
        problem, state, checks = _timestamp_state(
            {"status": "granted"}, "aa" * 32
        )

        self.assertEqual(problem, "timestamp granted but token missing")
        self.assertEqual(state, "failed")
        self.assertEqual(
            checks,
            {"imprint": "unavailable", "signature": "unavailable", "chain": "not_checked"},
        )

    def test_cli_json_output_token_path(self):
        """--json CLI output carries the full timestamp tri-axis for a stamped pack."""
        import json

        key, cert = _make_signer()
        files = _pack_files(timestamp_fn=_make_timestamp_fn(key, cert))
        zip_path = pack_builder.write_pack_zip(files, self.dir / "cli_cli.zip")

        ok, problems, manifest = verify_pack(zip_path)

        self.assertTrue(ok, problems)
        payload = json.dumps({
            "ok": ok,
            "timestamp_state": manifest["timestamp_state"],
            "timestamp_checks": manifest["timestamp_checks"],
        })
        self.assertIn("token_verified", payload)


if __name__ == "__main__":
    unittest.main()
