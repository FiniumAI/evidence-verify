"""Case-pack tests (format case-v0.2): verification of the nested-bundle layout.

A case pack carries ``case_hash_manifest.json`` at the top level with hash
coverage over every other file — including each nested per-bundle pack's own
``bundles/<id>/hash_manifest.json``. The verification algorithm is identical
to the per-bundle one; only the manifest filename differs.
"""
from __future__ import annotations

import unittest
import pack_builder
import token_builder
from evidence_verify.verify import verify_pack

NOW = "2026-06-26T12:00:00Z"


def _case_pack_files():
    files: dict = {}
    file_hashes: dict = {}
    summaries = []

    # one nested per-bundle pack, laid out under bundles/<id>/
    bundle_id = "bundle-nested-0001"
    sub = pack_builder.build_pack_files(bundle_id=bundle_id)
    for arc, data in sub.items():
        nested = f"bundles/{bundle_id}/{arc}"
        files[nested] = data
        file_hashes[nested] = pack_builder._sha256(data)
    summaries.append({
        "bundle_id": bundle_id,
        "root_hash": pack_builder.compute_root_hash(
            {a: pack_builder._sha256(b) for a, b in sub.items() if a != "hash_manifest.json"}
            # NOTE: the sub-pack's own root_hash, from its manifest, is the
            # authoritative nested root; recompute below instead of guessing.
        ),
        "pack_complete": True,
        "review_status": "none",
        "pack_stage": "tamper_evident",
    })
    # authoritative nested root hash from the sub-pack's manifest
    import json

    sub_manifest = json.loads(sub["hash_manifest.json"])
    summaries[0]["root_hash"] = sub_manifest["root_hash"]

    case_manifest = {
        "pack_version": "case-v0.2",
        "case_id": "case-0001",
        "case_title": "Example case",
        "jurisdiction": "DE",
        "generated_at": NOW,
        "exporter": "pack_builder",
        "app_commit": None,
        "bundle_count": 1,
        "bundles": summaries,
    }
    manifest_bytes = pack_builder.json_bytes(case_manifest)
    files["case_manifest.json"] = manifest_bytes
    file_hashes["case_manifest.json"] = pack_builder._sha256(manifest_bytes)

    access_log = {"case_id": "case-0001", "events": []}
    access_bytes = pack_builder.json_bytes(access_log)
    files["access_log.json"] = access_bytes
    file_hashes["access_log.json"] = pack_builder._sha256(access_bytes)

    root_hash = pack_builder.compute_root_hash(file_hashes)

    files["case_hash_manifest.json"] = pack_builder.json_bytes({
        "root_hash": root_hash,
        "pack_complete": True,
        "files": file_hashes,
        "timestamp_status": {"status": "not_configured"},
    })
    return files, root_hash


class CasePackTests(pack_builder.TmpDirTestCase):
    def test_case_pack_verifies(self):
        files, root_hash = _case_pack_files()
        zip_path = pack_builder.write_pack_zip(files, self.dir / "case.zip")

        ok, problems, manifest = verify_pack(zip_path)

        self.assertTrue(ok, problems)
        self.assertEqual(manifest.get("root_hash"), root_hash)

    def test_case_pack_detects_tampered_nested_file(self):
        files, _ = _case_pack_files()
        # tamper a nested bundle artifact
        target = next(
            p for p in files
            if p.startswith("bundles/") and (p.endswith(".html") or p.endswith(".png") or p.endswith(".json"))
        )
        files[target] = b"tampered-bytes"
        zip_path = pack_builder.write_pack_zip(files, self.dir / "bad.zip")

        ok, problems, _ = verify_pack(zip_path)

        self.assertFalse(ok)
        self.assertTrue(any("hash mismatch" in p for p in problems))
        self.assertTrue(any("root_hash" in p for p in problems))

    def test_case_pack_detects_unlisted_file(self):
        files, _ = _case_pack_files()
        files["bundles/bundle-nested-0001/SMUGGLED.txt"] = b"not in the manifest"
        zip_path = pack_builder.write_pack_zip(files, self.dir / "smuggled.zip")

        ok, problems, _ = verify_pack(zip_path)

        self.assertFalse(ok)
        self.assertTrue(any("unlisted file" in p for p in problems))

    def test_per_bundle_pack_still_verifies(self):
        # regression: the existing per-bundle path must still work
        files = pack_builder.build_pack_files()
        zip_path = pack_builder.write_pack_zip(files, self.dir / "bundle.zip")
        ok, problems, manifest = verify_pack(zip_path)
        self.assertTrue(ok, problems)


class CasePackTimestampTests(pack_builder.TmpDirTestCase):
    def test_case_pack_granted_timestamp_verifies_and_cross_checks_case_root(self):
        import json

        key = token_builder.generate_rsa_key(bits=1024, seed=7)
        cert = token_builder.make_self_signed_cert(key, "Test TSA")

        def fake_timestamp_fn(root_hash):
            token_b64 = token_builder.build_timestamp_token(root_hash, key, cert)
            return {
                "status": "granted",
                "provider": "TestTSA",
                "digest_algorithm": "sha256",
                "hashed_value": root_hash,
                "gen_time": "2026-06-26T12:00:00+00:00",
                "token_b64": token_b64,
            }

        files, root_hash = _case_pack_files()
        # re-stamp the case manifest with the granted token (the builder above
        # recorded not_configured)
        manifest = json.loads(files["case_hash_manifest.json"])
        ts = fake_timestamp_fn(root_hash)
        manifest["timestamp_status"] = ts
        files["case_hash_manifest.json"] = pack_builder.json_bytes(manifest)

        zip_path = pack_builder.write_pack_zip(files, self.dir / "case_ts_ok.zip")

        ok, problems, verified_manifest = verify_pack(zip_path)

        self.assertTrue(ok, problems)
        self.assertEqual(verified_manifest["timestamp_status"]["status"], "granted")

    def test_case_pack_wrong_root_timestamp_token_is_a_verify_problem(self):
        import json

        key = token_builder.generate_rsa_key(bits=1024, seed=8)
        cert = token_builder.make_self_signed_cert(key, "Test TSA")

        def fake_timestamp_fn(root_hash):
            token_b64 = token_builder.build_timestamp_token(root_hash, key, cert, wrong_root=True)
            return {
                "status": "granted",
                "provider": "TestTSA",
                "digest_algorithm": "sha256",
                "hashed_value": root_hash,
                "gen_time": "2026-06-26T12:00:00+00:00",
                "token_b64": token_b64,
            }

        files, root_hash = _case_pack_files()
        manifest = json.loads(files["case_hash_manifest.json"])
        manifest["timestamp_status"] = fake_timestamp_fn(root_hash)
        files["case_hash_manifest.json"] = pack_builder.json_bytes(manifest)

        zip_path = pack_builder.write_pack_zip(files, self.dir / "case_ts_bad.zip")

        ok, problems, _ = verify_pack(zip_path)

        self.assertFalse(ok)
        self.assertTrue(any("attests" in p for p in problems))


if __name__ == "__main__":
    unittest.main()
