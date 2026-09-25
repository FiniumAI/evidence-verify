"""Tests for the standalone evidence-pack verifier (format v0.2).

The verifier re-hashes every file listed in hash_manifest.json, recomputes the
root hash, and rejects tampered / missing / unlisted files. These tests build a
real pack via the shared test pack-builder, then mutate the file set to
exercise each failure mode. The pack builder mirrors the production exporter's
semantics (see tests/pack_builder.py) without importing any of it.
"""
from __future__ import annotations

import json
import unittest

import pack_builder
from pack_builder import TmpDirTestCase
from evidence_verify.verify import verify_pack


class ValidPackTests(TmpDirTestCase):
    def test_verifier_passes_valid_pack(self):
        files = pack_builder.build_pack_files()
        zip_path = pack_builder.write_pack_zip(files, self.dir / "valid.zip")

        ok, problems, manifest = verify_pack(zip_path)

        self.assertTrue(ok, problems)
        self.assertIs(manifest["pack_complete"], True)

    def test_verifier_passes_valid_pack_directory(self):
        files = pack_builder.build_pack_files()
        dir_path = pack_builder.write_pack_dir(files, self.dir / "valid-dir")

        ok, problems, manifest = verify_pack(dir_path)

        self.assertTrue(ok, problems)
        self.assertIs(manifest["pack_complete"], True)

    def test_verifier_passes_valid_pack_bytes(self):
        import io
        import zipfile

        files = pack_builder.build_pack_files()
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for arc in sorted(files):
                zf.writestr(arc, files[arc])

        from evidence_verify.verify import verify_pack_bytes

        ok, problems, manifest = verify_pack_bytes(buf.getvalue())

        self.assertTrue(ok, problems)
        self.assertIs(manifest["pack_complete"], True)


class TamperTests(TmpDirTestCase):
    def test_verifier_fails_tampered_artifact(self):
        files = pack_builder.build_pack_files()
        html_member = next(name for name in files if name.endswith("/html_snapshot.html"))
        files[html_member] = b"<html>tampered after manifest</html>"
        zip_path = pack_builder.write_pack_zip(files, self.dir / "tampered.zip")

        ok, problems, _ = verify_pack(zip_path)

        self.assertFalse(ok)
        self.assertTrue(any("hash mismatch" in p for p in problems))
        self.assertTrue(any("root_hash" in p for p in problems))

    def test_verifier_fails_missing_required_file(self):
        files = pack_builder.build_pack_files()
        del files["review.json"]
        zip_path = pack_builder.write_pack_zip(files, self.dir / "missing.zip")

        ok, problems, _ = verify_pack(zip_path)

        self.assertFalse(ok)
        self.assertTrue(any("review.json" in p for p in problems))

    def test_verifier_fails_unlisted_extra_file(self):
        files = pack_builder.build_pack_files()
        files["artifacts/sneaky.txt"] = b"not in the manifest"
        zip_path = pack_builder.write_pack_zip(files, self.dir / "extra.zip")

        ok, problems, _ = verify_pack(zip_path)

        self.assertFalse(ok)
        self.assertTrue(any("unlisted file" in p for p in problems))

    def test_verifier_fails_missing_pack(self):
        ok, problems, _ = verify_pack(self.dir / "nonexistent.zip")

        self.assertFalse(ok)
        self.assertTrue(any("pack not found" in p for p in problems))

    def test_verifier_fails_not_a_zip(self):
        p = self.dir / "not-a-zip.bin"
        p.write_bytes(b"this is not a zip file")
        ok, problems, _ = verify_pack(p)

        self.assertFalse(ok)
        self.assertTrue(any("not a valid ZIP" in p for p in problems))

    def test_verifier_fails_pack_with_no_manifest(self):
        files = {"artifacts/loose.html": b"<html>no manifest</html>"}
        zip_path = pack_builder.write_pack_zip(files, self.dir / "nomanifest.zip")

        ok, problems, _ = verify_pack(zip_path)

        self.assertFalse(ok)
        self.assertTrue(any("not a v0.2 pack" in p for p in problems))

    def test_verifier_fails_manifest_with_bad_json(self):
        import zipfile

        p = self.dir / "badjson.zip"
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr("hash_manifest.json", "{not valid json")
        ok, problems, _ = verify_pack(p)

        self.assertFalse(ok)
        self.assertTrue(any("not valid JSON" in p for p in problems))

    def test_verifier_fails_when_listed_file_missing_from_zip(self):
        files = pack_builder.build_pack_files()
        manifest_name = "hash_manifest.json"
        manifest = json.loads(files[manifest_name])
        victim = "metadata.json"
        del files[victim]  # remove the file but keep it listed in the manifest
        # (the manifest itself is not self-listed, so its bytes are unchanged)
        del manifest["required_files"]  # avoid the separate missing-required problem string
        files[manifest_name] = pack_builder.json_bytes(manifest)
        zip_path = pack_builder.write_pack_zip(files, self.dir / "listed-missing.zip")

        ok, problems, _ = verify_pack(zip_path)

        self.assertFalse(ok)
        self.assertTrue(any(f"listed file missing from zip: {victim}" in p for p in problems))


if __name__ == "__main__":
    unittest.main()
