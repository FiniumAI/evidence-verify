"""Test pack builder — stdlib-only construction of a valid v0.2 evidence pack.

Builds the same file set the production exporter emits (report.pdf,
metadata.json, artifacts/, chain_of_custody.json, hash_manifest.json,
capture_failures.json, review.json) with the same root-hash computation, so
the verifier is tested against genuine, self-consistent pack bytes without
importing any producer code.
"""
from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

PACK_VERSION = "0.2"


class TmpDirTestCase(unittest.TestCase):
    """Base class giving each test a clean scratch directory (``self.dir``)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

REQUIRED_PACK_FILES = (
    "report.pdf",
    "metadata.json",
    "chain_of_custody.json",
    "hash_manifest.json",
    "capture_failures.json",
    "review.json",
)


def json_bytes(obj) -> bytes:
    """Deterministic JSON serialization for stable, re-hashable pack files."""
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _iso_z(dt) -> str:
    return dt.isoformat() + "Z"


def compute_root_hash(file_hashes: dict) -> str:
    """Aggregate/root hash over the per-file hashes (order-independent)."""
    payload = "\n".join(f"{path}:{file_hashes[path]}" for path in sorted(file_hashes))
    return _sha256(payload.encode("utf-8"))


def build_pack_files(
    *,
    bundle_id: str = "bundle-demo-0001",
    timestamp_fn=None,
    now=None,
) -> dict:
    """Build a minimal but structurally complete v0.2 pack's files dict.

    ``timestamp_fn(root_hash) -> {"status": ..., ...}`` mirrors the production
    exporter's injection point: when given, its result is recorded verbatim in
    ``hash_manifest.json.timestamp_status``; otherwise the pack records status
    ``not_configured``.
    """
    from datetime import datetime, timezone

    if now is None:
        now = datetime(2026, 6, 20, 12, 0, 0, tzinfo=timezone.utc)
    files: dict = {}

    # --- artifacts/ ---
    files["artifacts/html_snapshot.html"] = (
        b"<!doctype html><html><head><title>Example page</title></head>"
        b"<body><p>Example content captured as evidence.</p></body></html>"
    )
    files["artifacts/thread_context.json"] = json_bytes({
        "content_url": "https://example.com/post/123",
        "captured_at": _iso_z(now),
    })
    files["artifacts/screenshot.png"] = b"\x89PNG\r\n\x1a\nrendered"

    # --- chain_of_custody.json ---
    items = []
    for arc, item_type in (
        ("artifacts/html_snapshot.html", "html_snapshot"),
        ("artifacts/thread_context.json", "thread_context"),
        ("artifacts/screenshot.png", "screenshot"),
    ):
        items.append({
            "item_type": item_type,
            "capture_status": "captured",
            "artifact_uri": arc,
            "sha256_hash": _sha256(files[arc]),
            "captured_at": _iso_z(now),
            "method": "test_builder",
        })
    coc = {
        "bundle_id": bundle_id,
        "capture_method": "test_builder",
        "capture_actor": "pack_builder",
        "captured_at": _iso_z(now),
        "capture_timezone": "UTC",
        "items": items,
        "export_events": [
            {
                "event": f"evidence_pack_v{PACK_VERSION}_export",
                "exported_at": _iso_z(now),
                "exporter": "pack_builder",
                "app_commit": None,
            }
        ],
    }
    files["chain_of_custody.json"] = json_bytes(coc)

    # --- capture_failures.json : nothing failed, but the file must exist ---
    files["capture_failures.json"] = json_bytes({
        "bundle_id": bundle_id,
        "count": 0,
        "failures": [],
    })

    # --- review.json ---
    files["review.json"] = json_bytes({
        "review_status": "none",
        "bundle_id": bundle_id,
        "note": "bundle not linked to a review_queue item",
    })

    # --- metadata.json ---
    metadata = {
        "pack_version": PACK_VERSION,
        "bundle_id": bundle_id,
        "source_platform": "web",
        "capture_timezone": "UTC",
        "capture_status": "captured",
        "capture_method": "test_builder",
        "evidence_tier": "test_builder",
        "exporter": "pack_builder",
        "generated_at": _iso_z(now),
        "items": [
            {
                "item_type": row["item_type"],
                "capture_status": row["capture_status"],
                "sha256_hash": row["sha256_hash"],
                "captured_at": row["captured_at"],
                "timestamp_source": "system clock at capture time, recorded in UTC",
            }
            for row in items
        ],
        "artifacts": [
            {
                "item_type": row["item_type"],
                "arcname": row["artifact_uri"],
                "sha256_recorded": row["sha256_hash"],
                "sha256_actual": row["sha256_hash"],
                "integrity_ok": True,
            }
            for row in items
        ],
        "review_status": "none",
        "pack_complete": True,
        "pack_complete_reason": "core items captured and integrity verified",
        "evidence_ladder": {
            "pack_stage": "tamper_evident",
            "items": {},
            "reasons": [],
        },
    }
    files["metadata.json"] = json_bytes(metadata)

    # --- report.pdf : minimal valid PDF wrapper ---
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>",
        b"<< /Length 44 >>\nstream\nBT /F1 12 Tf 72 720 Td (Evidence Pack v0.2) Tj ET\nendstream",
    ]
    pdf = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
    xref_pos = len(pdf)
    pdf += f"xref\n0 {len(objects) + 1}\n".encode()
    pdf += b"0000000000 65535 f \n"
    for off in offsets:
        pdf += f"{off:010d} 00000 n \n".encode()
    pdf += (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n"
    ).encode()
    files["report.pdf"] = bytes(pdf)

    # --- hash_manifest.json : the integrity root (lists every OTHER file) ---
    file_hashes = {arc: _sha256(b) for arc, b in files.items()}
    root_hash = compute_root_hash(file_hashes)

    if timestamp_fn is None:
        timestamp_status = {"status": "not_configured"}
    else:
        timestamp_result = timestamp_fn(root_hash)
        if isinstance(timestamp_result, dict):
            timestamp_status = timestamp_result
        else:
            timestamp_status = timestamp_result.to_manifest()

    manifest = {
        "pack_version": PACK_VERSION,
        "bundle_id": bundle_id,
        "algorithm": "sha256",
        "generated_at": _iso_z(now),
        "files": file_hashes,
        "root_hash": root_hash,
        "required_files": list(REQUIRED_PACK_FILES),
        "required_core_items": ["html_snapshot", "thread_context", "chain_of_custody"],
        "missing_required": [],
        "pack_complete": True,
        "pack_complete_reason": "all required files present and integrity verified",
        "timestamp_status": timestamp_status,
    }
    files["hash_manifest.json"] = json_bytes(manifest)
    return files


def write_pack_zip(files: dict, zip_path) -> Path:
    zip_path = Path(zip_path)
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for arc in sorted(files):
            zf.writestr(arc, files[arc])
    return zip_path


def write_pack_dir(files: dict, dir_path) -> Path:
    dir_path = Path(dir_path)
    dir_path.mkdir(parents=True, exist_ok=True)
    for arc, data in files.items():
        target = dir_path / arc
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return dir_path
