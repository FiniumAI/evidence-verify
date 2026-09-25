#!/usr/bin/env python3
"""Build a minimal valid v0.2 evidence pack (demo) for immediate verification.

Usage:
    python examples/make_demo_pack.py                 # -> examples/demo-pack/
    python examples/make_demo_pack.py --zip           # -> examples/demo-pack.zip
    python examples/make_demo_pack.py --out PATH      # custom output dir

The demo pack contains a manifest, per-file SHA-256 hashes, the aggregate root
hash, a chain-of-custody log, a capture-failure log, and metadata — every file
the verifier expects from a per-bundle pack. Verify it with:

    python -m evidence_verify examples/demo-pack
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

DEMO_BUNDLE_ID = "bundle-demo-0001"
PACK_VERSION = "0.2"


def json_bytes(obj) -> bytes:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_root_hash(file_hashes: dict) -> str:
    """PACK-FORMAT.md root-hash definition — keep byte-identical to the verifier."""
    payload = "\n".join(f"{p}:{file_hashes[p]}" for p in sorted(file_hashes))
    return sha256_hex(payload.encode("utf-8"))


def minimal_pdf(title: str) -> bytes:
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
    return bytes(pdf)


def build_demo_pack(out_dir: Path) -> Path:
    """Construct the demo pack directory; return the root path."""
    now = datetime(2026, 6, 20, 12, 0, 0, tzinfo=timezone.utc)
    iso = now.isoformat().replace("+00:00", "Z")
    files: dict = {}

    # --- artifacts/ : the byte evidence ---
    files["artifacts/html_snapshot.html"] = (
        b"<!doctype html><html><head><title>Example post</title></head>"
        b"<body><h1>Example post</h1><p>The offending content would be captured "
        b"here verbatim at capture time.</p></body></html>"
    )
    files["artifacts/thread_context.json"] = json_bytes({
        "content_url": "https://example.com/post/123",
        "thread": [
            {"author": "example-user", "text": "parent post content", "captured_at": iso},
            {"author": "example-user-2", "text": "reply content", "captured_at": iso},
        ],
        "captured_at": iso,
    })
    files["artifacts/screenshot.png"] = b"\x89PNG\r\n\x1a\n" + b"demo-render" + bytes(16)

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
            "sha256_hash": sha256_hex(files[arc]),
            "captured_at": iso,
            "method": "make_demo_pack",
        })
    files["chain_of_custody.json"] = json_bytes({
        "bundle_id": DEMO_BUNDLE_ID,
        "source_platform": "web",
        "content_url": "https://example.com/post/123",
        "poster_profile_url": None,
        "model_run_id": None,
        "review_queue_id": None,
        "capture_method": "make_demo_pack",
        "capture_actor": "make_demo_pack.py",
        "captured_at": iso,
        "capture_timezone": "UTC",
        "items": items,
        "export_events": [
            {
                "event": f"evidence_pack_v{PACK_VERSION}_export",
                "exported_at": iso,
                "exporter": "make_demo_pack",
                "app_commit": None,
            }
        ],
    })

    # --- capture_failures.json : nothing failed, but the log must exist ---
    files["capture_failures.json"] = json_bytes({
        "bundle_id": DEMO_BUNDLE_ID,
        "count": 0,
        "failures": [],
    })

    # --- review.json ---
    files["review.json"] = json_bytes({
        "review_status": "none",
        "bundle_id": DEMO_BUNDLE_ID,
        "note": "bundle not linked to a review_queue item",
    })

    # --- metadata.json ---
    files["metadata.json"] = json_bytes({
        "pack_version": PACK_VERSION,
        "bundle_id": DEMO_BUNDLE_ID,
        "source_platform": "web",
        "source_urls": {"content_url": "https://example.com/post/123"},
        "capture_timezone": "UTC",
        "capture_status": "captured",
        "capture_method": "make_demo_pack",
        "evidence_tier": "make_demo_pack",
        "exporter": "make_demo_pack",
        "generated_at": iso,
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
        "evidence_ladder": {"pack_stage": "tamper_evident", "items": {}, "reasons": []},
    })

    # --- report.pdf ---
    files["report.pdf"] = minimal_pdf("Evidence Pack v0.2 Demo")

    # --- hash_manifest.json : lists every OTHER file ---
    file_hashes = {arc: sha256_hex(b) for arc, b in files.items()}
    root_hash = compute_root_hash(file_hashes)
    files["hash_manifest.json"] = json_bytes({
        "pack_version": PACK_VERSION,
        "bundle_id": DEMO_BUNDLE_ID,
        "algorithm": "sha256",
        "generated_at": iso,
        "files": file_hashes,
        "root_hash": root_hash,
        "required_files": [
            "report.pdf",
            "metadata.json",
            "chain_of_custody.json",
            "hash_manifest.json",
            "capture_failures.json",
            "review.json",
        ],
        "required_core_items": ["html_snapshot", "thread_context", "chain_of_custody"],
        "missing_required": [],
        "pack_complete": True,
        "pack_complete_reason": "all required files present and integrity verified",
        "timestamp_status": {"status": "not_configured"},
    })

    out_dir.mkdir(parents=True, exist_ok=True)
    for arc, data in files.items():
        target = out_dir / arc
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    print(f"wrote demo pack: {out_dir}")
    print(f"root_hash: {root_hash}")
    return out_dir


def zip_pack_dir(pack_dir: Path, zip_path: Path) -> Path:
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(pack_dir.rglob("*")):
            if p.is_file():
                zf.write(p, p.relative_to(pack_dir).as_posix())
    print(f"wrote zip: {zip_path}")
    return zip_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--out", default=str(Path(__file__).resolve().parent / "demo-pack"),
        help="output directory (default: examples/demo-pack)",
    )
    parser.add_argument(
        "--zip", action="store_true",
        help="also write examples/demo-pack.zip next to the directory",
    )
    args = parser.parse_args()

    pack_dir = build_demo_pack(Path(args.out))
    if args.zip:
        zip_pack_dir(pack_dir, pack_dir.parent / (pack_dir.name + ".zip"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
