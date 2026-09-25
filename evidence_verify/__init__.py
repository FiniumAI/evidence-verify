"""evidence-verify: offline verifier for tamper-evident legal/web evidence packs.

See PACK-FORMAT.md for the interchange specification this package verifies.
"""
__version__ = "0.1.0"

from evidence_verify.verify import verify_pack, verify_pack_bytes

__all__ = ["verify_pack", "verify_pack_bytes", "__version__"]
