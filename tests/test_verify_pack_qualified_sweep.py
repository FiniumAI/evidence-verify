"""Claim-honesty guard: the string ``qualified_verified`` must never reappear
in the package.

The offline verifier's top timestamp-verification tier was renamed from
``qualified_verified`` to ``token_signature_verified`` because the check it
names is CMS signature verification plus a single-hop trust-anchor match, not
RFC 5280 path/policy/revocation validation. "Qualified" is a term of art
under eIDAS that the verifier does not earn. This is a permanent guard
against the old, overclaiming name being reintroduced.
"""
from __future__ import annotations

import unittest
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1] / "evidence_verify"


class QualifiedVerifiedGuard(unittest.TestCase):
    def test_qualified_verified_string_absent_from_package(self):
        offenders = []
        for path in PACKAGE_ROOT.rglob("*.py"):
            text = path.read_text()
            if "qualified_verified" in text:
                offenders.append(str(path.relative_to(PACKAGE_ROOT.parent)))
        self.assertEqual(
            offenders, [],
            "the retired claim-name 'qualified_verified' reappeared in "
            f"{sorted(offenders)}; use 'token_signature_verified' instead",
        )


if __name__ == "__main__":
    unittest.main()
