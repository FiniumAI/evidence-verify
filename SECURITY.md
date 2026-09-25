# Security Policy

## Reporting a vulnerability

Report privately to the maintainer at henryk.wexel@gmail.com with
"[evidence-verify security]" in the subject. Please include a minimal
reproduction (a crafted pack ZIP or token that misleads the verifier) and
your assessment of impact. Do not open a public issue for suspected
vulnerabilities first.

## Scope

The verifier's decision logic: anything that makes a tampered pack verify as
ok, or makes a valid pack fail. Examples: hash-chain construction flaws,
parsing confusions in the DER/CMS walk, path traversal in directory packs,
signature-verification bypasses, ZIP handling bugs.

Not in scope: pack producers, timestamp authorities, or content captured
before packing — the verifier explicitly does not prove capture authenticity
(see README "Security notes").

## Expectations

This is a small, offline, standard-library-only tool with no network surface.
There is no promised response SLA. Fixes land as regular commits with a test
proving the flaw and its fix.

## Verification boundaries (repeated for searchability)

`token_signature_verified` is CMS signature verification plus a single-hop
trust-anchor match — not RFC 5280 path/policy/revocation validation. No
CRL/OCSP. No certificate validity-period checking. No defense against ZIP
bombs. Treat the verifier as a tamper detector for packs, not a proof of
capture authenticity.
