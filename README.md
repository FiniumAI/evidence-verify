# evidence-verify

An offline verifier for tamper-evident legal/web evidence packs. It re-hashes
every file in an evidence pack, recomputes the aggregate root hash, and
rejects tampered, missing, or smuggled-in files — with no network access, no
database, and no third-party dependencies (Python standard library only, so a
recipient such as a lawyer, court, or auditor can run it anywhere).

## What it is

`evidence-verify` checks the integrity of an "evidence pack": a ZIP file (or
unpacked directory) that bundles captured web content — HTML snapshots,
screenshots, thread context — together with a hash manifest, a chain-of-custody
log, a capture-failure log, and optionally an RFC3161 timestamp token binding
the pack's root hash to a trusted time. The pack format itself is specified in
[PACK-FORMAT.md](PACK-FORMAT.md), written so a third party can produce
verifiable packs independently of this tool.

## Usage

```bash
# from a checkout of this repository
python -m evidence_verify examples/demo-pack          # unpacked directory
python -m evidence_verify examples/demo-pack.zip      # ZIP form
python -m evidence_verify pack.zip --json             # machine-readable output
python -m evidence_verify pack.zip --tsa-ca tsa.pem   # single-hop TSA trust anchor
```

Build the demo pack yourself first:

```bash
python examples/make_demo_pack.py --zip
python -m evidence_verify examples/demo-pack --json
```

Verifying from the repository root requires no installation step; to use the
package from elsewhere, copy the `evidence_verify/` directory into your
project or add the repository root to `PYTHONPATH`.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Pack integrity verified (problems list is empty) |
| 1 | Verification failed — tamper, missing, or unlisted files |
| 2 | Bad invocation (e.g. an unreadable `--tsa-ca` PEM file) |

A verified-but-incomplete or verified-but-untimestamped pack still exits 0:
completeness and timestamping are surfaced as warnings, not enforced. See
"Security notes" below.

## Security notes — what this proves, and what it does NOT prove

**Proves (when the result is ok):**

- Every file listed in the pack's hash manifest hashes to its recorded
  SHA-256 value (no listed file was modified after the manifest was written).
- The aggregate root hash recomputed from the actual bytes matches the
  manifest's root hash (the file set is exactly the set that was hashed).
- No file is present in the pack that the manifest does not list, and no
  required file is missing.
- With a granted RFC3161 token: the token's message imprint matches the pack's
  root hash, and (for RSA PKCS#1 v1.5 with SHA-256/384/512) the token's CMS
  signature verifies against the embedded signer certificate. With `--tsa-ca`,
  additionally, that the signer certificate was issued directly by one of the
  supplied trust anchors (a single-hop check).

**Does NOT prove:**

- Authenticity of the original capture: a pack can be internally consistent
  and still contain fabricated content — the hashes only show the content was
  not changed *after* the pack was assembled.
- That a timestamp is *qualified* under eIDAS or similar schemes. The
  verification tier is honestly named `token_signature_verified`, not
  "qualified": it is CMS signature verification plus a single-hop anchor
  match, not full RFC 5280 path/policy/revocation validation. No CRL/OCSP
  revocation checking, no path-length or policy constraints, no intermediate
  chain support, and no validity-period check on the signer certificate.
- Capture-time claims inside metadata.json, chain_of_custody.json, or
  review.json beyond what their hashes cover: `captured_at` values come from
  the producer's system clock and are not independently verified.
- Completeness of the underlying capture: `pack_complete` is a claim recorded
  by the pack producer; the verifier surfaces it, and does not enforce it.
- That a timestamp token is currently valid: `gen_time` inside the token is
  not checked against the wall clock (verification is fully offline; token
  revocation and expiry are out of scope).

Other operational limits: RSA keys only for the token signature check
(ECDSA/Ed25519 tokens degrade to "unavailable", never "failed"); ZIP bombs and
decompression ratio limits are not defended against — verify packs from
parties you'd otherwise trust to send you archives.

**Exit-code discipline for automation:** treat exit 1 as "integrity broken"
and inspect the `problems` list; treat ok-with-warnings (incomplete pack,
`timestamp_state: unverifiable`) as a human-review case, not a pass/fail
signal.

## Development

```bash
python -m unittest discover -s tests   # 29 tests, stdlib only
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).

## Contributing & security

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
