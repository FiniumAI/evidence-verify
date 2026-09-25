# Evidence Pack Format (v0.2 / case-v0.2)

This document specifies the pack interchange format that
`evidence_verify` verifies, so that a third party can produce verifiable
packs independently of this tool. Conformance examples: the demo pack built
by `examples/make_demo_pack.py`, and the packs built by the test suite in
`tests/pack_builder.py`.

## 1. Overview

An **evidence pack** is a ZIP file (or a directory with the identical layout)
that bundles captured byte evidence — HTML snapshots, screenshots, thread
context — together with the records needed to detect after-the-fact
modification:

- a **hash manifest** listing every file with its SHA-256 hash, plus an
  aggregate **root hash** over the whole file set,
- a **chain-of-custody log** recording each capture event,
- a **capture-failure log** disclosing every skipped or failed capture (no
  silent gaps),
- a **review record** capturing any human decision made on the evidence,
- and, optionally, an **RFC3161 timestamp token** attesting the root hash.

There are three pack kinds, distinguished only by the manifest filename at
the pack's top level:

| Kind | Top-level manifest | Covers |
| --- | --- | --- |
| per-bundle pack | `hash_manifest.json` | one capture bundle |
| per-case pack | `case_hash_manifest.json` | several bundles under `bundles/<id>/` plus case-level files |
| referral pack | `referral_manifest.json` | every other file in the pack, including a nested pack's own manifests |

The verification algorithm is identical for all three: only the manifest
filename differs. A pack with none of the three manifests is rejected as
"not a v0.2 pack".

## 2. Directory layout (per-bundle pack)

```
report.pdf                    rendered human-readable report
metadata.json                 capture metadata + completeness + evidence ladder
artifacts/                    the byte evidence
  html_snapshot.html
  thread_context.json
  screenshot.png
chain_of_custody.json         capture chain-of-custody + export events
hash_manifest.json            per-file SHA-256, root hash, completeness, timestamp status
capture_failures.json         every skipped/failed item + reason
review.json                   human review decision, or review_status="none"
```

Top-level files the verifier treats as **required** (when listed in the
manifest's `required_files`, which a conforming producer must include):

```
report.pdf, metadata.json, chain_of_custody.json,
hash_manifest.json, capture_failures.json, review.json
```

A per-case pack nests one or more complete per-bundle packs under
`bundles/<bundle-id>/` and adds at its own top level:

```
case_manifest.json            case metadata + per-bundle summaries
access_log.json               who accessed the case pack, when
case_hash_manifest.json       hash coverage over every other file
bundles/<bundle-id>/…         complete per-bundle packs (including their own hash_manifest.json)
```

## 3. Hash manifest schema

`hash_manifest.json` (respectively `case_hash_manifest.json` /
`referral_manifest.json`) is a JSON object:

```jsonc
{
  "pack_version": "0.2",            // "case-v0.2" for a case pack
  "bundle_id": "<id>",              // "case_id" for a case pack; both optional elsewhere
  "algorithm": "sha256",
  "generated_at": "2026-06-20T12:00:00Z",
  "files": {                        // arcname -> sha256 hex, for EVERY other file in the pack
    "report.pdf": "<64-hex>",
    "metadata.json": "<64-hex>",
    "artifacts/html_snapshot.html": "<64-hex>"
  },
  "root_hash": "<64-hex>",          // see section 4
  "required_files": ["report.pdf", "metadata.json", "chain_of_custody.json",
                      "hash_manifest.json", "capture_failures.json", "review.json"],
  "required_core_items": ["html_snapshot", "thread_context", "chain_of_custody"],
  "missing_required": [],
  "pack_complete": true,
  "pack_complete_reason": "all required files present and integrity verified",
  "timestamp_status": {"status": "not_configured"}
}
```

Rules:

- **The manifest is not self-listed.** `files` covers every other file in the
  pack; the manifest itself is the one file whose hash is not recorded (it
  carries all the others).
- **Exactly-covering.** Every file present in the pack (other than the
  manifest itself) MUST be listed in `files`, and every listed file MUST be
  present. Unlisted or missing entries are integrity failures.
- Case packs: the nested `bundles/<id>/hash_manifest.json` files are regular
  *listed* files of the case pack (hashed by the case manifest like any other
  file); only the top-level manifest is excluded from its own coverage.

## 4. Hash chain computation

1. For every file `f` in the pack (excluding the hash manifest itself),
   compute `sha256(f_bytes)` → the per-file hash recorded in
   `files`.
2. Root hash:

   ```
   payload = "\n".join(f"{path}:{hash}" for path in sorted(files))   # sorted by arcname, UTF-8
   root_hash = sha256(payload.encode("utf-8")).hex()
   ```

   The join uses a single newline (`"\n"`) with no trailing newline; sorting
   is over the arcnames' Unicode code points (Python `sorted()`), making the
   computation order-independent.

The verifier recomputes this from the *actual bytes in the pack* (using
`"MISSING"` in place of a listed-but-absent file's hash) and compares against
the manifest's `root_hash`; a mismatch is an integrity failure.

## 5. Chain-of-custody log (`chain_of_custody.json`)

```jsonc
{
  "bundle_id": "<id>",
  "source_platform": "web",
  "content_url": "https://example.com/post/123",
  "poster_profile_url": null,
  "model_run_id": null,
  "review_queue_id": null,
  "capture_method": "live|reconstruction|manual|…",
  "capture_actor": "<who or what ran the capture>",
  "captured_at": "2026-06-20T12:00:00Z",   // capture wall-clock, producer's system clock
  "capture_timezone": "UTC",
  "items": [                               // one entry per captured item
    {
      "item_type": "html_snapshot",        // html_snapshot | thread_context | screenshot | …
      "capture_status": "captured",
      "artifact_uri": "artifacts/html_snapshot.html",
      "sha256_hash": "<64-hex>",           // REQUIRED key when captured
      "captured_at": "2026-06-20T12:00:00Z",  // REQUIRED key when captured
      "method": "<capture method detail>"
    }
  ],
  "export_events": [
    {
      "event": "evidence_pack_v0.2_export",
      "exported_at": "2026-06-20T12:00:00Z",
      "exporter": "system",
      "app_commit": "<git sha or null>"
    }
  ]
}
```

A custody entry for a captured item is *well-formed* iff `sha256_hash` and
`captured_at` are present and truthy. The custody file is itself covered by
the hash manifest like any other file, so its integrity is verified by the
same hash chain.

## 6. Capture-failure log semantics (`capture_failures.json`)

```jsonc
{
  "bundle_id": "<id>",
  "count": 1,
  "failures": [
    {
      "item_type": "screenshot",
      "capture_status": "skipped|failed|integrity_mismatch",
      "reason": "auth wall: login required"
    }
  ]
}
```

The file MUST exist even when nothing failed (`count: 0`, empty `failures`).
Its purpose is **no silent gaps**: every capture that did not produce bytes
is disclosed with a reason. `capture_status` values:

- `skipped` — a deliberate policy/config decision not to capture.
- `failed` — a capture attempt that errored.
- `integrity_mismatch` — stored bytes did not match the recorded hash at
  export time.

## 7. Review record (`review.json`)

```jsonc
{
  "review_status": "none|approved|rejected|…",
  "bundle_id": "<id>",
  "note": "bundle not linked to a review_queue item"
}
```

When a human decision exists, producers add their decision fields; the
verifier only checks the file's presence and hash, never its decision
content.

## 8. Timestamp token handling

`timestamp_status` in the hash manifest records the outcome of an RFC3161
timestamp attempt over the pack's **root hash**:

```jsonc
{
  "status": "granted|not_configured|disabled|unavailable|error",
  "provider": "https://tsa.example.org",
  "digest_algorithm": "sha256",
  "hashed_value": "<root hash that was stamped, hex>",
  "gen_time": "2026-06-20T12:00:01+00:00",
  "token_b64": "<base64 DER TimeStampToken>"     // present iff status is granted
}
```

The manifest is NOT covered by the root hash, so the token attests a value
unperturbed by the token's own presence.

Verifier behavior by `status`:

- **not `granted`** (not_configured/disabled/error/unavailable): the recorded
  status passes through as `timestamp_state`; no integrity impact.
- **`granted` but no `token_b64`**: integrity failure ("timestamp granted but
  token missing").
- **`granted` with a token**: the token is parsed as a CMS `ContentInfo`
  wrapping `SignedData`/`TSTInfo`; its `messageImprint.hashedMessage` MUST
  equal the pack root hash. A mismatch is an integrity failure ("timestamp
  attests … but pack root is …").
- With matching imprint, the verifier additionally checks (surfaced, not
  enforced):
  - the CMS `messageDigest` signed attribute equals the hash of the TSTInfo
    eContent bytes,
  - the signer's signature over the DER-encoded signed attributes verifies
    against the certificate embedded in the token (RSA PKCS#1 v1.5 with
    SHA-256/384/512),
  - with `--tsa-ca` anchors, that the signer certificate was issued directly
    by one anchor (single-hop, byte-comparable issuer/subject DN match).

Resulting `timestamp_state` values (for granted tokens): `token_verified`
(signature verified, no anchor supplied), `token_signature_verified`
(signature verified and chained to a supplied anchor), `failed` (definite
mismatch or invalid signature), `unverifiable` (token present but not
parseable/checkable by this verifier — never an integrity failure by itself).

Supported token shapes: exactly one SignerInfo with `signedAttrs` carrying
`messageDigest`; `issuerAndSerialNumber` or `subjectKeyIdentifier` signer
identifier; RSA PKCS#1 v1.5 signatures only. Anything else degrades to
`unverifiable`/`signature: unavailable` — never "failed".

## 9. Completeness and evidence stage (informational)

`pack_complete` / `pack_complete_reason` (manifest and metadata.json) and
`evidence_ladder.pack_stage` (metadata.json) are producer claims, surfaced by
the verifier in human and `--json` output but never part of the pass/fail
axis. A verified-but-incomplete pack still exits 0 with a warning.

## 10. Versioning

`pack_version` is `"0.2"` for per-bundle packs and `"case-v0.2"` for case
packs. The format is additive: a verifier MUST ignore manifest keys it does
not recognize, and a producer MUST NOT change the semantics of the keys
defined here.
