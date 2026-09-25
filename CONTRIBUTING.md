# Contributing

Thanks for your interest in `evidence-verify`.

## Ground rules

- **Standard library only.** The verifier must stay dependency-free and fully
  offline — `requests`, `cryptography`, `asn1crypto`, etc. are out of scope
  for `evidence_verify/`. If a feature needs them, it belongs in a separate
  tool.
- **No claims the code does not earn.** Do not rename
  `token_signature_verified` to anything containing "qualified", do not add
  marketing adjectives about evidentiary strength to the docs, and do not
  describe the single-hop `--tsa-ca` check as full chain validation. A
  claim-honesty test enforces the first one; reviewers enforce the rest.
- **Keep the pass/fail axis narrow.** Integrity failures are: hash mismatch,
  root-hash mismatch, missing/extra files, granted-but-missing token, token
  imprint mismatch, invalid token signature. Everything else is surfaced,
  not enforced. Think hard before widening this set.

## Workflow

1. Fork/clone; run the suite first:
   `python -m unittest discover -s tests` (29 tests, no dependencies).
2. Make your change with tests. New failure modes need a test that fails
   without the fix.
3. Ensure `python -m evidence_verify examples/demo-pack` still exits 0.
4. Open a PR describing what changed and why. Commits: DCO sign-off
   (`git commit -s`, `Signed-off-by: Name <email>`) required — you keep the
   copyright to your contribution and grant a license under Apache-2.0.

## Scope

In scope: verifier correctness, spec (PACK-FORMAT.md) clarifications,
interop fixes for real-world tokens, tests, docs.
Out of scope (for now): pack production beyond the demo builder, network
fetching, GUIs.
