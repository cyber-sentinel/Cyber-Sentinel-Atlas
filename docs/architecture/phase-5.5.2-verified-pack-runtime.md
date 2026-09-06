# Phase 5.5.2 — Verified Pack Runtime

Status: **COMPLETE / MERGED / POST-MERGE VERIFIED**

Baseline main: `a21b619c605e94c6bd9896e639acd574fe969b12`

Feature head: `7d97434fad8749a5fc791ae1a0543760a9f74fd0`

Merge commit: `9a8f9f30a937d546ed08a205d19998bbbd1ed0d9`

PR: `#20` — Phase 5.5.2: Verified Pack Runtime

## Purpose

Phase 5.5.2 implements the first executable reference runtime for the accepted Phase 5.5.1 trust model. It turns an untrusted `.atlaspack` transport into a verified immutable generation without weakening the authority boundaries already frozen by ADR-0023.

The implementation is intentionally a **Python reference/runtime implementation** under `tools/pack/`. It does **not** select the future production Shared Core language.

## Trusted flow

```text
untrusted .atlaspack
  -> bounded archive preflight
  -> safe extraction into private staging
  -> persistent trusted-time rollback guard
  -> offline TUF refresh/verification using trusted bootstrap root
  -> TUF-verified Pack Manifest target
  -> TUF-verified Source/License Inventory target
  -> exact-byte Atlas contract validation
  -> TUF-verified declared artifact targets
  -> Atlas artifact digest/length validation
  -> canonical AtlasRecord schema validation
  -> SPC/search-index validation or local deterministic rebuild
  -> immutable generation staging
  -> rollback/version guard
  -> atomic active-state swap
  -> post-activation health check
  -> LKG commit or atomic rollback
```

No pack target executes at any stage.

## Security boundaries

### Archive layer

Archive extraction is fail-closed and permits only `metadata/` and `targets/` namespaces. It rejects:

- absolute, drive-qualified, traversal, backslash and non-canonical paths;
- Unicode-normalization and case-insensitive collisions;
- Windows reserved or ambiguous path components;
- symlinks, special files and Windows reparse-point attributes;
- encrypted members;
- unsupported compression methods;
- duplicate names;
- excessive entry count, per-file size, aggregate size and compression ratio;
- active-code extensions under target payloads.

The final cross-platform hardening also compares `ZipInfo.orig_filename` with the parser-exposed `ZipInfo.filename`. If the host ZIP parser sanitizes or mutates a wire-level member name before validation — including Windows backslash normalization or NUL truncation behavior — Atlas rejects the member rather than validating the repaired representation.

The safety envelope is represented by a versioned/configurable runtime dataclass. The defaults are reference defaults, not a future product-capacity commitment.

### TUF layer

The verifier uses `python-tuf` `ngclient.Updater` with exact direct dependency pin `tuf==7.0.0`. A custom local-only fetcher serves only files from the extracted pack; no network fetch is possible through the Atlas verifier.

The bootstrap root is supplied out-of-band by the caller. The writable TUF metadata cache is durable runtime state and is kept across installations so python-tuf can enforce metadata rollback/freshness rules across pack attempts. The permanent regression suite explicitly proves that after a newer signed metadata version has been trusted, replaying the previously valid older metadata fails closed.

The local fetcher supports TUF consistent-snapshot requests while keeping the `.atlaspack` logical layout readable. It may map version-prefixed metadata and hash-prefixed target requests only to the corresponding local file; python-tuf still performs the signed version/hash/length verification.

### Atlas contract layer

After TUF authenticates control targets, Atlas additionally enforces:

- exact `pack_id` and `pack_version` agreement;
- exact-byte SHA-256 binding of `source-license-inventory.json`;
- public publication/license fail-closed policy;
- exact artifact length and SHA-256 against the manifest;
- exactly one canonical-records artifact and one SPC artifact;
- top-level canonical/SPC digest fields matching those artifacts;
- no undeclared files under `targets/`;
- runtime compatibility via strict SemVer precedence.

Activation has no inspection/non-publication mode. Untrusted transport activation always performs publication-grade licensing and trust checks; inspection remains a separate verification boundary.

### Canonical/search health

Canonical records are validated offline against the repository-local `schemas/v1` registry through the aggregate `AtlasRecord` schema. No schema reference is fetched over the network.

SPC is validated through the existing Phase 5.4 projection contract. A supplied SQLite/FTS5 search index is opened through the accepted Phase 5.4.3 read-only validation path. If the signed prebuilt index is stale/corrupt/misbound, it is never trusted as canonical state: the runtime deterministically rebuilds a local derived index from the verified SPC and validates the rebuilt index before activation.

The rebuilt index is kept under runtime-derived state and is not represented as a signed TUF target.

## Durable runtime state

Runtime state is stored atomically as JSON and includes:

- active generation;
- Last Known Good generation;
- highest-seen Atlas pack version and manifest digest per pack ID.

TUF metadata rollback state remains in python-tuf's durable metadata cache.

A separate `trusted-time.json` persists the highest observed UTC wall-clock value. The runtime uses a zero-tolerance rollback profile for the reference implementation: an observed time lower than the durable floor fails closed, and a missing trusted-time file while other durable trust state exists is treated as administrative recovery rather than silently recreating trust state.

A process lock is acquired with exclusive-create semantics. A stale lock is a fail-closed administrative recovery condition; it is never silently removed by the runtime.

Runtime state and generation metadata use strict structures and exact digest/identifier formats; corrupt, unexpected or ambiguous state is rejected rather than repaired automatically.

For Atlas pack-version rollback protection:

- a lower SemVer than highest-seen is rejected;
- the same version is accepted only when the exact verified manifest digest is identical;
- a higher verified version advances highest-seen state before active-pointer publication;
- rollback after failed post-activation health returns to the previous LKG without lowering highest-seen trust state.

## Atomic activation

Generations are installed under immutable generation directories. Runtime state is published using write-temp + flush/fsync + `os.replace()` on the same filesystem.

Activation sequence:

```text
verified generation
  -> pre-activation health
  -> persist highest-seen guard
  -> atomic active generation update
  -> post-activation health via active resolution
  -> success: active=LKG=new generation
  -> failure: active=previous LKG, LKG unchanged, rollback report recorded
```

## Verified builder

The Phase 5.5.2 builder does **not** sign TUF metadata and does not handle production private keys. It accepts an already signed repository-layout directory, verifies it against a caller-supplied trusted bootstrap root, writes a deterministic ZIP-compatible `.atlaspack` transport, re-extracts it through the production safe extractor, and verifies the produced transport again before atomic publication.

This keeps key-management/HSM/KMS decisions outside this slice.

## Explicit non-goals

Phase 5.5.2 does not freeze:

- production Shared Core implementation language;
- HSM/KMS/signing-provider selection;
- application binary update architecture;
- Desktop installer technology;
- Web/PWA packaging;
- remote repository distribution/CDN topology;
- semantic/vector model distribution.

## Closure evidence

The exact reviewed feature head was `7d97434fad8749a5fc791ae1a0543760a9f74fd0`. PR-triggered CI passed on that exact head before merge:

- Phase 5.5.2 Verified Pack Runtime — Linux + Windows: **PASS**;
- Phase 5.5.1 Pack Trust Contracts regression: **PASS**;
- Foundation Hygiene: **PASS**;
- canonical `schemas/v1/` unchanged: **PASS**.

PR #20 was merged using a Merge Commit with expected-head protection. The resulting `main` commit is `9a8f9f30a937d546ed08a205d19998bbbd1ed0d9`, whose parents are the prior `main` and the exact reviewed feature head.

Post-merge workflows on that exact `main` commit also passed:

- Phase 5.5.2 Verified Pack Runtime: **PASS**;
- Phase 5.5.1 Pack Trust Contracts: **PASS**;
- Foundation Hygiene: **PASS**;
- Phase 5.3.4 source canaries: **PASS**.

## Exit criteria result

Phase 5.5.2 is closed. The merged implementation demonstrates on Linux and Windows:

- secure archive extraction positive and adversarial cases;
- TUF valid pack verification;
- TUF signature/hash/freshness and persistent metadata rollback failure cases;
- offline/no-network fetch enforcement;
- exact control/artifact binding;
- canonical schema validation;
- search-index validation and deterministic rebuild fallback;
- pack-version rollback/version-reuse protection;
- trusted wall-clock rollback/state-loss protection;
- atomic activation/LKG rollback behavior;
- builder round-trip verification;
- parser-sanitization rejection for non-canonical archive member names;
- no `schemas/v1/` change;
- no production private key or secret committed to the repository.

The remaining Phase 5.5 material architecture work is the production Shared Core technology spike and ADR; Phase 5.5.2 itself does not select that technology.
