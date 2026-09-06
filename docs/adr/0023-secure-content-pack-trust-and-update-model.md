# ADR-0023 — Secure Content-Pack Trust and Update Model

**Status:** Accepted — Architecture Authority approved under the project-wide continuation mandate, 2026-09-06
**Decision scope:** Phase 5.5 Offline Pack Runtime / Shared Core
**Baseline main:** `ff615da0510646314247e06a6f684439cb54efb5`

## Context

Phase 5.3 terminates at `PACK_READY`; it deliberately does not sign, release, install, activate, or roll back content packs. Phase 5.4 produces a deterministic, disposable SQLite/FTS5 search index bound to an authoritative Search Projection Corpus (SPC). Phase 5.5 must turn reviewed content into an offline-installable artifact without inventing a weak bespoke updater or turning derived indexes into canonical truth.

Atlas must resist malicious or compromised distribution infrastructure, stale metadata, mix-and-match repositories, rollback, partial/corrupt transfers, arbitrary executable payloads, and local activation failures. It must also preserve Last Known Good (LKG) and work without a mandatory network connection at query time.

## Decision

Atlas adopts **The Update Framework (TUF) 1.0.35 security model** as the trust/update metadata architecture for content packs.

Official specification reference:

- `https://theupdateframework.github.io/specification/latest/`
- reviewed specification version: `1.0.35`, last modified 2026-07-15.

Atlas will document its concrete TUF choices as an Atlas POUF/profile and will use conformant TUF libraries rather than implementing signature verification, threshold counting, root rotation, metadata-chain verification, rollback protection, or delegation matching from scratch.

### Mandatory TUF roles

Every production Atlas repository/pack trust set uses the four mandatory top-level roles:

- Root;
- Targets;
- Snapshot;
- Timestamp.

Production policy minimums:

| Role | Minimum keys | Signature threshold | Key posture |
|---|---:|---:|---|
| Root | 3 | 2 | independently controlled and offline |
| Targets | 3 | 2 | release-controlled; offline-capable strongly preferred |
| Snapshot | 1 | 1 | automation/online permitted |
| Timestamp | 1 | 1 | automation/online permitted |

The fixture/test profile may use 1-of-1 keys, but test keys/seeds are explicitly non-production and can never establish production trust.

Root trust is bootstrapped from trusted root metadata shipped/installed with the application or via a separately authenticated administrative channel. Atlas does not derive its TUF root of trust from Web PKI.

### Algorithms

The Atlas v1 trust profile requires SHA-256 target hashes and supports TUF-mandated interoperable signature schemes. The reference/test signing profile uses Ed25519. A production key-management provider is **not** selected by this ADR; it must satisfy the role/threshold/isolation policy without committing private keys to the repository, pack, client binary, logs, or CI artifacts.

### Content pack transport

The canonical offline transport is a single file with extension:

```text
.atlaspack
```

An `.atlaspack` is a ZIP-compatible transport container with a strict Atlas extraction profile. The archive itself is **not** the security root and is not trusted merely because the ZIP bytes have a signature. Trust derives from TUF metadata and verified target hashes/lengths plus Atlas pack-contract validation.

Required logical layout:

```text
metadata/
  root.json
  timestamp.json
  snapshot.json
  targets.json
  [delegated-role.json ...]
targets/
  atlas/pack-manifest.json
  atlas/source-license-inventory.json
  content/...
  search/...
```

Consistent snapshots are enabled for production repositories. Target naming inside self-contained transports must remain unambiguous and content-verifiable.

### Pack payload is data, not executable code

Atlas content packs may carry canonical knowledge data, source/license inventories, coverage/provenance artifacts and rebuildable derived search/index data. Pack v1 **must not** deliver executables, scripts intended for execution, DLL/shared libraries, drivers, installers, macros, or other active code.

Application binary updates are outside the content-pack trust boundary and require a separate code-signing/release architecture.

### Offline activation semantics

Offline does not mean freshness checks are bypassed.

For activation, Atlas requires:

1. a trusted TUF root chain;
2. valid threshold signatures;
3. non-expired trusted metadata according to the trusted local time policy;
4. rollback/version monotonicity checks against durable runtime state;
5. verified target lengths and SHA-256 hashes;
6. Atlas pack-contract, compatibility, schema, source/license and health validation.

Expired metadata may be opened only in an explicit **inspection-only** path. Inspection-only never changes active/LKG state and never makes the content available to production search/runtime APIs.

A local-clock rollback or state loss that prevents reliable freshness/rollback evaluation fails closed for activation and requires an administrative recovery procedure; Atlas does not silently weaken TUF to accommodate an uncertain clock.

### Strict archive extraction

Before any TUF target is exposed to validators, extraction must reject:

- absolute paths, drive-qualified paths and `..` traversal;
- backslashes or alternate separators in archive target names;
- symlinks, hardlinks, reparse-point-like entries and special/device files;
- duplicate paths after Atlas normalization, including Windows case-insensitive collisions;
- encrypted ZIP members;
- unsupported compression/encryption methods;
- reserved Windows device names;
- excessive file count, per-file uncompressed size, aggregate uncompressed size, or decompression ratio;
- any entry outside `metadata/` and `targets/`.

Initial v1 safety envelope is enforced by runtime constants and is versioned independently from canonical schemas.

### Atomic installation and Last Known Good

The installer uses immutable staging and never mutates the active installation in place:

```text
receive -> bounded extract -> TUF verify -> Atlas contract verify
-> compatibility/license/schema validation -> search/index validation/rebuild
-> health check -> immutable install generation -> atomic active-pointer swap
-> post-activation health check -> commit LKG
```

Any pre-activation failure leaves the current active/LKG generation untouched. A failed post-activation health check atomically restores the previous LKG and records a rollback report.

### Authority boundary

Canonical Atlas records remain authoritative. Search/SPC/SQLite artifacts are derived and disposable. A pack may include a prebuilt search index for startup speed only when it is cryptographically bound to the same trusted SPC/corpus and independently validates under the accepted search runtime. The runtime must be able to reject/rebuild it without losing canonical content.

### Licensing/publication boundary

Every releasable pack includes a machine-readable `source-license-inventory.json`. Unknown, incompatible, missing, or insufficient redistribution rights are a non-waivable publication failure. TUF authenticity does not imply legal redistribution permission or canonical truth.

### No private keys in repository

Production private keys and signing credentials are forbidden from Git history, fixtures, packs, client state and CI artifacts. Key identifiers and public keys/metadata are expected. Test-only signing material must be unmistakably non-production and accepted only by test trust roots.

## Rejected alternatives

### Single detached signature over ZIP

Rejected. It does not by itself provide robust rollback/freeze/mix-and-match protection, role separation, threshold trust or standardized root rotation.

### TLS/code-host trust only

Rejected. Distribution transport and repository compromise are inside the threat model; core trust must not rely on a mirror or TLS endpoint remaining honest.

### Custom Atlas PKI/update protocol

Rejected. It would duplicate mature, security-sensitive functionality and increase implementation/audit risk.

### Sign only the prebuilt SQLite database

Rejected. SQLite search state is derived and cannot become canonical content authority.

## Consequences

- Phase 5.5.2 will use a maintained conformant TUF implementation and pin dependency versions for reproducibility.
- The Python reference implementation must use `python-tuf >= 7.0.0`; the Phase 5.5.2 spike begins with exact pin `tuf==7.0.0` because <=6.0.0 has a published Windows delegation-path matching vulnerability.
- Production Shared Core language/library selection remains a separate evidence-based ADR.
- Pack key-management vendor/HSM/KMS selection remains deployment-specific and is not frozen here.
- `.atlaspack` extraction and installation semantics are Atlas responsibilities because TUF intentionally treats target files as opaque and does not define package installation.

## Security invariants

1. No content activation without a trusted root chain and valid current metadata.
2. No rollback to a pack or metadata version lower than durable highest-seen state.
3. No pack content executes during verification, projection, indexing, health checks, or installation.
4. No archive pathname is trusted before normalization and bounds checks.
5. No derived search/index artifact can override canonical identity or provenance.
6. No unknown/ambiguous third-party licensing can pass a public publication gate.
7. No production private signing key may be stored in source control.
