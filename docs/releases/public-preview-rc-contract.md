# Public Preview Release Candidate Contract — Phase 5.10.7

Status: **FUNCTIONALLY FROZEN / RC EVIDENCE BLOCKED**

Target candidate: `v0.1.0-rc.1`

Functional-freeze baseline: `main@2c7788e08e0254f330cca1cbb0d1a8a9432291f5`

This contract freezes the ATLAS Public Preview feature and security boundary while deliberately leaving the visual identity surface open for approved branding and presentation refinement.

## Freeze objective

The next Public Preview candidate is no longer a feature-development vehicle. Work on the candidate is restricted to release closure, security/accessibility correction, defect repair, evidence production, and non-behavioral visual refinement.

The freeze exists to keep source, package, notices, accessibility evidence, signatures, hashes, and publication bytes convergent on one reviewable candidate.

## Frozen functional boundary

The following are frozen for `v0.1.0-rc.1` unless a documented freeze reset is approved:

- canonical schema `1.0.0` and exactly seven AtlasRecord families;
- deterministic SQLite + FTS5 exact-before-lexical search semantics;
- bounded relationship / graph behavior;
- TUF content-pack trust, trusted-time, anti-rollback, immutable generation and Last Known Good semantics;
- Go Shared Core authority;
- `atlas-core/1.0.0` bounded child-process stdio protocol;
- exactly seven desktop application commands: `core_status`, `search_records`, `get_record`, `expand_graph`, `pack_status`, `pack_update`, `pack_rollback`;
- Tauri 2.x Windows desktop host;
- no default local HTTP/TCP/WebSocket listener;
- CSP `connect-src 'none'`;
- no Tauri plugin surface;
- no generic frontend-controlled Shared Core method bridge;
- signed portable ZIP as the Public Preview distribution format;
- GitHub Releases as the canonical Public Preview publication channel;
- binary auto-update disabled for the initial Public Preview.

## Visual identity remains intentionally open

The following may change after functional freeze when they do not alter the security, trust, storage, IPC, search, graph, or update boundaries:

- ATLAS logo and trademark artwork;
- application banner/header artwork;
- geographic/satellite visual assets;
- typography, spacing and iconography;
- CSS design tokens;
- ATLAS Blue and Tactical Dark Green presentation themes;
- non-semantic animation or visual polish;
- product wording and presentation copy.

Any visual change that touches executable UI code must rerun applicable desktop, accessibility, packaging and exact-head regression workflows.

Visual refinement does **not** authorize a new application command, network capability, plugin, trust store, data model, search behavior, or pack behavior.

## Changes allowed after freeze

Allowed change classes are security fixes, correctness/crash fixes, release-engineering and packaging fixes, accessibility fixes, legal/licensing/attribution closure, production-signing integration conforming to PPR-05, public-pack corpus/notices/freshness closure, non-behavioral visual identity/theme refinement, and documentation corrections.

Every change remains subject to normal PR, exact-head CI and release evidence.

## Freeze-reset conditions

The candidate freeze must be reset if a change introduces or modifies the canonical record/schema semantics, Shared Core method or protocol framing, desktop command allowlist, search or graph semantics, pack trust/rollback, default network behavior, Tauri plugin/capability surface, persistent storage authority, binary update mechanism, a new top-level functional product module, or Grounded AI/broader API/Web/PWA/new OS surfaces.

A freeze reset requires a new reviewed baseline and invalidates package-bound evidence that depends on the prior executable bytes.

## RC naming rule

The repository may prepare an RC staging branch and rehearsal package while blockers remain, but the project must not create or publish `v0.1.0-rc.1` as an approved Public Preview candidate until the strict RC gate passes.

Strict RC authority requires every mandatory PPR gate to PASS, the exact signed package and release commit to be recorded, the public corpus and final notices/SBOM/release notes to be package-bound, clean-Windows and accessibility acceptance to run against the same package SHA, and publication bytes to be reverified before promotion.

## Candidate sequence

```text
FUNCTIONAL FREEZE
        ↓
license decision / PPR-03
        ↓
public corpus + notices closure / PPR-04
        ↓
production signing authority / PPR-05
        ↓
exact signed portable ZIP
        ↓
clean Windows + accessibility on same SHA
        ↓
strict RC gate
        ↓
v0.1.0-rc.1
        ↓
publication verification
        ↓
Public Preview promotion
```

The functional freeze does not convert any currently blocked PPR gate into PASS and does not grant release authority.
