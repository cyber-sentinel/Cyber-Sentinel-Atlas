# ATLAS Workspace Product Review

Status: **PRODUCT REVIEW BASELINE / FINAL VISUAL FREEZE NOT YET AUTHORIZED**

This document converts the approved five-workspace ATLAS desktop model into a page-by-page product review checklist for international release quality.

It intentionally separates **current First Preview capability** from **post-preview candidates** so visual design does not accidentally promise functionality outside the frozen command boundary.

## Review method

Every workspace must be reviewed with the maintainer before final visual freeze.

For each page, approval covers:

- mission and analyst problem;
- information hierarchy;
- visible data fields;
- actions/buttons;
- navigation;
- trust/provenance behavior;
- empty/loading/error states;
- keyboard/accessibility;
- terminology;
- visual density;
- features deferred because they require new Core/API/persistence capabilities.

## Workspace 1 — Investigate

**Primary mission:** deterministic offline discovery.

Current release-critical content:

- large search input;
- exact/alias/lexical result behavior;
- result count/limit;
- result rows with type/source/context;
- selected-result Quick Detail;
- open canonical record;
- graph/relationship pivot through approved navigation;
- clear offline, pack-ready and core-health status.

International-market review questions:

- are result types understandable without product training?
- are provider/product/channel/version distinctions obvious?
- can an analyst identify why a result matched?
- are no-result and pack-not-ready states unambiguous?
- are keyboard-first actions discoverable?

Post-preview candidates: advanced filters, saved/recent searches, richer export, expanded command palette.

## Workspace 2 — Record & Provenance

**Primary mission:** explain the canonical record and prove its claims.

Current release-critical content:

- canonical identity/title/type;
- provider/platform/product/channel/version applicability;
- technical meaning;
- security significance where corpus evidence permits;
- claims;
- sources;
- source revision/version;
- validation/provenance state;
- relationships/navigation.

International-market review questions:

- can a reviewer distinguish ATLAS-authored interpretation from source-derived facts?
- can every material claim be traced?
- are unavailable fields clearly absent rather than displayed as placeholders?
- does source/version context remain readable on smaller displays?

Post-preview candidates: analyst notes, annotations, customer overlays, export/report workflows.

## Workspace 3 — Relationships

**Primary mission:** bounded knowledge navigation.

Current release-critical content:

- selected center node;
- typed edges;
- bounded expansion;
- node selection/detail;
- relationship provenance/context;
- open canonical record.

International-market review questions:

- does the graph avoid implying live attack activity?
- do edge labels explain the relationship?
- is color supplemented by shape/text?
- can dense graphs remain understandable and bounded?
- are unsupported inference/causality claims avoided?

Post-preview candidates: saved views, path tracing, advanced filtering/depth controls, exports, larger graph analytics.

## Workspace 4 — Pack Control

**Primary mission:** expose content trust and lifecycle.

Current release-critical content:

- active verified pack;
- pack identity/version;
- trust/verification state;
- update action;
- rollback action;
- failure state;
- distinction between content-pack lifecycle and application binary lifecycle.

International-market review questions:

- can the user understand why a pack is or is not trusted?
- is Last Known Good behavior understandable?
- can rollback be distinguished from downgrade/anti-rollback violations?
- are trust failures fail-closed and actionable?

Post-preview candidates: manual import, rich source inventory, advanced TUF diagnostics, enterprise repository/policy controls.

## Workspace 5 — Diagnostics

**Primary mission:** local product health and supportability.

Current release-critical content:

- desktop/core state;
- protocol/core identity;
- sidecar integrity state;
- pack readiness;
- available search/index health;
- network-listener posture;
- safe operational errors.

International-market review questions:

- can first-line support identify the failing component?
- do diagnostics avoid leaking secrets/sensitive paths unnecessarily?
- are errors actionable?
- can the user distinguish app, core, pack and index failures?

Post-preview candidates: support bundle export, deep performance telemetry, automated repair, advanced log viewer.

## Cross-product visual requirements

Approved direction:

- professional cyber-intelligence / command-center aesthetic;
- dark design with restrained tactical visual language;
- readable typography and large enough information elements;
- no gaming/neon overload;
- no generic SaaS dashboard look;
- ATLAS Blue theme;
- Tactical Dark Green theme;
- subtle satellite/geographic identity when used;
- Iran geography must be geographically accurate when represented;
- Damavand may appear as a dim identity element with restrained dawn light;
- artwork may change after functional freeze as long as behavior/security boundaries do not drift.

## Finalization gate

A workspace is visually frozen only after:

```text
Functional review
    ↓
Data-field review
    ↓
Action/security-boundary review
    ↓
Empty/error/accessibility review
    ↓
Maintainer approval
    ↓
Final visual design
    ↓
Executable regression + accessibility acceptance
```
