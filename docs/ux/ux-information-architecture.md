# ATLAS UX Information Architecture

Status: **APPROVED FIRST-PREVIEW WORKSPACE MODEL / VISUAL IDENTITY OPEN**

## UX objective

ATLAS should behave like a focused cyber-defense investigation instrument, not a generic documentation portal, executive dashboard, SIEM replacement, or AI chat shell.

The First Preview desktop information architecture is intentionally constrained to five primary workspaces:

```text
ATLAS
├── Investigate
├── Record & Provenance
├── Relationships
├── Pack Control
└── Diagnostics
```

No additional top-level page is part of the frozen `v0.1.0-rc.1` functional boundary unless the freeze is explicitly reset.

## Persistent application shell

The five workspaces share one shell:

- ATLAS product identity;
- persistent left navigation;
- offline / knowledge-pack / core health state;
- clear selected-workspace state;
- consistent keyboard focus and accessibility behavior;
- status/footer information that does not imply cloud connectivity;
- visual identity that can evolve without redefining product behavior.

Approved visual themes:

- **ATLAS Blue** — primary product theme;
- **Tactical Dark Green** — approved alternate theme.

Logo, header/banner art, Iran/satellite visual identity, Damavand imagery, spacing, typography, icons and other non-behavioral presentation remain outside the functional freeze and may be refined later.

## 1. Investigate

### Mission

Provide the fastest deterministic entry point from an identifier, term, technique, telemetry concept, or alias to relevant canonical ATLAS knowledge.

### First Preview services

- exact-before-lexical search;
- offline search against the active verified pack;
- record type/source context in result rows;
- bounded result count;
- Quick Detail for the selected result;
- open selected canonical record;
- navigate to related knowledge through the existing record/graph flow;
- clear pack/core readiness state;
- keyboard-accessible result navigation.

### Product-quality states

The page must distinguish:

- ready with active verified pack;
- no result;
- ambiguous/scoped result;
- invalid query;
- pack unavailable;
- pack rejected / trust failure;
- Shared Core unavailable.

An error state must never silently fall back to network search.

### Post-preview candidates

Saved searches, persistent recent history, command palette expansion, advanced filtering and richer export are useful candidates, but any feature requiring new Shared Core commands or persistent state is outside the frozen seven-command First Preview boundary until separately approved.

## 2. Record & Provenance

### Mission

Present one canonical security record together with the evidence needed to understand and defend its technical claims.

### First Preview services

- canonical identity;
- record/entity type;
- provider/platform/product context;
- applicability/version context present in the pack;
- technical meaning;
- claim/source provenance;
- record relationships available through the bounded graph;
- clear validation/trust state;
- source/version references contained in the active pack;
- navigation back to investigation results and into relationships.

### UX rule

Provenance is a primary product surface, not a hidden metadata drawer.

Material technical claims should make it straightforward to answer:

```text
What is being claimed?
Which source supports it?
Which source revision/version applies?
What ATLAS record/claim carries it?
What is the validation state?
```

### Content organization

Detailed content may be grouped visually into sections/tabs such as Overview, Technical Data, Relationships, Defensive Context and References only when the underlying pack contains those facts. Empty decorative tabs must not imply unavailable content.

### Post-preview candidates

Analyst notes, annotations, richer exports and workflow handoff may be added later under an explicit persistence/authorization design.

## 3. Relationships

### Mission

Provide bounded deterministic knowledge-graph navigation around the selected record without presenting inference as fact.

### First Preview services

- selected canonical node;
- bounded graph expansion;
- typed relationships;
- node detail;
- deterministic relationship traversal;
- provenance-aware relationship context where present;
- return/open canonical record.

### Graph semantics

The graph is a **knowledge relationship graph**, not live SIEM telemetry and not automatic attack attribution.

Visual differentiation may distinguish categories such as:

- telemetry/event/entity;
- ATT&CK/adversary behavior;
- D3FEND/defensive knowledge;
- CAR/analytic context;
- provider/source/metadata.

Color alone must not be the only semantic signal.

### Post-preview candidates

Path tracing, saved graph views, richer depth/type controls, exports and large-graph analysis may be added after explicit performance and command/API review.

## 4. Pack Control

### Mission

Make ATLAS content trust, active-pack identity, verification and safe lifecycle behavior visible and understandable.

### First Preview services

- active pack state;
- pack identity/version;
- verified/trust state;
- controlled pack update through the frozen command boundary;
- safe rollback through the frozen command boundary;
- clear fail-closed errors;
- visible distinction between content-pack update and application-binary update.

### Trust principles

The interface must never equate "downloaded" with "trusted" or "installed" with "active".

The lifecycle remains:

```text
candidate
  ↓
verified
  ↓
installed immutable generation
  ↓
health gate
  ↓
active
  ↓
Last Known Good / rollback when required
```

Application binary auto-update remains disabled for the initial Public Preview.

### Post-preview candidates

Manual pack import, richer source-by-source corpus inspection and advanced trust diagnostics require explicit command/security review if they exceed the current seven-command surface.

## 5. Diagnostics

### Mission

Explain whether the local ATLAS product is healthy and provide actionable, non-secret operational diagnostics.

### First Preview services

- Shared Core availability;
- core/protocol version context;
- active-pack readiness;
- executable/sidecar integrity state;
- search/index readiness where exposed by the bounded core status;
- no-default-listener posture;
- application/runtime status;
- safe error presentation.

### Diagnostic design rule

Diagnostics must help support/troubleshooting without exposing secrets, key material, sensitive host data, or unrestricted filesystem/process controls.

### Post-preview candidates

Exportable support bundles, deep performance telemetry, automated repair and richer log exploration require separate privacy/security design before entering a release boundary.

## Cross-workspace interaction rules

- keyboard navigation is first-class;
- focus must remain visible;
- copy actions should be explicit where safe;
- loading states must not look like successful empty results;
- security-significant errors use clear text, not color alone;
- no workflow should require hidden network access;
- every externally sourced technical fact remains attributable;
- dangerous/destructive controls must not be introduced as presentation-only shortcuts;
- responsive behavior must preserve labels and critical state rather than collapsing them into ambiguous icons.

## International product-readiness review

Before final visual freeze, each workspace must be reviewed page-by-page for:

1. user mission;
2. required inputs;
3. primary actions;
4. outputs;
5. evidence/provenance presentation;
6. empty/loading/error states;
7. keyboard/accessibility behavior;
8. security/trust implications;
9. telemetry/data dependencies;
10. functions that require a new command/API/persistence boundary.

This review happens before final artwork, iconography and visual polish are considered frozen.

## AI UX

Grounded AI remains deferred beyond the First Preview. No AI chat panel is part of the current five-workspace desktop release boundary.

When a later AI surface is approved, it must expose evidence, referenced entities, uncertainty and canonical-vs-generated state rather than presenting generated output as ATLAS canonical truth.
