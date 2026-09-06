# ADR-0024 — Production Shared Core Technology Selection

**Status:** Proposed

## Context

ADR-0006 requires an implementation spike before Atlas selects the production Shared Core technology. Phase 5.4 froze deterministic search semantics and selected SQLite + FTS5 for the derived production search artifact. ADR-0023 and Phase 5.5.2 froze and proved the secure content-pack trust/runtime behavior through an executable Python reference implementation.

The Windows Desktop MVP now needs a production Shared Core that can implement those contracts without becoming a second source of truth or forcing future Web/PWA, API or CLI interfaces to reimplement security/search semantics independently.

The current Python implementation is executable evidence, not an automatic production-language decision.

## Decision to be made

Select the production implementation language/runtime and its minimum core dependency profile for:

- canonical/read model access;
- deterministic SQLite/FTS5 search;
- bounded relationship navigation;
- Atlas TUF POUF v1 pack verification;
- immutable install/activation/LKG/rollback state;
- stable bindings/interfaces consumed by Windows Desktop and later interfaces.

The decision does **not** select the Desktop UI framework, broader application storage, graph database, HSM/KMS provider, application updater, CDN/distribution topology, Detection IR or Grounded AI runtime.

## Candidates

Architecture screening covers:

- Rust;
- Go;
- Python as reference/control;
- TypeScript/Node.js;
- .NET/C#.

The initial executable finalists are Rust, Go and Python control, subject to the hard-gate rules in `docs/architecture/phase-5.5.3-shared-core-technology-spike.md`.

## Mandatory evidence

No candidate can be selected without reproducible Linux and Windows evidence for:

- canonical and digest interoperability;
- Phase 5.4 exact/lexical search parity;
- SQLite + FTS5 availability and deterministic behavior;
- TUF/Atlas POUF v1 conformance including adversarial rollback/tamper cases;
- offline/no-network operation;
- atomic durable state and Last Known Good rollback semantics;
- binary/runtime footprint and build reproducibility;
- supply-chain/dependency inventory;
- compatibility with the Windows Desktop MVP while preserving reusable core contracts.

A mandatory gate failure disqualifies a candidate regardless of weighted score.

## Serialization/digest guard

Cross-language canonical serialization is a protocol boundary, not an implementation detail. The spike must compare existing Atlas deterministic JSON bytes with a standards-based canonical representation such as RFC 8785/JCS and identify all byte-level differences.

This ADR must not silently migrate existing digests. If a serialization migration is required, it needs an explicit accepted architecture decision, versioning/migration rules and compatibility evidence before ADR-0024 can be accepted.

## Decision criteria

Candidates passing all hard gates are scored using the Phase 5.5.3 weighted matrix:

- contract/security fidelity — 30%;
- TUF/pack trust maturity and fit — 20%;
- SQLite/FTS5 performance and operational fit — 15%;
- Windows/Linux durability and portability — 10%;
- binary/runtime/dependency footprint — 10%;
- Desktop/API/CLI integration fit — 10%;
- maintainability/ecosystem/supply-chain surface — 5%.

Scores must cite executable evidence or authoritative upstream facts.

## Current evidence observations — not a selection

At architecture-gate time:

- Python is the already-proven Atlas semantic/control implementation and uses the current `python-tuf` trust path, but its production packaging/embedding/footprint still needs measurement.
- Go has an official `go-tuf/v2` client implementation and CGo-free SQLite options capable of FTS5, but Atlas-specific contract parity and Desktop integration still need execution evidence.
- Rust has strong native/embedded characteristics and mature SQLite bindings; however, available Rust TUF choices have material maturity/feature caveats that must be measured against Atlas POUF v1 rather than ignored.
- TypeScript/Node.js has an official TUF implementation and interface-ecosystem alignment, but native runtime/SQLite/durability/security-boundary costs require evidence.
- .NET/C# is strong for Windows/native APIs, but its TUF implementation/conformance path and cross-interface reuse require evidence before it can outrank executable finalists.

These observations justify the spike order only. They do not establish the winner.

## Revisit triggers after acceptance

The eventual accepted decision must define revisit triggers. At minimum, reopen the technology decision if:

- a mandatory security/conformance property cannot be maintained in production;
- required TUF features exceed the selected client implementation's supported profile;
- Windows Desktop embedding or portable mode becomes materially infeasible;
- corpus/pack scale invalidates measured performance/footprint assumptions;
- future API/CLI/Web reuse requires a different boundary than the selected core can expose safely;
- a dependency becomes unmaintained or suffers a security issue that cannot be mitigated within the selected stack.

## Consequences while Proposed

- no production Shared Core language/runtime is frozen;
- spike code must live in isolated benchmark/reference directories and must not replace accepted production contracts;
- canonical `schemas/v1/` must remain unchanged;
- the existing Python runtime remains the executable semantic oracle until parity evidence proves another implementation;
- Phase 5.6 Windows Desktop implementation must not begin by embedding an unselected Shared Core stack.
