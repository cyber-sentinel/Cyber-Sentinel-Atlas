# AGENTS.md — Cyber-Sentinel ATLAS Engineering Contract

This file defines the operating contract for human and AI contributors working on Cyber-Sentinel ATLAS.

## Source-of-truth hierarchy

When documents disagree, resolve them in this order:

1. Accepted ADRs in `docs/adr/` for frozen architecture decisions.
2. Machine-readable release/readiness state under `docs/releases/`.
3. `docs/project-state.md` for the current project control-plane state.
4. `docs/current-status.md` for verified operational evidence and exact baselines.
5. `docs/roadmap.md` for phase sequencing and remaining work.
6. `docs/product-surfaces.md` for approved product-family scope.
7. `README.md` for the public product summary.

Historical snapshots under `docs/history/` are evidence, not current authority.

## Non-negotiable engineering rules

- `main` is release authority.
- Do not develop directly on `main`.
- Use a focused branch and pull request for every material change.
- Keep changes atomic: one bounded engineering objective per PR whenever practical.
- Do not weaken tests, policy checks, security controls, or release gates merely to make CI green.
- Release-critical work requires exact-head CI before merge.
- Release or packaging changes require post-merge verification when the governing workflow defines it.
- Documentation must not claim a gate is PASS without matching evidence.
- Never treat generated search indexes, UI state, model output, or upstream source text as canonical truth.
- Never commit credentials, private keys, tokens, personal secrets, signing material, or uncontrolled production data.
- Do not make licensing, production certificate, HSM/KMS, or legal redistribution decisions automatically.

## Frozen architecture

The following boundaries are already accepted and must not drift without a new ADR and explicit review:

- exactly seven canonical `AtlasRecord` families;
- deterministic exact-before-lexical retrieval;
- SQLite + FTS5 derived search artifact;
- TUF content-pack trust;
- trusted-time and highest-seen anti-rollback state;
- immutable generations, atomic activation, and Last Known Good recovery;
- production Shared Core in Go;
- Python retained as semantic/conformance oracle;
- local Desktop/Core boundary through `atlas-core --serve-stdio`;
- bounded length-prefixed UTF-8 JSON protocol;
- no default local HTTP/TCP/WebSocket listener or hidden network fallback;
- Windows Desktop host: Tauri 2.x;
- offline-first behavior and inspectable provenance.

## Approved product family

```text
ATLAS
├── Desktop
│   ├── Windows
│   ├── Linux
│   └── macOS
├── CLI
│   ├── Windows
│   ├── Linux
│   └── macOS
├── Web
├── PWA
│   └── iOS Safari
├── API
└── Mobile
    ├── iOS
    └── Android
```

Windows Desktop is the current release-critical surface. Other surfaces must reuse the same canonical, provenance, trust, and bounded-service contracts.

## Standard task lifecycle

Every implementation task follows this sequence:

```text
Read authority
    ↓
Identify phase / gate / invariant
    ↓
Create focused branch
    ↓
Implement smallest safe slice
    ↓
Run local/static validation where available
    ↓
Commit
    ↓
Open PR
    ↓
Exact-head CI
    ↓
Architecture / security / evidence review
    ↓
Merge
    ↓
Post-merge verification when required
    ↓
Synchronize project-state / current-status / roadmap / README as applicable
```

## Agent execution protocol

Before modifying code or documentation, an agent must:

1. read `AGENTS.md`;
2. read `docs/project-state.md`;
3. read the relevant ADR, release gate, architecture document, and tests;
4. inspect the current `main` head and open PRs;
5. confirm that the proposed change does not bypass a frozen boundary.

During execution:

- use a dedicated branch or isolated worktree;
- do not have two agents modify the same file set concurrently unless the work is explicitly coordinated;
- prefer deterministic builders and machine-readable evidence over hand-maintained counters;
- keep generated evidence reproducible;
- preserve fail-closed behavior;
- preserve provenance and source-version identity.

Before handoff or stopping:

- leave the branch and PR in an inspectable state;
- record blockers and exact evidence;
- update authoritative state documents if the completed change materially alters project state;
- do not rely on chat history as the only record of a decision.

## Definition of Done

A task is DONE only when all applicable conditions are true:

- implementation is committed on the intended branch;
- tests and validators for the affected boundary pass;
- required exact-head CI is green;
- security and architecture invariants remain intact;
- documentation and machine-readable state agree;
- the PR is merged to the intended base;
- required post-merge verification succeeds;
- the authoritative project-state documents are synchronized.

A green unit test alone is not Definition of Done.

## Continuity rule

Chat sessions, local terminals, agent processes, and individual machines are replaceable. The repository is the durable project memory.

A new technical lead or implementation agent must be able to continue the project from GitHub using the files above without requiring reconstruction from a previous chat.
