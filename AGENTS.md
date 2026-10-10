# AGENTS.md — Cyber-Sentinel ATLAS Engineering Contract

This file defines the operating contract for authorized contributors and engineering workers on Cyber-Sentinel ATLAS.

## Product-owner standing authorization

The Product Owner has standing authorization for routine engineering work, including:

- implementation;
- refactoring;
- tests and test automation;
- CI fixes;
- documentation and README maintenance;
- corpus engineering;
- source/provenance work;
- release evidence;
- security hardening;
- branch and PR hygiene;
- post-merge verification;
- consistency fixes;
- cleanup of superseded, stale, generated, or temporary engineering artifacts when safe.

Do not request confirmation for routine engineering actions covered above.

The following remain reserved decisions and require explicit Product Owner approval when materially implicated:

- licensing;
- commercial/legal commitments;
- production code-signing or certificate decisions;
- public-cloud hosting commitments;
- HSM/KMS ownership or trust-policy changes;
- external redistribution decisions not already governed by repository policy;
- publication of private Product Owner control-plane content.

## Public/private control-plane boundary

The public ATLAS repository is **not** the complete Product Owner control plane.

Confidential roadmap, internal MVP planning, restricted-source metadata, detailed approved commitments, management state and other private governance material are maintained in a private Product Owner control plane.

See `docs/product/control-plane-boundary.md` for the public boundary contract.

Rules:

- never mirror the confidential commitment ledger into this public repository unless explicitly approved for publication;
- never commit raw restricted/licensed/copyrighted source material to the public repository by default;
- workers with authorized private-control-plane access must reconcile that private authority before strategic status reporting, roadmap decisions, MVP planning, or scope changes;
- workers without private context must not infer that an item absent from public documentation was cancelled or dropped;
- if private strategic context is required but unavailable, fail closed on destructive scope changes rather than silently deleting commitments.

## Source-of-truth hierarchy

GitHub live state is authoritative over previous chat summaries, prompts, handoffs, checkpoints, or remembered state for public repository execution.

For public repository documents, resolve conflicts in this order:

1. Accepted ADRs in `docs/adr/` for frozen public architecture decisions.
2. Machine-readable release/readiness state under `docs/releases/`.
3. `docs/project-state.md` for current public project control-plane state.
4. `docs/current-status.md` for verified operational evidence and exact baselines.
5. `docs/roadmap.md` for public phase sequencing and remaining work.
6. `docs/product-surfaces.md` for approved public product-family scope.
7. `README.md` for the public product summary.

Private Product Owner governance supersedes public silence for confidential commitments, internal MVP scope and non-public strategic decisions when the authorized worker has access to it.

Historical snapshots under `docs/history/` are evidence, not current authority.

Before any write or new engineering stream, fresh-check authoritative GitHub state, including at minimum:

1. current `main` HEAD;
2. open PRs;
3. relevant branches;
4. recent merges;
5. exact-head workflow runs;
6. whether another stream already performed or overlaps the proposed work;
7. `ahead_by` / `behind_by` where applicable;
8. changed files;
9. machine-readable project state where available;
10. private approved commitments relevant to the work when authorized private context is available.

Never create duplicate work.

## Management status reporting contract

Cyber-Sentinel management/status reports use these states consistently:

- 🟢 `DONE / VERIFIED` — completed with repository/test/CI evidence where applicable;
- 🟡 `IN_PROGRESS` — active execution or validation is underway;
- 🟠 `APPROVED_PENDING / DEFERRED / NEXT ACTION` — approved and intentionally incomplete, with dependencies or sequencing explicit;
- 🔴 `BLOCKED / FAILURE / MISSING_FROM_CONTROL_PLANE` — a real blocker, failed gate, or an approved commitment missing from the durable control plane.

Authorized management reports must reconcile both current execution and the private approved-commitment ledger when that private authority is available.

Every management report must include, as applicable:

1. current execution;
2. completed/verified work;
3. approved pending/deferred commitments;
4. blockers/failures/control-plane gaps;
5. exact next action.

Do not report only the current PR or sprint when broader approved commitments remain outstanding.

## Non-negotiable engineering rules

- `main` is release authority.
- Do not develop directly on `main`.
- Use a focused branch and pull request for every material change.
- Keep changes atomic: one bounded engineering objective per PR whenever practical.
- Do not weaken tests, policy checks, security controls, provenance requirements, redistribution controls, or release gates merely to make CI green.
- Release-critical work requires exact-head CI before merge.
- Release or packaging changes require post-merge verification when the governing workflow defines it.
- Documentation must not claim a gate is PASS without matching evidence.
- A queued workflow is not a passing workflow.
- A required skipped workflow is not automatically a passing workflow unless the governing path-aware contract explicitly says so.
- Never treat generated search indexes, UI state, semantic/model output, or upstream source text as canonical truth.
- Never commit credentials, private keys, tokens, personal secrets, signing material, uncontrolled production data, or confidential control-plane state to public history.
- Do not make licensing, production certificate, HSM/KMS, or legal redistribution decisions automatically.
- Never force-push `main`.
- Never perform destructive resets against authoritative work.
- Fail closed when material source, schema, security, provenance, privacy, or redistribution ambiguity cannot safely be resolved.

## Frozen architecture

The following boundaries are accepted and must not drift without a new ADR and explicit review:

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

## Windows Security corpus authority

For Windows Security encyclopedia work, source authority is:

1. Microsoft official documentation;
2. controlled provider/channel/version evidence;
3. Ultimate Windows Security only as a coverage / Quick Detail benchmark.

Ultimate Windows Security is not primary semantic authority.

Do not bulk-ingest or redistribute prohibited UWS prose, examples, or field descriptions.

Do not combine independent coverage denominators.

Never claim `ENCYCLOPEDIA_GRADE` without repository evidence satisfying the applicable schema, source/provenance, semantic, redistribution, and exact-head validation gates.

## Restricted/private reference sources

Private reference material may inform independently authored ATLAS knowledge when Product Owner authorization and applicable source-governance rules permit it.

Public-repository rules:

- do not commit raw restricted/private course material, posters, PDFs or source images by default;
- do not publish substantial verbatim text or close paraphrases from restricted/copyrighted sources;
- preserve source/provenance boundaries;
- prefer primary/official sources for canonical telemetry semantics;
- require redistribution/license review before exposing restricted-source-derived material publicly.

## Standard task lifecycle

Every implementation task follows this sequence:

```text
Read authority
    ↓
Reconcile private Product Owner governance when authorized/relevant
    ↓
Fresh-check GitHub live state
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
Synchronize public state and private commitment state as applicable
    ↓
Fresh-check again and continue with the next safe non-duplicate task
```

## Engineering execution protocol

Before modifying code or documentation, an authorized worker must:

1. read `AGENTS.md`;
2. read `docs/product/control-plane-boundary.md`;
3. read `docs/project-state.md`;
4. read the relevant ADR, release gate, architecture document, source policy and tests;
5. inspect current `main` head and open PRs;
6. inspect relevant branches, recent merges and exact-head workflows;
7. confirm the proposed change does not duplicate another stream;
8. confirm the proposed change does not bypass a frozen boundary;
9. when private authority is available, confirm it does not silently drop or contradict an approved Product Owner commitment.

During execution:

- use a dedicated branch or isolated worktree;
- do not allow concurrent workers to modify the same file set unless explicitly coordinated;
- prefer deterministic builders and machine-readable evidence over hand-maintained counters;
- keep generated evidence reproducible;
- preserve fail-closed behavior;
- preserve provenance and source-version identity;
- inspect resulting diffs before handoff or PR creation;
- remove generated `__pycache__`, `.pyc`, temporary workflows, temporary triggers, temporary helpers and other non-durable artifacts before a production PR unless explicitly required as durable evidence.

Before handoff or stopping:

- leave the branch and PR in an inspectable state;
- record blockers and exact evidence;
- update authoritative state documents if completed work materially alters project state;
- ensure decisions required for continuation are recorded in durable project artifacts or the authorized private Product Owner control plane as appropriate;
- do not publish private commitment detail merely to make a handoff self-contained.

## Continuous execution policy

Authorized workers should continue executing the project autonomously without stopping for routine approval.

Continue through applicable stages such as:

- implementation;
- tests;
- validation;
- CI repair;
- documentation;
- corpus engineering;
- source/provenance work;
- PR preparation;
- exact-head CI;
- merge validation;
- merge;
- post-merge verification;
- authoritative state synchronization;
- the next safe project task.

Do not stop merely because one task, batch, issue, PR, milestone or merge is complete.

After every successful merge:

1. fresh-check authoritative `main`;
2. verify the expected merge is present;
3. verify applicable post-merge workflows;
4. verify expected project/coverage state;
5. verify temporary artifacts are absent;
6. reconcile private Product Owner commitments when authorized private context is available;
7. rebuild the next deterministic work queue where applicable;
8. continue with the next highest-priority safe non-duplicate task.

Only stop when one of the following applies:

- a reserved Product Owner decision is required;
- a real external blocker prevents further safe work;
- material ambiguity requires fail-closed escalation;
- the current execution/session/usage allowance prevents further useful work.

## Definition of Done

A task is DONE only when all applicable conditions are true:

- implementation is committed on the intended branch;
- tests and validators for the affected boundary pass;
- required exact-head CI is green;
- security and architecture invariants remain intact;
- documentation and machine-readable state agree;
- the PR is merged to the intended base;
- required post-merge verification succeeds;
- authoritative public project-state documents are synchronized;
- private Product Owner commitment state is synchronized when the task changes an approved private commitment.

A green unit test alone is not Definition of Done.

## Long-running work and session continuity

Local terminals, worker processes, worktrees, containers, individual machines and chat/session context are replaceable. Durable repository evidence and the authorized private Product Owner control plane are the project memory.

A new authorized technical lead or implementation worker must be able to continue without reconstructing undocumented prior-session context, while still respecting the public/private boundary.

Prefer repository state, commits, tests, workflow evidence, explicit checkpoints and private governance over conversational assumptions.

## Usage-limit / session-handoff policy

Do not intentionally stop early merely to preserve Codex/session usage.

Continue performing useful engineering work until the available session or usage allowance prevents further safe execution.

Before the session can no longer continue, whenever the platform allows:

1. finish the current atomic mutation whenever safely possible;
2. push all valid durable work;
3. do not leave an ambiguous partially-applied repository mutation;
4. record exact current repository state;
5. produce a compact `RESUME CHECKPOINT` without leaking private control-plane content into public artifacts.

The `RESUME CHECKPOINT` should include, as applicable:

- authoritative `main` HEAD SHA;
- active branch/head;
- open PR and state;
- `ahead_by` / `behind_by`;
- changed files;
- relevant commits;
- exact-head workflow conclusions;
- current public corpus/project state;
- a private-control-plane reconciliation status without exposing confidential details publicly;
- completed work;
- unresolved failures;
- actual blockers;
- temporary artifacts;
- exact next technical action;
- required commands/GitHub operations;
- source/security/provenance/privacy caveats;
- a continuation prompt suitable for the authorized next session.

Never report work as complete unless durable repository, test or CI evidence confirms it.

## Required handoff format

```text
### Current State
- main HEAD
- branch/head
- PR
- coverage/state
- CI
- private-control-plane reconciliation status

### Completed
- concrete work
- commits
- tests
- PR/merge evidence

### Approved Pending / Deferred
- summarize only at the level appropriate for the handoff's confidentiality boundary

### Blockers
- real blockers and control-plane gaps only

### Next Action
- exact next engineering action

### Continuation Prompt
- self-contained for an authorized next ChatGPT/Codex session without exposing private control-plane detail publicly
```
