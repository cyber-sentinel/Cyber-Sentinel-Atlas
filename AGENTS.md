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
- external redistribution decisions not already governed by repository policy.

## Source-of-truth hierarchy

GitHub live state is authoritative over previous chat summaries, prompts, handoffs, checkpoints, or remembered state.

When repository documents disagree, resolve them in this order:

1. Accepted ADRs in `docs/adr/` for frozen architecture decisions.
2. `docs/product/approved-commitments.json` for Product Owner-approved scope, backlog, MVP, governance and durable product commitments that must not disappear merely because they are not in the current execution stream.
3. Machine-readable release/readiness state under `docs/releases/`.
4. `docs/project-state.md` for the current project control-plane state.
5. `docs/current-status.md` for verified operational evidence and exact baselines.
6. `docs/roadmap.md` for phase sequencing and remaining work.
7. `docs/product-surfaces.md` for approved product-family scope.
8. `README.md` for the public product summary.

Historical snapshots under `docs/history/` are evidence, not current authority.

Before any write, new engineering stream, status report, handoff, roadmap update, or MVP planning action, read and reconcile `docs/product/approved-commitments.json`. A commitment may not silently disappear from planning or reporting merely because it is not part of the current sprint, branch, batch, or PR. If a Product Owner-approved commitment is absent from the live control-plane, report it as `MISSING_FROM_CONTROL_PLANE` and repair the durable control-plane as routine documentation/governance work unless a reserved Product Owner decision is implicated.

Before any write or new engineering stream, fresh-check the authoritative GitHub state, including at minimum:

1. current `main` HEAD;
2. open PRs;
3. relevant branches;
4. recent merges;
5. exact-head workflow runs;
6. whether another stream already performed or overlaps the proposed work;
7. `ahead_by` / `behind_by` where applicable;
8. changed files;
9. machine-readable project state where available;
10. approved commitments relevant to the proposed work.

Never create duplicate work.

## Management status reporting contract

Cyber-Sentinel management/status reports must reconcile both current execution and the full approved commitment ledger. Use these states consistently:

- 🟢 `DONE / VERIFIED` — completed with repository/test/CI evidence where applicable;
- 🟡 `IN_PROGRESS` — active execution or validation is underway;
- 🟠 `APPROVED_PENDING / DEFERRED / NEXT ACTION` — approved and intentionally not complete yet, with dependencies or sequencing made explicit;
- 🔴 `BLOCKED / FAILURE / MISSING_FROM_CONTROL_PLANE` — a real blocker, failed gate, or approved commitment that is not durably represented where it should be.

Every management report must include, as applicable:

1. current execution;
2. completed/verified work;
3. approved pending/deferred commitments;
4. blockers/failures/control-plane gaps;
5. exact next action.

Do not report only the current PR or sprint when broader Product Owner-approved commitments remain outstanding.

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
- Never commit credentials, private keys, tokens, personal secrets, signing material, or uncontrolled production data.
- Do not make licensing, production certificate, HSM/KMS, or legal redistribution decisions automatically.
- Never force-push `main`.
- Never perform destructive resets against authoritative work.
- Fail closed when material source, schema, security, provenance, or redistribution ambiguity cannot safely be resolved.

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

## Standard task lifecycle

Every implementation task follows this sequence:

```text
Read authority
    ↓
Read approved commitments registry
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
Synchronize approved commitments / project-state / current-status / roadmap / README as applicable
    ↓
Fresh-check again and continue with the next safe non-duplicate task
```

## Engineering execution protocol

Before modifying code or documentation, an authorized worker must:

1. read `AGENTS.md`;
2. read `docs/product/approved-commitments.json`;
3. read `docs/project-state.md`;
4. read the relevant ADR, release gate, architecture document, and tests;
5. inspect the current `main` head and open PRs;
6. inspect relevant branches, recent merges, and exact-head workflows;
7. confirm that the proposed change does not duplicate another stream;
8. confirm that the proposed change does not bypass a frozen boundary;
9. confirm that it does not silently drop or contradict an approved Product Owner commitment.

During execution:

- use a dedicated branch or isolated worktree;
- do not allow concurrent workers to modify the same file set unless the work is explicitly coordinated;
- prefer deterministic builders and machine-readable evidence over hand-maintained counters;
- keep generated evidence reproducible;
- preserve fail-closed behavior;
- preserve provenance and source-version identity;
- inspect resulting diffs before handoff or PR creation;
- remove generated `__pycache__`, `.pyc`, temporary workflows, temporary triggers, temporary helpers, and other non-durable artifacts before a production PR unless explicitly required as durable evidence.

Before handoff or stopping:

- leave the branch and PR in an inspectable state;
- record blockers and exact evidence;
- update authoritative state documents if the completed change materially alters project state;
- ensure decisions required for continuation are recorded in durable project artifacts;
- ensure approved commitments affected by the work have accurate durable status and are not lost in conversational state.

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

Do not stop merely because one task, batch, issue, PR, milestone, or merge is complete.

After every successful merge:

1. fresh-check authoritative `main`;
2. verify the expected merge is present;
3. verify applicable post-merge workflows;
4. verify expected project/coverage state;
5. verify temporary artifacts are absent;
6. reconcile `docs/product/approved-commitments.json` against the completed work and remaining approved backlog;
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
- the authoritative project-state documents are synchronized;
- the approved commitment ledger is updated when the task changes the state of a Product Owner-approved commitment.

A green unit test alone is not Definition of Done.

## Long-running work and session continuity

Local terminals, worker processes, worktrees, containers, individual machines, and chat/session context are replaceable. The repository-backed engineering record is the durable project memory.

A new authorized technical lead or implementation worker must be able to continue the project from GitHub and the authoritative files above without reconstructing undocumented prior-session context.

For complex multi-step work, maintain enough durable state that another Codex or ChatGPT session can continue without relying on conversation memory.

Prefer repository state, commits, tests, workflow evidence, explicit checkpoints, and the approved commitment registry over conversational assumptions.

## Usage-limit / session-handoff policy

Do not intentionally stop early merely to preserve Codex/session usage.

Continue performing useful engineering work until the available session or usage allowance prevents further safe execution.

Before the session can no longer continue, whenever the platform allows:

1. finish the current atomic mutation whenever safely possible;
2. push all valid durable work;
3. do not leave an ambiguous partially-applied repository mutation;
4. record the exact current repository state;
5. produce a compact `RESUME CHECKPOINT`.

The `RESUME CHECKPOINT` must include:

- authoritative `main` HEAD SHA;
- active branch;
- active branch exact HEAD SHA;
- open PR number and state, if any;
- `ahead_by` / `behind_by` where applicable;
- changed files;
- latest relevant commits;
- exact-head workflow runs and conclusions;
- current corpus/project coverage state;
- approved commitments changed, completed, blocked or still pending;
- work completed during the session;
- unresolved failures;
- actual blockers;
- temporary artifacts still present, if any;
- exact next technical action;
- required commands or GitHub operations;
- security/source/provenance caveats;
- a paste-ready continuation prompt for ChatGPT or the next Codex session.

If usage is exhausted during an active turn, complete as much of that turn as the platform permits and leave the repository in the safest recoverable state.

Never report work as complete unless durable repository, test, or CI evidence confirms it.

## Required handoff format

When producing a session handoff, use:

```text
### Current State
- main HEAD
- branch/head
- PR
- coverage/state
- CI
- approved commitments status

### Completed
- concrete work
- commits
- tests
- PR/merge evidence

### Approved Pending / Deferred
- durable Product Owner-approved commitments not yet complete

### Blockers
- real blockers and control-plane gaps only

### Next Action
- exact next engineering action

### Continuation Prompt
- self-contained prompt that allows another ChatGPT/Codex session to resume without guessing
```
