# ATLAS Engineering Orchestration Operating Model

Status: **ACTIVE OPERATING STANDARD**

This document defines how product decisions, engineering orchestration, isolated implementation work, GitHub and CI verification are separated so ATLAS development remains resumable, reviewable and auditable across machines, sessions and parallel workstreams.

## Operating principle

The repository-backed engineering record is durable; individual interactive sessions are not project databases.

Architecture decisions, current state, implementation evidence, release gates, branch history, pull requests and CI results must be reconstructible from repository state and controlled project records.

## Roles

### Product Owner

Owns product intent and explicit business/security decisions, including:

- product priorities;
- scope changes;
- licensing choice;
- production signing/provider choice;
- release authorization;
- acceptance of material architecture changes.

### Technical Lead / Orchestrator

Owns execution sequencing and engineering control:

- reads authoritative project state;
- decomposes work into bounded tasks;
- assigns non-overlapping work units;
- enforces architectural invariants;
- reviews implementation and evidence;
- controls merge ordering;
- synchronizes project-state documentation;
- prevents duplicate or conflicting work.

The orchestrator does not bypass CI, release gates or source-of-truth controls.

### Engineering Workers

Engineering workers operate only on assigned bounded scopes. Each work unit receives:

- objective;
- authoritative inputs;
- files/directories in scope;
- required tests;
- prohibited changes;
- Definition of Done.

Workers use isolated branches/worktrees or containers and do not share an uncommitted mutable working directory.

### CI Runners

CI runners are verification infrastructure, not development workspaces.

Their responsibilities are:

- reproducible build;
- test;
- validation;
- packaging;
- evidence generation;
- clean-machine acceptance where defined.

General development tooling, persistent orchestration state and broad credentials must remain outside the CI runner boundary unless a separately reviewed design explicitly requires otherwise.

## Current execution model

ATLAS uses a repository-backed control model in which product intent, engineering coordination and verification remain separated:

```text
Product Owner
      ↓
Technical Lead / Orchestrator
      ↓
Engineering Control Plane
      ↓
isolated work units / branches / worktrees
      ↓
GitHub PRs
      ↓
Linux / Windows CI runners
      ↓
Review → Merge → Post-merge Verification
```

The engineering control plane may coordinate multiple bounded work units, but GitHub remains authoritative for committed source, branch/PR history and review evidence. Canonical task coordination must not weaken repository governance or CI gates.

## Work isolation

One mutable work unit maps to one isolated branch/worktree. A worker must not share an uncommitted working directory with another concurrent writer.

Recommended naming:

```text
feature/<phase>-<objective>
fix/<phase>-<objective>
docs/<objective>
test/<objective>
chore/<objective>
```

Concurrent work is allowed only when write sets are independent. If two tasks touch the same core files or generated artifacts, sequence them or define an explicit dependency order.

## Task state machine

```text
BACKLOG
  ↓
READY
  ↓
IN_PROGRESS
  ↓
LOCAL_VALIDATED
  ↓
PR_OPEN
  ↓
CI_RUNNING
  ↓
REVIEW
  ↓
MERGE_READY
  ↓
MERGED
  ↓
POST_MERGE_VERIFIED
  ↓
DONE
```

Any failed mandatory gate moves the task back to `IN_PROGRESS` or `BLOCKED`; it never authorizes weakening the gate.

## Long-running work

Long-running work must be checkpointed through durable artifacts such as:

- commits;
- branches;
- pull requests;
- issues when useful;
- CI artifacts;
- machine-readable coverage/readiness files;
- `docs/project-state.md`;
- `docs/current-status.md`;
- controlled orchestration evidence where applicable.

No workstream should depend on an uninterrupted interactive session to remain recoverable.

## Handoff protocol

A replacement executor should be able to recover the required project state from:

1. repository URL;
2. current `main` SHA;
3. `AGENTS.md`;
4. `docs/project-state.md`;
5. `docs/current-status.md`;
6. `docs/roadmap.md`;
7. relevant open PR/issue links;
8. relevant ADR and gate documents;
9. any required controlled orchestration checkpoint/evidence references.

If additional private context is required, that dependency must be explicit rather than silently assumed.

## Security controls for engineering orchestration

- use least-privilege GitHub credentials;
- separate read/review credentials from write/merge authority where practical;
- never expose signing keys or production credentials to general implementation workers;
- require explicit authorization for licensing, signing-provider, key-custody and public-release decisions;
- keep branch protection and CI gates authoritative;
- preserve commit attribution and engineering evidence;
- pin or verify toolchain/dependency versions where the ATLAS supply-chain model requires it;
- prefer ephemeral workspaces for untrusted or experimental tasks;
- prevent duplicate task execution and conflicting concurrent writes;
- keep canonical coordination state separate from transient worker state.

## Failure and rollback

If a work unit produces unsafe or conflicting changes:

1. stop further writes to the affected branch/worktree;
2. preserve evidence;
3. do not merge;
4. create a clean recovery branch from the last verified base when necessary;
5. reapply only reviewed changes;
6. rerun exact-head CI.

If an already merged change violates an invariant, use a dedicated revert/fix PR. Do not rewrite public branch history to hide the failure.

## Continuity guarantee

The objective of this operating model is resumability, not dependence on any single process, machine or interactive session.

A new authorized engineering process should be able to recover the exact project state from repository-backed evidence and continue from the last verified boundary without weakening security, governance or release controls.
