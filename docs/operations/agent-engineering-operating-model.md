# ATLAS Agent Engineering Operating Model

Status: **ACTIVE OPERATING STANDARD**

This document defines how human decision-making, AI-assisted engineering, GitHub, and CI runners are separated so ATLAS development can continue safely across chat limits, machines, and future multi-agent execution.

## Operating principle

The repository is the durable control plane. A chat session is not the project database.

Architecture decisions, current state, implementation evidence, release gates, branch history, pull requests, and CI results must be reconstructible from GitHub.

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

Owns execution sequencing:

- reads authoritative project state;
- decomposes work into bounded tasks;
- assigns non-overlapping work units;
- enforces architectural invariants;
- reviews implementation and evidence;
- controls merge ordering;
- synchronizes project-state documentation.

The orchestrator does not bypass CI or release gates.

### Implementation Agents

Implementation agents work only on assigned bounded scopes. Each agent receives:

- objective;
- authoritative inputs;
- files/directories in scope;
- required tests;
- prohibited changes;
- Definition of Done.

Agents use isolated branches/worktrees or containers and do not share an uncommitted working directory.

### CI Runners

CI runners are verification infrastructure, not development agents.

Their responsibilities are:

- reproducible build;
- test;
- validation;
- packaging;
- evidence generation;
- clean-machine acceptance where defined.

Do not install a general-purpose autonomous development agent on production CI runners unless a separately reviewed design explicitly requires it.

## Current interim execution mode

Until a dedicated agent-control server is deployed:

```text
Product Owner
      ↓
Technical Lead / Chat Orchestrator
      ↓
GitHub branches + PRs
      ↓
Existing Linux / Windows CI runners
      ↓
Review → Merge → Post-merge verification
```

This mode remains valid even if a chat reaches its context limit because authoritative state is written back to the repository.

## Target multi-agent execution mode

A future dedicated Agent Control Node may run the engineering workers:

```text
Product Owner
      ↓
Technical Lead / Orchestrator
      ↓
Agent Control Node
      ├── Planner / Coordinator
      ├── Implementation Agent A → isolated worktree/container
      ├── Implementation Agent B → isolated worktree/container
      ├── Test / Review Agent      → read-only or review branch
      └── Documentation Agent      → bounded documentation branch
                    ↓
                  GitHub
                    ↓
          Linux / Windows CI Runners
                    ↓
          Review → Merge → Verification
```

The Agent Control Node must not replace GitHub as source of truth and must not bypass branch/PR/CI controls.

## Recommended initial Agent Control Node

A practical starting point for parallel repository engineering:

- Ubuntu 24.04 LTS;
- 16 vCPU;
- 64 GB RAM;
- 500 GB NVMe minimum;
- 1 TB NVMe preferred if multiple concurrent worktrees, Rust/Tauri caches, artifacts, and containers are retained;
- no GPU required for Codex-style code agents;
- encrypted storage where supported;
- SSH restricted to administrative identities;
- outbound network access limited to required GitHub/package registries;
- no production secrets on the node.

Capacity should scale from observed concurrency rather than from agent count alone.

## Work isolation

One task equals one branch. One mutable worktree belongs to one active implementation agent.

Recommended naming:

```text
feature/<phase>-<objective>
fix/<phase>-<objective>
docs/<objective>
test/<objective>
chore/<objective>
```

Concurrent agents may work in parallel only when their write sets are independent. If two tasks touch the same core files or generated artifacts, sequence them or explicitly define dependency branches.

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

Any failed mandatory gate moves the task back to `IN_PROGRESS` or `BLOCKED`; it does not permit weakening the gate.

## Long-running work

Long-running work must be checkpointed through durable artifacts:

- commits;
- branches;
- pull requests;
- issues when useful;
- CI artifacts;
- machine-readable coverage/readiness files;
- `docs/project-state.md`;
- `docs/current-status.md`.

No task should depend on an uninterrupted chat stream to remain recoverable.

## Handoff protocol

When a session, agent, or machine changes, the next executor should need only:

1. repository URL;
2. current `main` SHA;
3. `AGENTS.md`;
4. `docs/project-state.md`;
5. `docs/current-status.md`;
6. `docs/roadmap.md`;
7. relevant open PR/issue links;
8. relevant ADR and gate documents.

If additional private context is required, that dependency must be explicit rather than silently assumed.

## Security controls for agent execution

- use least-privilege GitHub credentials;
- separate read/review credentials from write/merge authority where practical;
- never expose signing keys or production credentials to general implementation agents;
- require human authorization for licensing, signing-provider, key-custody, and public-release decisions;
- keep branch protection and CI gates authoritative;
- log agent actions and preserve commit attribution;
- pin or verify toolchain/dependency versions where the existing ATLAS supply-chain model requires it;
- prefer ephemeral workspaces for untrusted or experimental tasks.

## Failure and rollback

If an agent produces unsafe or conflicting work:

1. stop further writes to the affected branch;
2. preserve evidence;
3. do not merge;
4. reset by creating a clean branch from the last verified base;
5. reapply only reviewed changes;
6. rerun exact-head CI.

If an already merged change violates an invariant, use a dedicated revert/fix PR. Do not rewrite public branch history to hide the failure.

## Continuity guarantee

The goal of this operating model is not to make an individual chat or agent immortal. It is to make the project resumable.

A new chat, a new technical lead process, or a new Agent Control Node should be able to recover the exact project state from GitHub and continue from the last verified boundary.
