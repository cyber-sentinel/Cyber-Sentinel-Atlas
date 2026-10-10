# Public / Private Control-Plane Boundary

Cyber-Sentinel ATLAS maintains a **private Product Owner control plane** for confidential roadmap, MVP, internal source-governance, and approved-commitment state.

This public repository intentionally does **not** mirror that confidential ledger.

## Public repository scope

The public repository may contain:

- accepted public architecture decisions;
- public product documentation;
- source/provenance rules suitable for publication;
- release/readiness evidence intended for public inspection;
- code, tests, schemas and public corpus content approved for redistribution.

It must not contain, unless explicitly approved for publication:

- confidential Product Owner commitment ledgers;
- private MVP/test-build plans;
- private management state or internal roadmap detail;
- restricted-source inventories or raw copyrighted/licensed material;
- private control-plane commands, runtime state, secrets or sensitive operational evidence.

## Engineering rule

Authorized workers with access to the private Product Owner control plane must reconcile it before strategic status reporting, roadmap decisions, MVP planning, or any change that could silently drop an approved commitment.

Workers without that private context must not infer that an absent public item was cancelled. They must treat private strategic scope as unknown and avoid destructive scope changes.

## Publication rule

Public release of private control-plane content requires explicit Product Owner approval and all applicable source, licensing, redistribution, security and release gates.
