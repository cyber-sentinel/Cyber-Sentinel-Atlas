# Contributing to Cyber-Sentinel-Atlas

Cyber-Sentinel-Atlas is maintainer-controlled. Contributions are welcome only when they preserve the approved product scope, provenance model, security boundaries and architecture decisions.

## Control model

- `main` is the authoritative branch and is never a direct-write target.
- Changes are proposed through a feature/chore branch and pull request.
- The maintainer (`@cyber-sentinel`) is the final merge authority for the official repository.
- Architecture, canonical schemas, security controls, trust/signing, release mechanics and other material decisions require an ADR or equivalent architecture record before implementation.
- A green CI result is necessary but never sufficient for merge.
- The official merge method is Merge Commit unless the maintainer explicitly approves another method.

## Scope and quality

A contribution must:

1. fit the approved Atlas roadmap and product boundaries;
2. include deterministic tests for behavior it changes;
3. preserve source/provenance references for technical claims;
4. preserve legacy/current identities instead of collapsing them;
5. avoid introducing raw backend query syntax, hidden network dependencies or unbounded parsing/traversal surfaces;
6. document security and rollback implications where relevant;
7. avoid unrelated refactors in the same PR.

## Source and licensing requirements

Do not submit copied prose, datasets, rules, schemas, binaries or other material unless redistribution and modification rights are known and the required attribution/provenance metadata is included. Third-party origin never makes content automatically canonical or publishable.

The repository is in controlled private development and does not currently publish a general public project license. External contribution acceptance is therefore paused until the maintainer approves the final first-party license and contribution-rights mechanism (for example, an approved CLA/DCO process). Opening a PR does not by itself grant the project rights beyond those explicitly agreed.

## Security

Never commit credentials, private keys, tokens, production secrets, private customer data or unredacted incident evidence. Security-sensitive findings should follow `SECURITY.md` rather than a public issue.

## Pull request expectations

PRs should state:

- purpose and bounded scope;
- affected architecture/ADR references;
- tests and evidence;
- source/licensing impact;
- security/rollback impact;
- exact files or contracts intentionally changed.

The maintainer may close contributions that are out of scope, inadequately sourced, unsafe, licensing-ambiguous, or that would move the official product away from its approved architecture.
