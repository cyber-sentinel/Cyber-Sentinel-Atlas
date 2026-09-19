# Atlas Self-Hosted GitHub Actions Runners

Status: **ACTIVE / OPERATIONAL**

## Decision

ATLAS keeps GitHub as the source of truth and uses two repository-scoped self-hosted runners for the required Linux and Windows CI workloads.

This is an operational change only. It does not change the canonical data model, search contracts, pack trust model, ADR-0024 technology selection, ADR-0025 local interface boundary, or Merge Commit governance.

## Role separation: CI runners are not agent nodes

`ATLAS-CI-LNX01` and `ATLAS-CI-WIN01` are verification/build infrastructure. They are not the persistent development workspace for Codex or other autonomous implementation agents.

The supported separation is:

```text
Technical Lead / Agent Orchestrator
        ↓
isolated development worktree/container
        ↓
GitHub branch / PR
        ↓
ATLAS-CI-LNX01 + ATLAS-CI-WIN01
        ↓
CI evidence / package evidence
```

A future dedicated Agent Control Node is a separate host and is governed by [`agent-engineering-operating-model.md`](agent-engineering-operating-model.md). General-purpose agent credentials, long-running development state, or production secrets must not be moved onto CI runners merely to gain persistence.

## Hosts

### ATLAS-CI-LNX01

- OS: Ubuntu Server 24.04 LTS x86-64
- vCPU: 4 minimum; 8 preferred if capacity is available
- RAM: 8 GiB minimum; 16 GiB preferred
- Disk: 100 GiB SSD minimum
- Network: private IP is sufficient; outbound HTTPS required
- GitHub runner labels: `self-hosted`, `linux`, `x64`, `atlas-ci`, `atlas-linux`
- Runner account: dedicated non-interactive `atlasrunner`
- Runner root: `/opt/atlas-runner`

### ATLAS-CI-WIN01

- OS: Windows Server 2022 Standard x86-64
- vCPU: 4 minimum; 8 preferred if capacity is available
- RAM: 8 GiB minimum; 16 GiB preferred
- Disk: 120 GiB SSD minimum
- Network: private IP is sufficient; outbound HTTPS required
- GitHub runner labels: `self-hosted`, `windows`, `x64`, `atlas-ci`, `atlas-windows`
- Runner root: `C:\AtlasRunner`
- Runner mode: Windows service

## Network policy

No inbound Internet exposure is required for either runner. GitHub Actions self-hosted runners establish outbound connections to GitHub.

Outbound TCP/443 must be reliable for GitHub and dependency endpoints used by Atlas. At minimum allow the GitHub/GitHub Actions domains required by the official self-hosted runner documentation, including GitHub API, Actions service endpoints, GitHub content/release endpoints and artifact storage endpoints.

Atlas build/test dependencies currently also require reliable outbound access to relevant package sources such as Go module infrastructure and Python package infrastructure when a workflow installs dependencies. Future JavaScript/Rust phases may add npm/crates endpoints.

YouTube or unrestricted general-purpose web browsing is not a requirement. The CI requirement is reliable access to the explicit source-control, Actions and package endpoints used by the workflows.

TLS interception must not break GitHub certificate validation or package integrity validation. DNS and NTP must be reliable. Time synchronization is security-relevant because Atlas TUF/trusted-time tests intentionally exercise expiry and rollback semantics.

## Security model

These runners are dedicated to this repository. Do not register them for arbitrary public repositories or untrusted fork PR execution.

- repository scope only;
- no interactive user workloads on the runner hosts;
- no production credentials or private signing keys on the runners;
- no generic inbound RDP/SSH exposure from the Internet;
- administration through the organization's normal private management path;
- runner registration tokens are short-lived bootstrap secrets and must not be committed, logged or stored in scripts;
- jobs must not run as privileged/root/Administrator unless a separately reviewed workflow explicitly requires it;
- build workspaces and caches are disposable;
- GitHub remains the authoritative source for committed project content.

## Pinned runner bootstrap

Initial bootstrap is pinned to GitHub Actions Runner `v2.337.0`, published 2026-08-26.

Pinned SHA-256 values:

- Linux x64 archive: `70920811a4f8ad4328818682bca5c6469c1c942fab52448868071d0063816613`
- Windows x64 archive: `1150692afa94e71f872017e254ea55b6eece1eece3fe7e3a6d4c93d0a1b85cfc`

Upgrade of the runner binary is an operational maintenance action and must preserve checksum verification.

## Bootstrap sequence

1. Provision both VMs with the hostnames and resources above.
2. Apply OS updates and verify DNS/NTP/outbound HTTPS.
3. Ensure Git is installed and available on PATH.
4. Generate a repository-scoped self-hosted runner registration token from GitHub only when ready to register each host.
5. Run the corresponding bootstrap script with the token supplied through an environment variable or secure interactive shell variable.
6. Confirm both runners show `Idle` under repository Settings -> Actions -> Runners.
7. Allow the `Self-hosted Runner Smoke` workflow on `ops/self-hosted-runner-foundation` to execute.
8. Require both Linux and Windows smoke jobs to pass before changing production Atlas workflows.
9. Migrate active workflows from GitHub-hosted labels to Atlas self-hosted labels in a dedicated PR.
10. Re-run PR #26 on its exact current head using the self-hosted runners. Merge only after Foundation Hygiene and Phase 5.5.4A execute successfully on both required platforms.

## Cleanup and recovery

The working directories are disposable. Project source remains in GitHub.

Before decommissioning a runner:

1. disable or remove the runner from GitHub;
2. stop/uninstall the runner service;
3. remove runner credentials/configuration;
4. securely delete the runner root and `_work` directory;
5. remove build caches if the VM will be repurposed;
6. restore or delete the VM according to infrastructure policy.

A clean OS snapshot before runner registration and another baseline snapshot after successful bootstrap are recommended.

## Cost boundary

GitHub-hosted compute minutes are not consumed by jobs that actually execute on self-hosted runners. The organization remains responsible for the VM, storage, network and operating-system costs. GitHub-hosted workflows that remain configured as `ubuntu-latest`/`windows-latest` can still consume the GitHub-hosted quota, so migration must be explicit and verified.