# Atlas Self-Hosted GitHub Actions Runners

Status: **ACTIVE / OPERATIONAL**

## Decision

ATLAS keeps GitHub as the authoritative source for committed project content and uses repository-scoped self-hosted runners for required Linux and Windows CI workloads.

This is an operational boundary only. It does not change the canonical data model, search contracts, pack-trust model, ADR-0024 technology selection, ADR-0025 local interface boundary, or merge/release governance.

## Role separation: CI runners are verification infrastructure

`ATLAS-CI-LNX01` and `ATLAS-CI-WIN01` are dedicated verification/build infrastructure. They are not persistent development workspaces and must not become a storage location for general engineering credentials, long-running mutable work or production secrets.

The supported separation is:

```text
Product / Technical Engineering Control
        ↓
isolated development worktree or container
        ↓
GitHub branch / PR
        ↓
ATLAS-CI-LNX01 + ATLAS-CI-WIN01
        ↓
CI evidence / package evidence
```

Engineering orchestration, task coordination and long-running development state belong outside the CI runner boundary. CI runners remain disposable verification surfaces whose outputs are evidence, not canonical project state.

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

Outbound TCP/443 must be reliable for GitHub and dependency endpoints used by ATLAS. At minimum allow the GitHub/GitHub Actions endpoints required by the official self-hosted runner documentation, including GitHub API, Actions service endpoints, GitHub content/release endpoints and artifact storage endpoints.

Build/test dependencies may also require controlled outbound access to package sources such as Go module infrastructure and Python package infrastructure. Additional language/toolchain phases may require their corresponding package registries.

Unrestricted web browsing is not a CI requirement. The requirement is reliable access to explicitly required source-control, Actions and package endpoints.

TLS interception must not break certificate or package-integrity validation. DNS and NTP must remain reliable. Time synchronization is security-relevant because ATLAS trusted-time, expiry and rollback tests depend on deterministic time semantics.

## Security model

These runners are dedicated to this repository. Do not register them for arbitrary public repositories or untrusted fork PR execution.

- repository scope only;
- no interactive user workloads on runner hosts;
- no production credentials or private signing keys on runners;
- no generic inbound RDP/SSH exposure from the Internet;
- administration through the normal private management path;
- runner registration tokens are short-lived bootstrap secrets and must not be committed, logged or stored in scripts;
- jobs must not run as privileged/root/Administrator unless a separately reviewed workflow explicitly requires it;
- build workspaces and caches are disposable;
- GitHub remains authoritative for committed project content and review history.

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
4. Generate a repository-scoped self-hosted runner registration token only when ready to register each host.
5. Supply the token through an environment variable or secure interactive shell variable during bootstrap.
6. Confirm both runners show `Idle` under repository Settings → Actions → Runners.
7. Execute the self-hosted runner smoke workflow.
8. Require both Linux and Windows smoke jobs to pass before changing production ATLAS workflows.
9. Migrate active workflows to the ATLAS self-hosted labels through a reviewed PR.
10. Re-run the required exact-head validation workflows and merge only after mandatory gates pass.

## Cleanup and recovery

Runner working directories are disposable. Project source remains in GitHub.

Before decommissioning a runner:

1. disable or remove it from GitHub;
2. stop/uninstall the runner service;
3. remove runner credentials/configuration;
4. securely delete the runner root and `_work` directory;
5. remove build caches if the VM will be repurposed;
6. restore or delete the VM according to infrastructure policy.

A clean OS snapshot before runner registration and a verified baseline snapshot after bootstrap are recommended.

## Cost boundary

GitHub-hosted compute minutes are not consumed by jobs that execute on self-hosted runners. Infrastructure, storage, network and operating-system costs remain the responsibility of the project environment. Workflows that continue to use GitHub-hosted labels can still consume hosted-runner quota, so migration must be explicit and verified.
