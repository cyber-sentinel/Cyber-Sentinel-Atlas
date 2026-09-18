# Public Packaging & Distribution Hardening — Phase 5.10.3

Status: **FORMAT & CHANNEL SELECTED / SIGNED-CANDIDATE EVIDENCE BLOCKED**

This contract defines PPR-06 technical requirements. The initial Public Preview release vehicle is now selected as a **signed portable ZIP** published through **GitHub Releases**; PPR-06 remains BLOCKED until exact signed-candidate and post-publication evidence are complete.

## Release pipeline

```text
exact release commit
  → tested binaries
  → PPR-04 redistribution closure
  → PPR-05 production signing
  → final package assembly
  → package SHA-256 + SBOM + provenance
  → clean-machine install/launch acceptance
  → upgrade/downgrade/uninstall/recovery acceptance
  → publication to approved channel
  → independent download/hash/signature verification
```

## Mandatory package properties

- exact source commit and build/run identity recorded;
- every executable requiring trust is production-signed before publication;
- final package has immutable SHA-256 and size evidence;
- SBOM, third-party notices and release notes are package-bound;
- no production private signing material is included;
- no hidden local HTTP/TCP/WebSocket service is introduced;
- no binary auto-update mechanism is enabled unless separately reviewed;
- package must preserve verified Knowledge Pack/TUF fail-closed behavior;
- clean Windows installation/portable extraction must not require undocumented admin credentials;
- WebView2 prerequisite behavior must be explicit and deterministic;
- failure/rollback/recovery instructions must be public and testable.

## Distribution format decision

Selected for the initial Public Preview: **Signed portable ZIP**. MSI/MSIX remain future options requiring separate reviewed evidence.

Previously evaluated format classes:

1. **Signed portable ZIP** — lowest installer complexity; extraction-based deployment; easiest to inspect and hash.
2. **Signed MSI** — enterprise-friendly Windows deployment and managed uninstall/upgrade semantics.
3. **Signed MSIX** — modern Windows packaging with stronger platform-managed install identity, subject to compatibility and enterprise deployment review.

A format is not accepted merely because it builds. The exact candidate must pass installation, launch, upgrade/rollback, removal and security acceptance.

## Public channel decision

Selected canonical channel: **GitHub Releases** for `cyber-sentinel/Cyber-Sentinel-Atlas`.

A project-controlled HTTPS site/CDN or enterprise/private mirror may be added later, but mirrors must preserve the canonical signed bytes and digest.

The canonical release authority and artifact digest must be identical across mirrors. A mirror may not silently replace or repackage signed release bytes.

## Required clean-machine acceptance

For the exact Public Preview candidate:

- verify final package SHA-256 before installation/extraction;
- verify Authenticode signatures and trusted timestamp;
- start from a clean supported Windows environment;
- verify prerequisite handling, including WebView2;
- launch GUI and Shared Core successfully;
- activate the exact approved verified public knowledge pack;
- execute Search → Record → Graph → Provenance acceptance;
- verify no unexpected default network listener;
- verify corrupted executable/sidecar/pack rejection;
- exercise uninstall/remove path when applicable;
- exercise supported upgrade path from the prior published build when applicable;
- exercise rollback/recovery behavior;
- verify accessibility release evidence on the same package SHA-256;
- verify public download bytes match the approved release digest.

## Update boundary

Public Preview does not require automatic binary updates. If binary auto-update is later introduced, it is a separate security architecture change requiring signed metadata, anti-rollback, channel trust, recovery and compromise handling. Content-pack TUF update trust must not be conflated with application binary update trust.

## Machine-readable evidence

`docs/releases/public-packaging-readiness.json` is the PPR-06 machine-readable authority. Format/channel selection is closed. PPR-06 remains `BLOCKED` until an exact signed package passes the release acceptance contract, is published through GitHub Releases, and the published bytes are independently reverified.

PPR-06 remains **BLOCKED** on signed-candidate and publication evidence, not on format/channel selection.
