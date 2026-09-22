# Third-Party Redistribution Closure — Phase 5.10.1

Status: **IN PROGRESS / FAIL-CLOSED**

This document narrows PPR-04 from a generic third-party notice requirement to an exact, release-scoped redistribution control. It is an engineering/compliance inventory, not legal advice and not a declaration that Public Preview redistribution is approved.

## Closure rule

PPR-04 may move to `PASS` only when the exact Public Preview payload is frozen and every distributed third-party component or knowledge target has all of the following:

1. immutable upstream identity (version, commit, digest, or equivalent);
2. license/terms source bound to that identity;
3. redistribution classification;
4. required notice/attribution material prepared for the public package;
5. confirmation that the release payload contains no unreviewed third-party target;
6. machine-readable evidence bound to the exact release package SHA-256.

Unknown, ambiguous, incompatible, or unverified rights remain a non-waivable publication failure.

## Deterministic freeze evidence

The two machine-readable freeze booleans are not self-authenticating. Setting
`public_preview_corpus_frozen=true` or `software_payload_frozen=true` requires an
exact release commit plus a SHA-256-bound freeze manifest and an immutable evidence
reference recorded under `freeze_evidence` in
`docs/releases/third-party-redistribution-inventory.json`.

`tools/release/generate_redistribution_freeze_manifest.py` creates a deterministic
manifest over explicitly supplied artifacts. The manifest records the release commit,
freeze kind, artifact basename, size and SHA-256. It never grants publication authority.

`tools/release/validate_redistribution_freeze_manifest.py` verifies that manifest
against the exact artifact bytes and fails on path traversal, role/file duplication,
size drift, digest drift, release-commit drift or evidence-class drift.

The Phase 5.10.1 workflow performs a non-authoritative rehearsal for both corpus and
software freeze kinds and includes a deliberate tamper test. Rehearsal evidence does
not set either freeze boolean, does not change any redistribution classification and
does not move PPR-04 from `BLOCKED`.

## A. Production software/runtime payload

The Public Preview software inventory must be generated from the exact built artifacts, not inferred only from source manifests.

| Component family | Current pinned/observed boundary | Current control state | Release requirement |
| --- | --- | --- | --- |
| Go Shared Core | Go `1.25.13`; module graph in `shared-core/go/go.mod` | **TECHNICAL EVIDENCE AVAILABLE** | Bind exact linked-module SBOM + license evidence to release binary |
| TUF Go runtime | `github.com/theupdateframework/go-tuf/v2 v2.4.2` | **TECHNICAL EVIDENCE AVAILABLE** | Include if linked/distributed; preserve license evidence |
| SQLite Go implementation | `modernc.org/sqlite v1.58.0` | **TECHNICAL EVIDENCE AVAILABLE** | Bind linked dependency and license evidence to release binary |
| Go text/runtime dependencies | `golang.org/x/text v0.39.0` plus indirect locked modules | **TECHNICAL EVIDENCE AVAILABLE** | Use generated SBOM/license validation; do not maintain a hand-written substitute |
| Tauri desktop host | Tauri `2.11.5`, committed/hash-guarded Cargo lock | **AUTOMATED PREFLIGHT / RELEASE BINDING OPEN** | Generate exact Windows-target Cargo metadata/license evidence on every relevant change; bind final evidence to the release build/package |
| `serde_json` / `sha2` and transitive Rust crates | Exact versions resolved by committed Cargo lock | **AUTOMATED PREFLIGHT / RELEASE BINDING OPEN** | Preserve exact crate license metadata/license-file hashes and generate the final notice bundle from the frozen release graph |
| Microsoft Edge WebView2 Runtime | Runtime prerequisite; current portable First Preview does not claim redistribution of WebView2 binaries | **NOT BUNDLED IN CURRENT PORTABLE MODEL** | If a future installer bundles/bootstrap-downloads WebView2, review Microsoft's redistribution terms for that exact installer model |
| Product artwork/UI assets | Cyber-Sentinel repository assets unless separately attributed | **FIRST-PARTY/REVIEW REQUIRED** | Confirm every shipped font/icon/image has recorded origin and rights; no untracked asset may enter release payload |

Current desktop UI preflight: the packaged Tauri web surface contains only repository-owned `index.html`, `main.js`, and `styles.css`; no external CDN, remote font, `@font-face`, or remote asset URL is referenced. The Phase 5.10.1 CI now regenerates an exact asset SHA-256 inventory and rejects remote references in text-like packaged frontend assets. It also captures Windows-target (`x86_64-pc-windows-msvc`) Cargo metadata from the committed lock, requires every reachable third-party crate to expose a license expression or license file, and hashes any declared license file. This is preflight evidence only: it does not make a redistribution approval or bind evidence to the final signed package.

Existing Phase 5.5.4D supply-chain controls already generate CycloneDX evidence and fail closed on missing linked-module license evidence for the production Go binary. PPR-04 extends that discipline to the complete public distribution payload, including the Rust/Tauri host and release assets.

## B. Knowledge-content redistribution inventory

### MITRE ATT&CK

- Atlas source profile: `ingestion/source-profiles/mitre-attack-enterprise.release.json`
- Pinned ATT&CK release: `19.2`
- Upstream: `mitre-attack/attack-stix-data`
- Pinned commit: `6cda5ad8462c79e14fbb872f4e09059b18e0cfc4`
- Pinned bundle: `enterprise-attack/enterprise-attack-19.2.json`
- Upstream license at the pinned revision permits research, development, and commercial use subject to reproduction of MITRE's copyright designation and license in copies.
- Current state: **REDISTRIBUTION CONDITIONALLY CLEARABLE** — exact attribution/license text must be carried into the Public Preview notice bundle and the packaged target must match the reviewed pinned identity.

### MITRE CAR

- Atlas source profile: `ingestion/source-profiles/mitre-car.release.json`
- Upstream: `mitre-attack/car`
- Pinned commit: `1b922fe1527d956e222a99473472e594f10f610b`
- Current declared canary target: `analytics/CAR-2016-03-001.yaml`
- Upstream license at the pinned revision: Apache License 2.0.
- Current state: **REDISTRIBUTION CONDITIONALLY CLEARABLE** — include applicable Apache-2.0 license/notice obligations and review the exact CAR corpus selected for the Public Preview pack.

### MITRE D3FEND

- Atlas source profile: `ingestion/source-profiles/mitre-d3fend-ontology.release.json`
- Ontology version: `1.6.0`
- Pinned ontology SHA-256: `sha256-4909a5bb66b75d2c359624398848936fb56a6b246bcd5cfcd277977a1277753a`
- Upstream repository/release merge commit: `d3fend/d3fend-ontology@6f888567acb359328ebd1e793b7e01581b6a03ed`
- Upstream repository license at that revision: MIT License.
- Current state: **REDISTRIBUTION CONDITIONALLY CLEARABLE** — preserve copyright/license text and bind the exact ontology digest to release evidence.

### Microsoft Windows Security documentation

- Atlas source profile: `ingestion/source-profiles/microsoft-windows-security-auditing-4688-doc.release.json`.
- The current authoritative reference is a Microsoft Learn previous-versions page rather than a repository revision with an explicit content license pinned by Atlas.
- Current state: **SOURCE TEXT EXCLUDED FROM PUBLIC PACK**.
- Public Preview may retain the source URL as provenance and may include independently authored Atlas facts, identifiers, field semantics and analysis, but it must not package verbatim or substantial Microsoft Learn documentation text unless separate redistribution rights are later established.
- This exclusion removes ambiguous Microsoft Learn page text from the redistributable payload rather than treating public web visibility as redistribution permission.

### Microsoft Sysinternals / Sysmon documentation

- Atlas source profile: `ingestion/source-profiles/microsoft-sysmon-docs.release.json`
- Declared Sysmon documentation release context: `15.22`
- Upstream docs repository: `MicrosoftDocs/sysinternals`
- Pinned docs commit: `2fd3249657118505564fd220e672e8ea45d35916`
- Pinned document: `sysinternals/downloads/sysmon.md`
- Controlled telemetry-schema evidence is now promoted to Sysmon `15.22` / schema `4.91` from the reviewed reference-host export. The prior `15.21` inventory is retained as historical evidence, and semantic documentation freshness remains tracked independently from structural schema evidence.
- The repository `LICENSE` at the same pinned revision is **Creative Commons Attribution 4.0 International (CC-BY-4.0)** for documentation content.
- Current state: **REDISTRIBUTION CONDITIONALLY CLEARABLE** — exact included material must retain required source/copyright/license attribution, indicate modifications where applicable, and avoid any Microsoft trademark or endorsement implication.

### Cyber-Sentinel DefenseOps

- DefenseOps is an engineering provenance source, not automatically redistributable ATLAS content.
- Current DefenseOps `main` has no project `LICENSE` published.
- Current state: **DO NOT REDISTRIBUTE INTO PUBLIC ATLAS PACK** unless exact source material acquires compatible, explicit rights and attribution evidence.

### Future sources (LOLBAS, GTFOBins, vendor references, community repositories)

- Current state: **OUT OF PUBLIC PACK BY DEFAULT**.
- No source is admitted because it is merely public or technically ingestible. Each source requires exact version/license/attribution review before promotion.

## B.1 Deterministic notice-bundle generation

`tools/release/generate_public_preview_notice_bundle.py` converts the machine-readable redistribution inventory into deterministic human-readable notice metadata without inventing rights or upstream license text.

Two modes are intentionally separate:

- **draft mode** — succeeds while PPR-04 is still BLOCKED, records every included/excluded boundary, marks the package SHA as `UNBOUND` unless supplied, and states `DRAFT / NOT RELEASE AUTHORITY`;
- **release mode** — fails closed unless the inventory is already `PASS`, the software payload and public corpus are frozen, every included entry is `ACCEPTED`, and the supplied package SHA-256 exactly matches the inventory binding.

The Phase 5.10.1 workflow generates and uploads the draft on relevant changes so notice rendering remains executable evidence rather than a manually maintained release claim. Draft generation does not change redistribution state.

## B.2 Pinned upstream license material

ATLAS now keeps byte-identical copies of the upstream license material for the four conditionally-clearable knowledge sources selected by the current PPR-04 inventory:

- MITRE ATT&CK Enterprise;
- MITRE CAR;
- MITRE D3FEND ontology;
- Microsoft Sysinternals / Sysmon documentation.

The authoritative mapping is `third_party/license-material/manifest.json`. Each material entry records the exact upstream repository, pinned commit, upstream path, upstream Git blob SHA-1 and local path.

`tools/release/validate_pinned_license_material.py` reconstructs the Git blob object ID from the local bytes and requires it to match the recorded upstream blob exactly. It also emits SHA-256 and size evidence for later package binding.

This is **evidence only**. The local presence of upstream license material does not promote an inventory entry to `ACCEPTED`, does not determine legal compatibility, and does not authorize publication.

## C. Public Preview pack construction rule

The Public Preview corpus must be an allowlist, not a denylist. Pack build input must identify each included source target and its redistribution decision. A source target with any state other than an explicitly accepted redistributable state must cause pack publication to fail.

Recommended machine-readable release record fields:

```text
source_id
upstream_revision
content_digest
license_id_or_terms_class
license_source
redistribution_state
required_notices
attribution_text
review_evidence
release_package_sha256
```

## D. Remaining PPR-04 closure work

PPR-04 remains **BLOCKED** until all of the following are complete:

- exact Public Preview knowledge-corpus allowlist is selected;
- pinned byte-identical license material for ATT&CK/CAR/D3FEND/Sysmon is now available and CI-verified; the entries still require explicit reviewed promotion to exact `ACCEPTED` release entries with final attribution/material-selection evidence;
- exact Rust/Tauri preflight dependency/license and frontend-asset evidence is automated; final evidence must still be regenerated and bound to the frozen release build/package;
- final release assets/fonts/icons, including generated/bundled artifacts outside the source `www` tree, are inventoried;
- deterministic draft notice generation is automated; the final third-party license/NOTICE bundle must still be generated in strict release mode and must include the separately pinned upstream license/notice material required by each accepted entry;
- a machine-readable redistribution manifest is bound to the exact Public Preview package SHA-256;
- no unresolved/unknown item remains.

This document does not change PPR-03, PPR-05, PPR-06, or PPR-07 and does not authorize publication.
