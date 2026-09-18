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

## A. Production software/runtime payload

The Public Preview software inventory must be generated from the exact built artifacts, not inferred only from source manifests.

| Component family | Current pinned/observed boundary | Current control state | Release requirement |
| --- | --- | --- | --- |
| Go Shared Core | Go `1.25.13`; module graph in `shared-core/go/go.mod` | **TECHNICAL EVIDENCE AVAILABLE** | Bind exact linked-module SBOM + license evidence to release binary |
| TUF Go runtime | `github.com/theupdateframework/go-tuf/v2 v2.4.2` | **TECHNICAL EVIDENCE AVAILABLE** | Include if linked/distributed; preserve license evidence |
| SQLite Go implementation | `modernc.org/sqlite v1.58.0` | **TECHNICAL EVIDENCE AVAILABLE** | Bind linked dependency and license evidence to release binary |
| Go text/runtime dependencies | `golang.org/x/text v0.39.0` plus indirect locked modules | **TECHNICAL EVIDENCE AVAILABLE** | Use generated SBOM/license validation; do not maintain a hand-written substitute |
| Tauri desktop host | Tauri `2.11.5`, committed/hash-guarded Cargo lock | **INVENTORY REQUIRED FOR PUBLIC ARTIFACT** | Generate exact Rust/Cargo SBOM/license report from release lock/build |
| `serde_json` / `sha2` and transitive Rust crates | Exact versions resolved by committed Cargo lock | **INVENTORY REQUIRED FOR PUBLIC ARTIFACT** | Include exact crate/license/notice inventory generated from the release lock |
| Microsoft Edge WebView2 Runtime | Runtime prerequisite; current portable First Preview does not claim redistribution of WebView2 binaries | **NOT BUNDLED IN CURRENT PORTABLE MODEL** | If a future installer bundles/bootstrap-downloads WebView2, review Microsoft's redistribution terms for that exact installer model |
| Product artwork/UI assets | Cyber-Sentinel repository assets unless separately attributed | **FIRST-PARTY/REVIEW REQUIRED** | Confirm every shipped font/icon/image has recorded origin and rights; no untracked asset may enter release payload |

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
- Declared Sysmon release context: `15.21`
- Upstream docs repository: `MicrosoftDocs/sysinternals`
- Pinned docs commit: `8e3453544f1e417c481d5f6a368ce0e8bbf6a8e6`
- Pinned document: `sysinternals/downloads/sysmon.md`
- The repository `LICENSE` at the same pinned revision is **Creative Commons Attribution 4.0 International (CC-BY-4.0)** for documentation content.
- Current state: **REDISTRIBUTION CONDITIONALLY CLEARABLE** — exact included material must retain required source/copyright/license attribution, indicate modifications where applicable, and avoid any Microsoft trademark or endorsement implication.

### Cyber-Sentinel DefenseOps

- DefenseOps is an engineering provenance source, not automatically redistributable ATLAS content.
- Current DefenseOps `main` has no project `LICENSE` published.
- Current state: **DO NOT REDISTRIBUTE INTO PUBLIC ATLAS PACK** unless exact source material acquires compatible, explicit rights and attribution evidence.

### Future sources (LOLBAS, GTFOBins, vendor references, community repositories)

- Current state: **OUT OF PUBLIC PACK BY DEFAULT**.
- No source is admitted because it is merely public or technically ingestible. Each source requires exact version/license/attribution review before promotion.

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
- conditionally clearable ATT&CK/CAR/D3FEND/Sysmon entries are promoted to exact `ACCEPTED` release entries with final attribution material;
- exact Rust/Tauri release dependency license inventory is generated from the committed lock/build;
- release assets/fonts/icons are inventoried;
- final third-party license/NOTICE bundle is generated;
- a machine-readable redistribution manifest is bound to the exact Public Preview package SHA-256;
- no unresolved/unknown item remains.

This document does not change PPR-03, PPR-05, PPR-06, or PPR-07 and does not authorize publication.
