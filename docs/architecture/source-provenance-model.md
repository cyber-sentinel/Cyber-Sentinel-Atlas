# Source & Provenance Model

## Objective

Make Atlas trustworthy enough that a user can inspect why a technical statement exists, where it came from, whether it is current, and how it entered a released content pack.

## Source Classes

### Tier A — Authoritative

Preferred source of truth:

- Microsoft Learn / Microsoft Sysinternals for Windows and Sysmon;
- official MITRE ATT&CK, D3FEND, and CAR sources;
- vendor product documentation;
- standards bodies and specifications;
- official project documentation and repositories.

Canonical Microsoft references:

- Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Sysinternals: https://learn.microsoft.com/en-us/sysinternals/

### Tier B — Primary Engineering

High-value original engineering sources:

- vendor-maintained detection repositories;
- official open-source project repositories;
- maintainers' technical specifications;
- Cyber-Sentinel-DefenseOps validated engineering content.

Tier B engineering content does not become authoritative merely because it is validated engineering content.

### Tier C — Secondary Research

May support context but should not override authoritative sources without review.

UltimateWindowsSecurity and similar references belong here unless a more specific classification is justified.

### Tier D — Community

Useful for discovery, edge cases, and experience reports. Must not silently become authoritative.

## Claim Provenance Fields

Every material claim should support:

- source_id;
- source_url;
- source_title;
- publisher;
- source_class;
- retrieved_at;
- published_at when available;
- source_version;
- applicable_product_version;
- quote_locator or section locator;
- license / terms metadata;
- transformation type;
- reviewer status.

## Transformation Types

- direct structured import;
- normalized fact;
- human-authored synthesis;
- DefenseOps-derived engineering content;
- AI-assisted draft;
- machine-generated relationship;
- manually validated relationship.

## Controlled Publication Boundary

No upstream source or connector directly mutates the production/public Atlas dataset.

All released content follows the controlled pipeline documented in [Controlled Content Release Pipeline](content-release-pipeline.md).

## AI Rule

AI-assisted content is never promoted to trusted knowledge solely because a model produced it.

Promotion requires:

1. inspectable source evidence;
2. schema validation;
3. provenance metadata;
4. confidence assignment;
5. human or deterministic validation according to content class.

## Source Freshness

Each source connector must define:

- expected update cadence;
- stale threshold;
- last successful refresh;
- checksum/version;
- change detection strategy.

## Licensing Rule

Atlas should store normalized facts and attribution metadata, not indiscriminately mirror copyrighted documentation.

Any source ingestion must record redistribution and licensing constraints before public release.
