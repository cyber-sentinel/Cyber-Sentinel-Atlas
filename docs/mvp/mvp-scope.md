# MVP Scope

## MVP Objective

Deliver a product that is already useful to Windows/SOC analysts before expanding horizontally.

## In Scope

### Content

- Windows Security Events — prioritized security-relevant subset;
- Sysmon Events;
- PowerShell operational/security telemetry;
- Active Directory relationships;
- MITRE ATT&CK mappings;
- selected D3FEND relationships where authoritative mapping is defensible;
- DefenseOps Windows PowerShell/LOLBin detections;
- DefenseOps threat hunts;
- investigation pivots;
- source/provenance metadata.

### Product

- global exact/lexical search;
- entity pages;
- related-entity navigation;
- claim-level source panel;
- filters;
- saved/bookmarked entities;
- offline core dataset;
- PWA shell;
- import/update mechanism for Atlas packs;
- read-only API;
- initial CLI read/search commands.

### Quality

- schema validation;
- link/source validation where technically possible;
- duplicate canonical-ID checks;
- provenance-required checks;
- version/freshness checks;
- CI.

## Explicitly Deferred

- full cloud coverage;
- full Linux/macOS coverage;
- every database;
- live SIEM integrations;
- enterprise multi-tenancy;
- production SOAR actions;
- automatic remediation;
- broad generative query conversion without validation;
- large social/community features.

## MVP Success Criteria

A Windows analyst can:

1. search Event ID 4688 and land on the correct entity instantly;
2. inspect meaning and important fields;
3. traverse to Sysmon/ATT&CK/detections/hunts;
4. inspect source-backed claims;
5. use the same core content offline;
6. copy a relevant validated query where available;
7. understand validation and applicability limitations.
