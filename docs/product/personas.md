# Target Users & Personas

## Primary Personas

### SOC Analyst — Tier 1 / Tier 2

Needs:

- rapid event interpretation;
- related events and pivots;
- ATT&CK context;
- triage guidance;
- false-positive clues;
- copyable SIEM queries;
- evidence-based escalation criteria.

Primary success metric: **time from alert/event to informed triage**.

### Threat Hunter / Detection Engineer

Needs:

- telemetry-to-behavior mappings;
- cross-engine query examples;
- detection coverage;
- field dependencies;
- false positives;
- ATT&CK relationships;
- hunt hypotheses;
- validation status.

Primary success metric: **time from hypothesis to testable analytic**.

### DFIR / Incident Responder

Needs:

- forensic artifacts;
- event timelines;
- related host/network evidence;
- acquisition priorities;
- investigation pivots;
- scope expansion;
- response handoff.

Primary success metric: **time from signal to defensible incident narrative**.

### Security Architect / SOC Architect

Needs:

- telemetry coverage;
- data-source dependencies;
- platform relationships;
- control mappings;
- gaps by ATT&CK technique;
- vendor-neutral architecture context.

Primary success metric: **quality of telemetry and control design decisions**.

## Secondary Personas

### AppSec / DevSecOps Engineer

Future Atlas domains: CI/CD, containers, cloud, secrets, build telemetry, runtime detection, supply-chain events.

### Security Manager / CISO

Needs summarized coverage and capability views, not raw rule detail. Atlas should expose evidence and maturity without pretending to be a GRC platform.

### Educator / Researcher

Needs precise references, relationship exploration, and reproducible technical examples.

## Design Rule

Atlas must not optimize one persona at the cost of making the underlying knowledge model vendor-specific.
