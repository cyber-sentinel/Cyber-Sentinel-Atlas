# Product Vision

## Vision

Build the fastest, most trustworthy, and most operationally useful cyber defense reference and investigation platform for analysts, detection engineers, incident responders, security architects, and defenders worldwide.

Atlas should allow a defender to move from **a raw technical signal** to **security meaning and action** without opening ten unrelated documentation sources.

## Example User Journey

A user searches:

`4688`

Atlas should resolve this to the Windows Security event and provide, without mixing unrelated semantics:

- canonical event identity;
- platform and provider;
- prerequisites / audit-policy context;
- important fields;
- security relevance;
- related Windows and Sysmon events;
- ATT&CK mappings;
- detection opportunities;
- Splunk SPL;
- Microsoft Kusto Query Language (KQL);
- Elastic Kibana Query Language (KQL);
- Elastic Event Query Language (EQL) where applicable;
- Sigma;
- Wazuh or other native mappings where applicable;
- threat-hunting pivots;
- forensic relevance;
- false-positive considerations;
- investigation workflow;
- response implications;
- source-backed claims;
- version and freshness metadata.

## North Star

**Time-to-understanding and time-to-investigation should be materially lower than using fragmented vendor documentation and disconnected rule repositories.**

## Product Outcomes

Atlas succeeds when users can:

1. find a security concept or event in seconds;
2. understand why it matters;
3. traverse relationships without losing context;
4. inspect the exact evidence behind a claim;
5. translate knowledge into detection or investigation work;
6. operate with or without Internet access;
7. trust that AI assistance is grounded in inspectable sources;
8. contribute corrections through a reviewable engineering workflow.

## Non-Goals

Atlas is not intended to:

- replace SIEM, EDR, SOAR, or CTI platforms;
- claim production validation for vendor-specific content without evidence;
- host offensive tradecraft for uncontrolled use;
- scrape and republish copyrighted documentation wholesale;
- obscure uncertainty behind AI-generated prose;
- force every security concept into every query language or detection engine.
