# Product Principles

## 1. Source First

Every technical claim that could materially affect analyst decisions must be attributable to one or more sources.

## 2. Canonical Concept Before Vendor Syntax

The underlying event, behavior, artifact, or technique is canonical. Vendor-specific queries are representations and operationalizations of that concept.

## 3. Exact Before Intelligent

Exact identifiers such as Event ID, Sysmon ID, ATT&CK ID, CVE, rule ID, provider name, and field name must resolve deterministically before semantic ranking is applied.

## 4. AI Must Be Grounded

AI may summarize, correlate, explain, and propose pivots. It must not silently invent facts, mappings, citations, or engine syntax.

## 5. Offline Is a First-Class Mode

Core search, entity pages, relationships, citations, and saved investigation context must work without Internet access.

## 6. Validation Status Is Explicit

Content may be Draft, Static Validated, Engine Validated, Fixture Validated, Lab Validated, Production Candidate, or Production Validated. Atlas must never collapse those states.

## 7. Applicability Beats Coverage Count

If a rule format is not technically applicable to a behavior, Atlas should say N/A rather than manufacture a misleading translation.

## 8. Fast Analyst UX

Keyboard-first navigation, global search, dense-but-readable evidence views, and minimal navigation depth are preferred over decorative dashboards.

## 9. Version Everything That Can Drift

Sources, products, schemas, event semantics, ATT&CK relationships, query syntax, and imported packs must retain version/freshness information.

## 10. Public Trust Before Public Launch

The repository remains private until provenance, licensing, validation, security, content quality, and release gates are satisfied.
