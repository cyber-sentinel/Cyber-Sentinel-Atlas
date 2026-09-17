# Accessibility Release Review

Status: **PARTIAL — RELEASE REVIEW NOT YET CLOSED**

Applies to: Cyber-Sentinel ATLAS Windows Public Preview UI.

## Objective

ATLAS must remain usable for analysts who rely on keyboard navigation, Windows accessibility settings, high contrast, scaling, and assistive technologies. Existing UI controls are not sufficient evidence by themselves; Public Preview requires a release review against the packaged application.

## Current evidence

The First Preview includes accessibility-oriented labels and high-contrast controls, and the selected Windows host has already been evaluated for keyboard/accessibility/DPI feasibility. This is meaningful engineering evidence, but it is not yet the complete release review required by PPR-07.

## Mandatory review matrix

The Public Preview candidate must be tested on the exact packaged build for the following:

| Area | Acceptance requirement |
| --- | --- |
| Keyboard navigation | Every primary workflow can be completed without a pointing device; focus order is logical and visible |
| Focus visibility | Interactive controls expose a visible focus state in normal and high-contrast modes |
| Accessible names | Buttons, inputs, navigation items, status controls, and icon-only actions expose meaningful accessible names |
| Semantic structure | Headings, landmarks, form controls, tables/lists, and status regions use appropriate semantics |
| Screen reader | Core search, record detail, provenance, pack status/update/rollback and diagnostics are understandable with Windows Narrator |
| High contrast | Content remains readable and controls remain distinguishable under Windows high-contrast themes |
| Scaling | UI remains usable at 100%, 125%, 150%, 175% and 200% display scaling on a supported Windows configuration |
| Text zoom / reflow | Text enlargement does not hide critical controls or force unreadable overlap in primary workflows |
| Color dependence | Security state is not conveyed by color alone; text/icon/state labels provide equivalent meaning |
| Error handling | Validation, trust, update, rollback and sidecar-integrity errors are programmatically and visually understandable |
| Motion | No required workflow depends on animation; distracting motion is avoidable or non-essential |
| Localization resilience | UTC/system-local/Tehran-Jalali presentation does not break focus, labels or layout |

## Primary workflows under review

1. launch ATLAS and establish Shared Core session;
2. run offline global search;
3. inspect canonical record/entity detail;
4. navigate bounded relationships/graph pivots;
5. inspect claim/source provenance;
6. inspect verified pack state;
7. perform verified pack update;
8. perform safe rollback/recovery;
9. inspect diagnostics and failure states;
10. change accessibility/high-contrast presentation controls.

## Evidence required for PASS

PPR-07 may move to `PASS` only when the exact release candidate has:

- completed the matrix above on Windows;
- recorded tester, build hash/version, OS build, WebView2/runtime version and display configuration;
- recorded pass/fail/notes for every primary workflow;
- resolved or explicitly blocked any severity-high accessibility defect;
- linked review evidence from the release record;
- retained automated/static accessibility checks where practical without treating them as a substitute for packaged-app review.

## Defect severity

- **A11Y-1 / Release blocking:** primary workflow impossible by keyboard or assistive technology; inaccessible destructive/security-significant action; unreadable critical trust/security state.
- **A11Y-2 / Must fix before Public Preview unless explicitly accepted with compensating control:** substantial navigation, scaling, naming or contrast impairment.
- **A11Y-3 / Improvement:** cosmetic or low-impact issue with a usable alternative path.

## Fail-closed release rule

PPR-07 remains `PARTIAL` until the packaged Public Preview candidate has completed this review. Documentation or source-level inspection alone must not be used to relabel the gate as PASS.

## Review record template

The actual review evidence should be stored as a versioned artifact or repository document and contain:

- release candidate/version;
- commit and package SHA-256;
- review date/time in UTC;
- tester/reviewer;
- Windows build and runtime versions;
- display/scaling/high-contrast configurations;
- screen-reader configuration;
- matrix results;
- defects and disposition;
- final PPR-07 decision.

This document defines the acceptance contract for PPR-07 while preserving its current `PARTIAL` state until executable release evidence exists.
