# UX Information Architecture

## UX Goal

Make Atlas feel like a modern analyst instrument, not a documentation portal.

## Home / Command Center

Primary element:

```text
Search events, TTPs, fields, artifacts, detections…
[                                                   ]
```

Secondary quick scopes:

- Windows
- Sysmon
- Active Directory
- PowerShell
- ATT&CK
- Detections
- Hunts
- DFIR

## Search Interaction

Keyboard-first:

- `/` focus search;
- arrow keys move results;
- Enter opens entity;
- Cmd/Ctrl+K opens command palette;
- shortcuts for copy/open-related/source.

## Entity Page Layout

### Header

- entity type;
- canonical ID;
- title;
- platform;
- freshness;
- validation state.

### Main Content

- meaning;
- important fields;
- security significance;
- investigation notes.

### Relationship Rail

- related events;
- ATT&CK;
- detections;
- hunts;
- artifacts;
- controls.

### Evidence Panel

Every important claim can reveal its source and provenance without navigating away.

## Visual Direction

- modern, high-contrast, professional;
- dark and light mode;
- minimal decorative cyber imagery;
- dense information with strong hierarchy;
- graph visualization only where it adds analytic value;
- responsive layout;
- accessibility from the start.

## AI UX

AI is a side panel / command capability, not the home screen.

The user must always be able to inspect:

- evidence used;
- entities referenced;
- uncertainty;
- whether the answer came from canonical or draft content.
