# Cyber-Sentinel-Atlas Roadmap

## Phase 5.1 — Product Foundation

Status: **In progress / foundation authored**

- product vision;
- positioning;
- personas;
- knowledge graph;
- provenance;
- search;
- AI/RAG;
- offline-first;
- API/CLI;
- security;
- UX;
- MVP scope;
- ADRs;
- foundation CI.

## Phase 5.2 — Canonical Data Model

- production schemas;
- canonical identifier conventions;
- claim model;
- relationship model;
- source registry schema;
- validation records;
- migration/version strategy.

## Phase 5.3 — Source & Ingestion Core

Initial authoritative sources:

- Microsoft Windows event documentation;
- Microsoft Sysinternals Sysmon;
- MITRE ATT&CK;
- DefenseOps validated content.

Outputs:

- source adapters;
- normalization;
- deduplication;
- provenance;
- freshness;
- tests.

## Phase 5.4 — Search Core

- exact resolver;
- lexical index;
- filters;
- graph traversal;
- ranking;
- benchmarks.

## Phase 5.5 — MVP Web/PWA

- command-center search;
- event/entity pages;
- relationship navigation;
- source/evidence panel;
- responsive dark/light UI;
- offline shell.

## Phase 5.6 — Offline Packs

- pack format;
- signed manifests;
- checksum verification;
- local index;
- atomic update;
- first Windows/Sysmon/ATT&CK/DefenseOps pack.

## Phase 5.7 — API & CLI

- read API;
- search;
- graph;
- sources;
- packs;
- Atlas CLI.

## Phase 5.8 — Grounded AI

Only after deterministic retrieval and provenance are mature:

- entity-aware Q&A;
- evidence-grounded explanations;
- investigation pivots;
- cited summaries;
- offline model option later.

## Phase 5.9 — Public Preview Readiness

- security review;
- licensing review;
- performance;
- accessibility;
- contributor workflow;
- public documentation;
- launch criteria.

## Expansion After MVP

- Linux;
- macOS;
- Exchange;
- SharePoint;
- Azure;
- AWS;
- Google Cloud;
- Docker;
- Kubernetes;
- CI/CD;
- SQL Server;
- MongoDB;
- MariaDB;
- broader DFIR/IR/deception content.
