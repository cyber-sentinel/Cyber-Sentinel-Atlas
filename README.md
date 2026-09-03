# Cyber-Sentinel-Atlas

**Intelligent Cyber Defense Knowledge & Investigation Platform**

Cyber-Sentinel-Atlas is the signature product of the Cyber-Sentinel ecosystem: a vendor-neutral, analyst-first platform that connects telemetry, security events, adversary behavior, detections, hunts, forensic artifacts, defensive controls, investigation procedures, and response guidance into a source-backed knowledge system.

> Status: **Phase 5.1 — Product Foundation**  
> Visibility: **Private during active development**

## Product Thesis

Cyber defense knowledge is fragmented across operating systems, SIEMs, EDRs, cloud platforms, container runtimes, databases, vendor documentation, detection repositories, threat intelligence, and incident-response references.

Atlas makes those relationships searchable and operational:

```text
Platform / Technology
        ↓
Telemetry Source
        ↓
Event / Log / Artifact
        ↓
Security Meaning / Behavior
        ↓
ATT&CK / D3FEND / CAR
        ↓
Detection / Hunt
        ↓
Investigation / DFIR
        ↓
Response / Defensive Action
        ↓
Claim-level Sources & Provenance
```

## Product Position

Atlas is **not**:

- another Event ID wiki;
- another detection-rule repository;
- another ATT&CK browser;
- another SIEM-specific content portal;
- an AI chatbot without verifiable sources.

Atlas is designed as a **cyber defense knowledge graph + analyst workbench**.

## Planned Interfaces

- Web application / PWA
- Offline knowledge packs
- Desktop experience
- REST/Graph API
- CLI
- Grounded AI assistant with mandatory source attribution

## Initial MVP Domain

The first usable MVP intentionally starts narrow:

- Windows Security Events
- Sysmon
- PowerShell
- Active Directory
- MITRE ATT&CK relationships
- DefenseOps detections and hunts
- Investigation pivots
- Official-source provenance
- Fast exact/event search
- Offline-first local dataset

The architecture is intentionally extensible to Linux, macOS, Exchange, SharePoint, Azure, AWS, Google Cloud, Docker, Kubernetes, databases, CI/CD, DFIR, incident response, and cyber deception.

## Ecosystem

```text
Cyber-Sentinel
├── DefenseOps  → validated defensive engineering content
└── Atlas       → knowledge graph, search, analyst workspace, API and CLI
```

DefenseOps is an engineering source. Atlas is the product and knowledge layer.

## Foundation Documents

- [Product Vision](docs/product/product-vision.md)
- [Product Principles](docs/product/product-principles.md)
- [Personas](docs/product/personas.md)
- [Competitive Positioning](docs/product/competitive-positioning.md)
- [System Context](docs/architecture/system-context.md)
- [Knowledge Graph Model](docs/architecture/knowledge-graph-model.md)
- [Source & Provenance Model](docs/architecture/source-provenance-model.md)
- [Search Architecture](docs/architecture/search-architecture.md)
- [AI / RAG Architecture](docs/architecture/ai-rag-architecture.md)
- [Offline-first Architecture](docs/architecture/offline-first-architecture.md)
- [API / CLI Architecture](docs/architecture/api-cli-architecture.md)
- [Security Architecture](docs/architecture/security-architecture.md)
- [UX Information Architecture](docs/ux/ux-information-architecture.md)
- [MVP Scope](docs/mvp/mvp-scope.md)
- [MVP Release Gates](docs/mvp/release-gates.md)
- [Roadmap](docs/roadmap.md)

## Core Principle

> **No technical claim without provenance. No AI answer without inspectable evidence. No engine-specific syntax confused with the underlying security concept.**

---

**Maintainer:** Ali RahimDabagh  
**GitHub:** `cyber-sentinel`
