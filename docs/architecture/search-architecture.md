# Search Architecture

## Search Goal

A user should be able to type an identifier, phrase, behavior, field, tool name, or question and get the correct entity before getting a clever answer.

## Retrieval Stages

### 1. Exact Resolver

Highest priority.

Examples:

- `4688`
- `Event ID 4688`
- `Sysmon 1`
- `T1059.001`
- `DET-WIN-001`

Exact identifiers resolve deterministically.

### 2. Structured Filters

Examples:

- platform:windows
- provider:security
- attack:T1059.001
- validation:Q2
- engine:splunk-spl

### 3. Lexical Search

BM25/FTS across:

- titles;
- aliases;
- descriptions;
- field names;
- normalized claims;
- references.

### 4. Graph Expansion

Boost directly related entities:

- related events;
- parent/child techniques;
- detections;
- hunts;
- forensic artifacts.

### 5. Semantic Retrieval

Used when exact/lexical retrieval is insufficient.

Semantic search must never outrank a clear exact identifier match.

## Ranking Signals

- exact identifier match;
- canonical title match;
- alias match;
- platform context;
- authoritative-source confidence;
- freshness;
- relationship proximity;
- validation maturity;
- lexical relevance;
- semantic relevance.

## Search Output

Results should display:

- entity type;
- canonical identifier;
- platform;
- one-line meaning;
- validation/freshness indicators;
- source confidence.

## Performance Targets for MVP

- exact local lookup: target <100 ms;
- normal local search: target <300 ms;
- offline core search available with no network;
- AI answer latency must not block basic search.
