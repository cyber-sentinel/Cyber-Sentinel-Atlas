# AI / RAG Architecture

## Purpose

AI in Atlas is an explanation and investigation accelerator, not the source of truth.

## Allowed AI Capabilities

- explain an event or field;
- summarize connected entities;
- suggest investigation pivots;
- compare telemetry sources;
- translate validated concepts into draft queries;
- summarize change history;
- answer natural-language questions over Atlas knowledge;
- identify likely gaps for analyst review.

## Retrieval Pipeline

```text
User Question
    ↓
Intent / Entity Resolution
    ↓
Exact + Lexical + Graph Retrieval
    ↓
Optional Semantic Retrieval
    ↓
Evidence Set
    ↓
Grounded Generation
    ↓
Citation / Claim Verification
    ↓
Answer
```

## Mandatory Answer Contract

An AI answer that makes factual technical claims must return:

- referenced Atlas entity IDs;
- source-backed evidence;
- confidence;
- applicable platform/version where known;
- explicit uncertainty when evidence is incomplete.

## Prohibited AI Behavior

- fabricated citations;
- silent query-language substitution;
- calling Elastic KQL and Microsoft KQL the same language;
- presenting Draft/Q1 content as production validated;
- inventing ATT&CK mappings;
- answering from model memory when Atlas has contradictory source-backed content.

## Offline AI

AI is optional in offline mode.

The core product must remain useful without a model.

Future offline options may include:

- local embeddings;
- local reranking;
- local LLM;
- no-model deterministic mode.

## RAG Storage Rule

Vector embeddings are derivative indexes. They are rebuildable and must not become the canonical knowledge store.
