# Phase 5.4.4 Search Closure Benchmark

This benchmark is the permanent regression profile for the deterministic search/catalog/graph closure.

Default profile:

- 20,000 deterministic SearchDocuments;
- final Phase 5.4.4 acceptance identities preserved;
- high-fanout lexical term present in roughly 20% of synthetic documents;
- provider/lifecycle/version facet density across the synthetic corpus;
- a 1,000-edge deterministic `RELATED_TO` chain in addition to the final acceptance graph cycle;
- 40 process-warm iterations per measured operation;
- no network dependency.

Measured operations:

1. exact native identifier lookup (`4688`);
2. high-fanout FTS5 lexical lookup (`benchmarkfanout`);
3. provider catalog browse;
4. lifecycle catalog browse;
5. provider-scoped numeric Event ID browse;
6. bounded depth-2 graph expansion.

The JSON evidence records the environment, corpus/SPC binding, engine versions, index size/build time, latency percentiles and correctness checks. CI fails when exact P95 reaches 100 ms, when lexical P95 reaches 300 ms, or when catalog/numeric/graph P95 reaches 300 ms.

Run locally:

```bash
python benchmarks/search/phase544/benchmark.py --docs 20000 --iterations 40 --output phase544-benchmark.json
```

Performance evidence is scoped to the environment recorded in each output file; it is not a universal hardware-independent claim.
