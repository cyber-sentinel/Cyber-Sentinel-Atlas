package search_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cyber-sentinel/Cyber-Sentinel-Atlas/shared-core/go/internal/graph"
	"github.com/cyber-sentinel/Cyber-Sentinel-Atlas/shared-core/go/internal/search"
)

type queryExpectation struct {
	Status  string   `json:"status"`
	Stage   string   `json:"stage"`
	Targets []string `json:"targets"`
}

type oracleEvidence struct {
	Bundle  search.Bundle               `json:"bundle"`
	Queries map[string]queryExpectation `json:"queries"`
	Browse  []string                    `json:"browse"`
	Facets  []search.FacetValue         `json:"facets"`
	Numeric []search.NumericIdentifier  `json:"numeric"`
	Graph   []graph.Pivot               `json:"graph"`
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func buildPythonOracle(t *testing.T) (string, oracleEvidence) {
	t.Helper()
	root := repoRoot(t)
	temp := t.TempDir()
	indexPath := filepath.Join(temp, "atlas-phase554b.sqlite3")
	oraclePath := filepath.Join(temp, "oracle.json")

	const script = `
import json, sys
from pathlib import Path
root = Path(sys.argv[1])
index_path = Path(sys.argv[2])
out_path = Path(sys.argv[3])
sys.path.insert(0, str(root / "tools" / "search"))
import catalog_graph
fixture = json.loads((root / "fixtures" / "phase-5.4.4" / "catalog-graph-corpus.json").read_text(encoding="utf-8"))
bundle = catalog_graph.build_phase544_bundle(fixture)
catalog_graph.search.build_index(bundle, index_path)
queries = [
    "atlas:event:microsoft.windows.security:4688",
    "1",
    "sysmon 1",
    "Event ID 4688",
    "docker exec start",
    "PowerShell",
    "provider:mitre PowerShell",
]
with catalog_graph.search.SQLiteSearchCore.open(index_path, expected_bundle=bundle) as core:
    runtime = catalog_graph.CatalogGraphRuntime(core, bundle)
    q = {}
    for query in queries:
        result = core.resolve(query, graph_depth=1, limit=20)
        q[query] = {
            "status": result["status"],
            "stage": result["match_stage"],
            "targets": [item["target_id"] for item in result["matches"]],
        }
    browse = [item["target_id"] for item in runtime.browse(filters={"provider":"microsoft-windows-security-auditing"}, limit=20)]
    facets = runtime.facet_values("provider", limit=100)
    numeric = runtime.numeric_event_ids(namespace="microsoft.windows.security", limit=20)
    graph = runtime.graph_expand(["atlas:activity:synthetic.graph:a"], depth=2, direction="both", limit=100)
out = {"bundle": bundle, "queries": q, "browse": browse, "facets": facets, "numeric": numeric, "graph": graph}
out_path.write_text(json.dumps(out, ensure_ascii=False, sort_keys=True), encoding="utf-8")
`
	cmd := exec.Command("python", "-c", script, root, indexPath, oraclePath)
	cmd.Dir = root
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build Python search oracle: %v\n%s", err, output)
	}
	data, err := os.ReadFile(oraclePath)
	if err != nil {
		t.Fatal(err)
	}
	var evidence oracleEvidence
	if err := json.Unmarshal(data, &evidence); err != nil {
		t.Fatalf("decode Python oracle: %v", err)
	}
	return indexPath, evidence
}

func targetIDs(result search.Result) []string {
	ids := make([]string, 0, len(result.Matches))
	for _, match := range result.Matches {
		ids = append(ids, match.TargetID)
	}
	return ids
}

func TestPythonOracleSearchCatalogGraphParity(t *testing.T) {
	indexPath, oracle := buildPythonOracle(t)
	core, err := search.Open(indexPath, &oracle.Bundle)
	if err != nil {
		t.Fatalf("open Go search core over Python index: %v", err)
	}
	defer core.Close()

	if got := core.Manifest()["bundle_digest"]; got != oracle.Bundle.BundleDigest {
		t.Fatalf("bundle binding mismatch: %q != %q", got, oracle.Bundle.BundleDigest)
	}
	for query, want := range oracle.Queries {
		result, err := core.Resolve(query, 1, search.DefaultTopK)
		if err != nil {
			t.Fatalf("resolve %q: %v", query, err)
		}
		if result.Status != want.Status || result.MatchStage != want.Stage || !reflect.DeepEqual(targetIDs(result), want.Targets) {
			t.Fatalf("query parity %q: got status=%s stage=%s targets=%v; want status=%s stage=%s targets=%v",
				query, result.Status, result.MatchStage, targetIDs(result), want.Status, want.Stage, want.Targets)
		}
	}

	items, err := core.Browse(map[string]string{"provider": "microsoft-windows-security-auditing"}, 20)
	if err != nil {
		t.Fatal(err)
	}
	browse := make([]string, 0, len(items))
	for _, item := range items {
		browse = append(browse, item.TargetID)
	}
	if !reflect.DeepEqual(browse, oracle.Browse) {
		t.Fatalf("catalog browse parity: got %v want %v", browse, oracle.Browse)
	}

	facets, err := core.FacetValues("provider", nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(facets, oracle.Facets) {
		t.Fatalf("facet parity: got %#v want %#v", facets, oracle.Facets)
	}

	numeric, err := core.NumericBrowse("microsoft.windows.security", "event_id", 20)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(numeric, oracle.Numeric) {
		t.Fatalf("numeric browse parity: got %#v want %#v", numeric, oracle.Numeric)
	}

	graphRuntime, err := graph.New(&oracle.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	pivots, err := graphRuntime.Expand([]string{"atlas:activity:synthetic.graph:a"}, 2, nil, "both", 100)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(pivots, oracle.Graph) {
		t.Fatalf("graph parity: got %#v want %#v", pivots, oracle.Graph)
	}
}

func TestSearchBoundsFailClosedAndIndexBinding(t *testing.T) {
	indexPath, oracle := buildPythonOracle(t)
	core, err := search.Open(indexPath, &oracle.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()

	badQueries := []struct {
		query string
		depth int
		limit int
	}{
		{query: string([]byte{0xff, 0xfe}), depth: 1, limit: 20},
		{query: strings.Repeat("x", search.MaxQueryScalars+1), depth: 1, limit: 20},
		{query: strings.Repeat("term ", search.MaxTerms+1), depth: 1, limit: 20},
		{query: "PowerShell", depth: search.MaxGraphDepth + 1, limit: 20},
		{query: "PowerShell", depth: 1, limit: 0},
	}
	for _, tc := range badQueries {
		if _, err := core.Resolve(tc.query, tc.depth, tc.limit); err == nil {
			t.Fatalf("bounded query should fail: depth=%d limit=%d query=%q", tc.depth, tc.limit, tc.query)
		}
	}
	if _, err := core.Browse(map[string]string{"unsupported": "x"}, 20); err == nil {
		t.Fatal("unsupported catalog filter must fail")
	}
	if _, err := core.FacetValues("unsupported", nil, 20); err == nil {
		t.Fatal("unsupported facet must fail")
	}

	stale := oracle.Bundle
	stale.BundleDigest = "sha256-0000000000000000000000000000000000000000000000000000000000000000"
	if staleCore, err := search.Open(indexPath, &stale); err == nil {
		staleCore.Close()
		t.Fatal("stale SPC binding must fail closed")
	}
}

func TestSearchPerformanceRegressionGate(t *testing.T) {
	indexPath, oracle := buildPythonOracle(t)
	core, err := search.Open(indexPath, &oracle.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()

	started := time.Now()
	for i := 0; i < 200; i++ {
		if _, err := core.Resolve("PowerShell", 1, 20); err != nil {
			t.Fatal(err)
		}
		if _, err := core.Resolve("sysmon 1", 1, 20); err != nil {
			t.Fatal(err)
		}
	}
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Fatalf("Phase 5.5.4B search regression gate exceeded: %v", elapsed)
	}
}
