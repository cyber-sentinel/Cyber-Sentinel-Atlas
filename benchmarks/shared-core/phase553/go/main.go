package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"
)

type QueryExpectation struct {
	Targets []string `json:"targets"`
	Stage   string   `json:"stage"`
	Status  string   `json:"status"`
}

type Expected struct {
	EvidenceSchemaVersion string                      `json:"evidence_schema_version"`
	Queries               []string                    `json:"queries"`
	QueryExpectations     map[string]QueryExpectation `json:"query_expectations"`
	SPCBundleDigest       string                      `json:"spc_bundle_digest"`
	SearchIndexSHA256     string                      `json:"search_index_sha256"`
	SerializationVector   any                         `json:"serialization_vector"`
	CompactJSONBase64     string                      `json:"compact_json_base64"`
	CompactJSONSHA256     string                      `json:"compact_json_sha256"`
	ValidManifestSHA256   string                      `json:"valid_manifest_sha256"`
}

type QueryEvidence struct {
	Pass    bool     `json:"pass"`
	Targets []string `json:"targets"`
	Stage   string   `json:"stage"`
	Status  string   `json:"status"`
	P95MS   float64  `json:"p95_ms"`
}

type CandidateEvidence struct {
	EvidenceSchemaVersion string                   `json:"evidence_schema_version"`
	Candidate             string                   `json:"candidate"`
	Eligible              bool                     `json:"eligible"`
	Gates                 map[string]bool          `json:"gates"`
	Runtime               map[string]any           `json:"runtime"`
	Dependencies          map[string]string        `json:"dependencies"`
	Bindings              map[string]string        `json:"bindings"`
	Search                map[string]any           `json:"search"`
	Pack                  map[string]any           `json:"pack"`
	State                 map[string]any           `json:"state"`
	KnownLimitations      []string                 `json:"known_limitations"`
}

func sha256Prefixed(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256-" + hex.EncodeToString(sum[:])
}

func readJSON(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

func writeJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

func percentile(values []float64, p float64) float64 {
	if len(values) == 0 {
		return 0
	}
	cpy := append([]float64(nil), values...)
	sort.Float64s(cpy)
	idx := int(float64(len(cpy)-1)*p + 0.5)
	if idx < 0 {
		idx = 0
	}
	if idx >= len(cpy) {
		idx = len(cpy) - 1
	}
	return cpy[idx]
}

func main() {
	workspace := flag.String("workspace", "", "Phase 5.5.3 fixture workspace")
	output := flag.String("output", "", "candidate evidence JSON path")
	flag.Parse()
	if *workspace == "" || *output == "" {
		fmt.Fprintln(os.Stderr, "--workspace and --output are required")
		os.Exit(2)
	}

	var expected Expected
	if err := readJSON(filepath.Join(*workspace, "expected.json"), &expected); err != nil {
		fatalf("load expected evidence: %v", err)
	}

	compact, err := canonicalJSON(expected.SerializationVector)
	if err != nil {
		fatalf("canonical JSON probe: %v", err)
	}
	serializationOK := base64.StdEncoding.EncodeToString(compact) == expected.CompactJSONBase64 && sha256Prefixed(compact) == expected.CompactJSONSHA256

	searchEvidence, sqliteInfo, searchOK, exactP95, lexicalP95, err := runSearchProbe(
		filepath.Join(*workspace, "search", "atlas-search.sqlite3"), expected,
	)
	if err != nil {
		fatalf("search probe: %v", err)
	}

	packEvidence, packOK, err := runTUFProbe(*workspace, expected)
	if err != nil {
		fatalf("TUF probe infrastructure failure: %v", err)
	}

	stateEvidence, stateOK, err := runStateProbe(filepath.Join(*workspace, "go-state-probe"))
	if err != nil {
		fatalf("state probe infrastructure failure: %v", err)
	}

	indexBytes, err := os.ReadFile(filepath.Join(*workspace, "search", "atlas-search.sqlite3"))
	if err != nil {
		fatalf("read search index: %v", err)
	}
	bindingOK := sha256Prefixed(indexBytes) == expected.SearchIndexSHA256
	ftsOK, _ := sqliteInfo["fts5"].(bool)
	gates := map[string]bool{
		"G-SC1": searchOK && bindingOK,
		"G-SC2": serializationOK,
		"G-SC3": searchOK && exactP95 < 100.0 && lexicalP95 < 300.0,
		"G-SC4": searchOK && ftsOK && bindingOK,
		"G-SC5": packOK,
		"G-SC6": stateOK,
		"G-SC7": packOK && stateOK,
		"G-SC8": true,
	}
	eligible := true
	for _, value := range gates {
		eligible = eligible && value
	}

	evidence := CandidateEvidence{
		EvidenceSchemaVersion: "1.0.0",
		Candidate:             "go",
		Eligible:              eligible,
		Gates:                 gates,
		Runtime: map[string]any{
			"go":      runtime.Version(),
			"os":      runtime.GOOS,
			"arch":    runtime.GOARCH,
			"sqlite":  sqliteInfo["version"],
			"fts5":    ftsOK,
			"compiler": runtime.Compiler,
		},
		Dependencies: map[string]string{
			"go-tuf":          "v2.4.2",
			"modernc-sqlite": "v1.58.0",
			"x-text":          "v0.28.0",
		},
		Bindings: map[string]string{
			"spc_bundle_digest":   expected.SPCBundleDigest,
			"search_index_sha256": expected.SearchIndexSHA256,
			"serialization_sha256": expected.CompactJSONSHA256,
		},
		Search: map[string]any{
			"queries":         searchEvidence,
			"exact_p95_ms":    exactP95,
			"lexical_p95_ms":  lexicalP95,
		},
		Pack:             packEvidence,
		State:            stateEvidence,
		KnownLimitations: []string{
			"The spike consumes the already-approved SQLite artifact and ports the frozen resolver contract; it does not freeze Desktop IPC or UI technology.",
			"Go filesystem durability evidence uses fsync on written files plus atomic rename; directory-sync support is platform-dependent and is recorded by the state probe.",
		},
	}

	if err := writeJSON(*output, evidence); err != nil {
		fatalf("write evidence: %v", err)
	}
	fmt.Printf("{\"candidate\":\"go\",\"eligible\":%t,\"timestamp\":%q}\n", eligible, time.Now().UTC().Format(time.RFC3339))
	if !eligible {
		os.Exit(1)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
