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

type SearchStressExpectation struct {
	IndexSHA256             string   `json:"index_sha256"`
	BundleDigest            string   `json:"bundle_digest"`
	LexicalQuery            string   `json:"lexical_query"`
	LexicalExpectedTargets  []string `json:"lexical_expected_targets"`
	NumericNamespace        string   `json:"numeric_namespace"`
	NumericIdentifierType   string   `json:"numeric_identifier_type"`
	NumericLimit            int      `json:"numeric_limit"`
	NumericExpectedTargets  []string `json:"numeric_expected_targets"`
	FanoutDocumentCount     int      `json:"fanout_document_count"`
	NumericDuplicateCount   int      `json:"numeric_duplicate_count"`
}

type ArchiveCasesExpectation struct {
	Valid  string            `json:"valid"`
	Reject map[string]string `json:"reject"`
}

type Expected struct {
	EvidenceSchemaVersion string                      `json:"evidence_schema_version"`
	Queries               []string                    `json:"queries"`
	QueryExpectations     map[string]QueryExpectation `json:"query_expectations"`
	SPCBundleDigest       string                      `json:"spc_bundle_digest"`
	SearchIndexSHA256     string                      `json:"search_index_sha256"`
	SearchStress          SearchStressExpectation     `json:"search_stress"`
	ArchiveCases          ArchiveCasesExpectation     `json:"archive_cases"`
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
	EvidenceSchemaVersion string            `json:"evidence_schema_version"`
	Candidate             string            `json:"candidate"`
	Eligible              bool              `json:"eligible"`
	Gates                 map[string]bool   `json:"gates"`
	Runtime               map[string]any    `json:"runtime"`
	Dependencies          map[string]string `json:"dependencies"`
	Bindings              map[string]string `json:"bindings"`
	Canonical             map[string]any    `json:"canonical"`
	Search                map[string]any    `json:"search"`
	Pack                  map[string]any    `json:"pack"`
	Archive               map[string]any    `json:"archive"`
	State                 map[string]any    `json:"state"`
	KnownLimitations      []string          `json:"known_limitations"`
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
	unicodeCasefoldOK := fold("Straße") == "strasse" && fold("Σ") == fold("ς") && fold("K") == "k"

	canonicalEvidence, canonicalOK, err := runCanonicalContractProbe(".")
	if err != nil {
		fatalf("canonical contract probe: %v", err)
	}

	searchEvidence, sqliteInfo, _, exactP95, lexicalP95, err := runSearchProbe(
		filepath.Join(*workspace, "search", "atlas-search.sqlite3"), expected,
	)
	if err != nil {
		fatalf("search probe: %v", err)
	}
	searchOK := true
	ftsOK := false
	for _, queryEvidence := range searchEvidence {
		searchOK = searchOK && queryEvidence.Pass
		if queryEvidence.Stage == "lexical" && queryEvidence.Pass {
			ftsOK = true
		}
	}
	rawDDLProbe, _ := sqliteInfo["fts5"].(bool)

	stressEvidence, stressOK, err := runSearchStressProbe(*workspace, expected)
	if err != nil {
		fatalf("search stress probe: %v", err)
	}

	packEvidence, packOK, err := runTUFProbe(*workspace, expected)
	if err != nil {
		fatalf("TUF probe infrastructure failure: %v", err)
	}
	archiveEvidence, archiveOK, err := runArchiveProbe(*workspace, expected)
	if err != nil {
		fatalf("archive safety probe infrastructure failure: %v", err)
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

	goSumDigest := "unavailable"
	if goSumBytes, readErr := os.ReadFile(filepath.Join("benchmarks", "shared-core", "phase553", "go", "go.sum")); readErr == nil {
		goSumDigest = sha256Prefixed(goSumBytes)
	}
	selectedModules := selectedModuleVersions()
	goTUFVersion := selectedModules["github.com/theupdateframework/go-tuf/v2"]
	moderncVersion := selectedModules["modernc.org/sqlite"]
	xTextVersion := selectedModules["golang.org/x/text"]
	dependencySelectionOK := goTUFVersion == "v2.4.2" && moderncVersion == "v1.58.0" && xTextVersion != ""

	gates := map[string]bool{
		"G-SC1": canonicalOK && searchOK && bindingOK && unicodeCasefoldOK,
		"G-SC2": serializationOK,
		"G-SC3": searchOK && stressOK && unicodeCasefoldOK && exactP95 < 100.0 && lexicalP95 < 300.0,
		"G-SC4": searchOK && stressOK && ftsOK && bindingOK,
		"G-SC5": packOK,
		"G-SC6": stateOK,
		"G-SC7": packOK && archiveOK && stateOK,
		"G-SC8": dependencySelectionOK,
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
			"go":                     runtime.Version(),
			"os":                     runtime.GOOS,
			"arch":                   runtime.GOARCH,
			"sqlite":                 sqliteInfo["version"],
			"fts5":                   ftsOK,
			"fts5_readonly_workload": ftsOK,
			"fts5_ddl_probe":         rawDDLProbe,
			"unicode_nfkc_casefold":  unicodeCasefoldOK,
			"compiler":               runtime.Compiler,
		},
		Dependencies: map[string]string{
			"go-tuf":                   goTUFVersion,
			"modernc-sqlite":           moderncVersion,
			"x-text":                   xTextVersion,
			"go-sum-sha256":            goSumDigest,
			"selected-modules-present": fmt.Sprintf("%t", dependencySelectionOK),
		},
		Bindings: map[string]string{
			"spc_bundle_digest":    expected.SPCBundleDigest,
			"search_index_sha256":  expected.SearchIndexSHA256,
			"serialization_sha256": expected.CompactJSONSHA256,
		},
		Canonical: canonicalEvidence,
		Search: map[string]any{
			"queries":        searchEvidence,
			"exact_p95_ms":   exactP95,
			"lexical_p95_ms": lexicalP95,
			"stress":         stressEvidence,
		},
		Pack:    packEvidence,
		Archive: archiveEvidence,
		State:   stateEvidence,
		KnownLimitations: []string{
			"The seven-family Go probe validates the frozen common envelope plus representative Entity lifecycle/native-ID and Claim provenance invariants; authoritative JSON Schema validation remains owned by the canonical ingestion/pack validators and is not redefined by the spike.",
			"The spike consumes the already-approved SQLite artifact and ports the frozen resolver contract; it does not freeze Desktop IPC or UI technology.",
			"Archive evidence is fail-closed preflight/read validation only; pack contents are never executed and production extraction remains subject to the frozen Phase 5.5.2 staging contract.",
		},
	}

	if err := writeJSON(*output, evidence); err != nil {
		fatalf("write evidence: %v", err)
	}
	fmt.Printf("{\"candidate\":\"go\",\"eligible\":%t,\"timestamp\":%q}\n", eligible, time.Now().UTC().Format(time.RFC3339))
	if !eligible {
		diagnostic := map[string]any{
			"archive":                archiveEvidence,
			"binding_ok":             bindingOK,
			"canonical_ok":           canonicalOK,
			"dependency_selection":   selectedModules,
			"fts5_ok":                ftsOK,
			"fts5_ddl_probe":         rawDDLProbe,
			"gates":                  gates,
			"pack":                   packEvidence,
			"search":                 evidence.Search,
			"serialization_ok":       serializationOK,
			"state":                  stateEvidence,
			"stress_ok":              stressOK,
			"unicode_casefold_ok":    unicodeCasefoldOK,
		}
		data, marshalErr := json.Marshal(diagnostic)
		if marshalErr == nil {
			fmt.Fprintln(os.Stderr, string(data))
		}
		os.Exit(1)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
