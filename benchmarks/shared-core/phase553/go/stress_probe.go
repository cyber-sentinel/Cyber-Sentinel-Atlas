package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func numericStressBrowse(db *sql.DB, namespace, identifierType string, limit int) ([]string, error) {
	rows, err := db.Query(`
		SELECT target_id
		FROM identifiers
		WHERE namespace=? AND identifier_type=?
		  AND numeric_semantics=1 AND derived_numeric_value IS NOT NULL
		ORDER BY derived_numeric_value ASC,target_id ASC
		LIMIT ?`, namespace, identifierType, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var targets []string
	for rows.Next() {
		var target string
		if err := rows.Scan(&target); err != nil {
			return nil, err
		}
		targets = append(targets, target)
	}
	return targets, rows.Err()
}

func runSearchStressProbe(workspace string, expected Expected) (map[string]any, bool, error) {
	path := filepath.Join(workspace, "search", "stress-search.sqlite3")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	bindingOK := sha256Prefixed(data) == expected.SearchStress.IndexSHA256
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, false, err
	}
	defer db.Close()
	if _, err := db.Exec("PRAGMA query_only=ON"); err != nil {
		return nil, false, err
	}
	var quick string
	if err := db.QueryRow("PRAGMA quick_check").Scan(&quick); err != nil || quick != "ok" {
		return nil, false, fmt.Errorf("stress quick_check=%q err=%v", quick, err)
	}

	lexicalStable := true
	var lexicalBaseline []string
	var lexicalP95Samples []float64
	for i := 0; i < 40; i++ {
		started := time.Now()
		result, err := resolveQuery(db, expected.SearchStress.LexicalQuery)
		if err != nil {
			return nil, false, err
		}
		lexicalP95Samples = append(lexicalP95Samples, float64(time.Since(started).Nanoseconds())/1_000_000.0)
		if i == 0 {
			lexicalBaseline = result.Targets
		} else if strings.Join(result.Targets, "\x00") != strings.Join(lexicalBaseline, "\x00") {
			lexicalStable = false
		}
	}
	lexicalExpected := strings.Join(lexicalBaseline, "\x00") == strings.Join(expected.SearchStress.LexicalExpectedTargets, "\x00")

	numericStable := true
	var numericBaseline []string
	var numericP95Samples []float64
	for i := 0; i < 40; i++ {
		started := time.Now()
		current, err := numericStressBrowse(
			db,
			expected.SearchStress.NumericNamespace,
			expected.SearchStress.NumericIdentifierType,
			expected.SearchStress.NumericLimit,
		)
		if err != nil {
			return nil, false, err
		}
		numericP95Samples = append(numericP95Samples, float64(time.Since(started).Nanoseconds())/1_000_000.0)
		if i == 0 {
			numericBaseline = current
		} else if strings.Join(current, "\x00") != strings.Join(numericBaseline, "\x00") {
			numericStable = false
		}
	}
	numericExpected := strings.Join(numericBaseline, "\x00") == strings.Join(expected.SearchStress.NumericExpectedTargets, "\x00")

	passed := bindingOK && lexicalStable && lexicalExpected && numericStable && numericExpected
	return map[string]any{
		"pass": passed,
		"index_binding": bindingOK,
		"bundle_digest": expected.SearchStress.BundleDigest,
		"high_fanout": map[string]any{
			"document_count": expected.SearchStress.FanoutDocumentCount,
			"query": expected.SearchStress.LexicalQuery,
			"targets": lexicalBaseline,
			"expected_order": lexicalExpected,
			"repeated_order_stable": lexicalStable,
			"p95_ms": percentile(lexicalP95Samples, 0.95),
		},
		"duplicate_numeric_cutoff": map[string]any{
			"duplicate_count": expected.SearchStress.NumericDuplicateCount,
			"limit": expected.SearchStress.NumericLimit,
			"targets": numericBaseline,
			"expected_order": numericExpected,
			"repeated_order_stable": numericStable,
			"p95_ms": percentile(numericP95Samples, 0.95),
		},
	}, passed, nil
}
