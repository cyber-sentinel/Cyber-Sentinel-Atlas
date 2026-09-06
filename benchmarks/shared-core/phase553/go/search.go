package main

import (
	"database/sql"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
	_ "modernc.org/sqlite"
)

const (
	maxQueryScalars = 512
	maxTerms        = 32
	maxFilters      = 16
)

var lexicalTokenRE = regexp.MustCompile(`[\p{L}\p{N}_]+`)
var unicodeCaseFolder = cases.Fold()

type parsedQuery struct {
	Normalized         string
	Terms              []string
	Scope              map[string]string
	IdentifierTypeHint string
	IdentifierValue    string
}

type resolved struct {
	Targets []string
	Stage   string
	Status  string
}

func fold(value string) string {
	// Phase 5.4 freezes Unicode NFKC + full casefold semantics, not simple lowercase.
	return unicodeCaseFolder.String(norm.NFKC.String(value))
}

func parseQuery(query string) (parsedQuery, error) {
	if !utf8.ValidString(query) {
		return parsedQuery{}, fmt.Errorf("query contains invalid UTF-8")
	}
	if utf8.RuneCountInString(query) > maxQueryScalars {
		return parsedQuery{}, fmt.Errorf("query exceeds %d Unicode scalars", maxQueryScalars)
	}
	normalized := strings.Join(strings.Fields(norm.NFKC.String(query)), " ")
	raw := []string{}
	if normalized != "" {
		raw = strings.Split(normalized, " ")
	}
	terms := make([]string, 0, len(raw))
	scope := map[string]string{}
	filters := 0
	allowed := map[string]bool{
		"platform": true, "product": true, "provider": true, "channel": true,
		"namespace": true, "type": true, "lifecycle": true, "version": true,
	}
	for _, term := range raw {
		if parts := strings.SplitN(term, ":", 2); len(parts) == 2 && allowed[strings.ToLower(parts[0])] && parts[1] != "" {
			scope[strings.ToLower(parts[0])] = parts[1]
			filters++
			continue
		}
		terms = append(terms, term)
	}
	if len(terms) > maxTerms {
		return parsedQuery{}, fmt.Errorf("query exceeds %d parsed terms", maxTerms)
	}
	if filters > maxFilters {
		return parsedQuery{}, fmt.Errorf("query exceeds %d filters", maxFilters)
	}

	request := parsedQuery{Normalized: normalized, Terms: terms, Scope: scope}
	if len(terms) >= 2 {
		switch strings.ToLower(terms[0]) {
		case "sysmon":
			request.Scope["namespace"] = "microsoft.sysmon"
			request.Scope["product"] = "sysmon"
			if len(terms) == 2 {
				request.IdentifierValue = terms[1]
			}
		case "windows":
			request.Scope["namespace"] = "microsoft.windows.security"
			request.Scope["platform"] = "windows"
			if len(terms) == 2 {
				request.IdentifierValue = terms[1]
			}
		}
	}
	if len(terms) == 3 && strings.EqualFold(terms[0], "event") && strings.EqualFold(terms[1], "id") {
		request.IdentifierTypeHint = "event_id"
		request.IdentifierValue = terms[2]
	} else if len(terms) == 1 {
		request.IdentifierValue = terms[0]
	}
	return request, nil
}

func scopeClause(scope map[string]string, alias string) (string, []any) {
	if len(scope) == 0 {
		return "", nil
	}
	keys := make([]string, 0, len(scope))
	for key := range scope {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	clauses := make([]string, 0, len(keys))
	params := make([]any, 0, len(keys)*2)
	for _, key := range keys {
		clauses = append(clauses, fmt.Sprintf("EXISTS (SELECT 1 FROM facets sf WHERE sf.target_id=%s.target_id AND sf.facet_key=? AND sf.facet_value_norm=?)", alias))
		params = append(params, key, fold(scope[key]))
	}
	return strings.Join(clauses, " AND "), params
}

func statusFor(targets []string) string {
	if len(targets) == 0 {
		return "no_match"
	}
	if len(targets) == 1 {
		return "direct"
	}
	return "disambiguation"
}

type stableTargetRow struct {
	id   string
	keys [7]string
}

func stableTargets(db *sql.DB, pairs map[string]string) ([]string, error) {
	if len(pairs) == 0 {
		return nil, nil
	}
	ids := make([]string, 0, len(pairs))
	for id := range pairs {
		ids = append(ids, id)
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	query := fmt.Sprintf(`
		SELECT d.target_id,
		       COALESCE(d.platform,''), COALESCE(d.product,''),
		       COALESCE(d.provider,''), COALESCE(d.channel,''),
		       COALESCE(pi.identifier_type,''), COALESCE(pi.value,''),
		       COALESCE(d.lifecycle,'')
		FROM documents d
		LEFT JOIN identifiers pi ON pi.target_id=d.target_id AND pi.primary_flag=1
		WHERE d.target_id IN (%s)`, placeholders)
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []stableTargetRow{}
	for rows.Next() {
		var item stableTargetRow
		if err := rows.Scan(
			&item.id,
			&item.keys[0], &item.keys[1], &item.keys[2], &item.keys[3],
			&item.keys[4], &item.keys[5], &item.keys[6],
		); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(items, func(i, j int) bool {
		for k := range items[i].keys {
			left, right := fold(items[i].keys[k]), fold(items[j].keys[k])
			if left != right {
				return left < right
			}
		}
		return items[i].id < items[j].id
	})
	ordered := make([]string, 0, len(items))
	for _, item := range items {
		ordered = append(ordered, item.id)
	}
	return ordered, nil
}

func resolveQuery(db *sql.DB, query string) (resolved, error) {
	request, err := parseQuery(query)
	if err != nil {
		return resolved{}, err
	}
	if request.Normalized == "" {
		return resolved{Stage: "none", Status: "no_match"}, nil
	}

	var canonical string
	err = db.QueryRow("SELECT target_id FROM documents WHERE target_id=?", request.Normalized).Scan(&canonical)
	if err == nil {
		return resolved{Targets: []string{canonical}, Stage: "canonical_identifier", Status: "direct"}, nil
	}
	if err != sql.ErrNoRows {
		return resolved{}, err
	}

	if request.IdentifierValue != "" {
		scopeSQL, scopeParams := scopeClause(request.Scope, "d")
		sqlText := `SELECT i.target_id,i.value FROM identifiers i JOIN documents d ON d.target_id=i.target_id
			WHERE ((i.case_sensitive=1 AND i.match_value=?) OR (i.case_sensitive=0 AND i.match_value=?))`
		params := []any{norm.NFKC.String(request.IdentifierValue), fold(request.IdentifierValue)}
		if request.IdentifierTypeHint != "" {
			sqlText += " AND i.identifier_type=?"
			params = append(params, request.IdentifierTypeHint)
		}
		if scopeSQL != "" {
			sqlText += " AND " + scopeSQL
			params = append(params, scopeParams...)
		}
		rows, err := db.Query(sqlText, params...)
		if err != nil {
			return resolved{}, err
		}
		pairs := map[string]string{}
		for rows.Next() {
			var id, value string
			if err := rows.Scan(&id, &value); err != nil {
				rows.Close()
				return resolved{}, err
			}
			if _, exists := pairs[id]; !exists {
				pairs[id] = value
			}
		}
		rows.Close()
		if len(pairs) > 0 {
			targets, err := stableTargets(db, pairs)
			if err != nil {
				return resolved{}, err
			}
			stage := "native_identifier"
			if len(request.Scope) > 0 {
				stage = "scoped_identifier"
			}
			return resolved{Targets: targets, Stage: stage, Status: statusFor(targets)}, nil
		}
	}

	aliasScope, aliasScopeParams := scopeClause(request.Scope, "d")
	aliasSQL := `SELECT a.target_id,a.value FROM aliases a JOIN documents d ON d.target_id=a.target_id
		WHERE ((a.case_sensitive=1 AND a.match_value=?) OR (a.case_sensitive=0 AND a.match_value=?))`
	aliasParams := []any{norm.NFKC.String(request.Normalized), fold(request.Normalized)}
	if aliasScope != "" {
		aliasSQL += " AND " + aliasScope
		aliasParams = append(aliasParams, aliasScopeParams...)
	}
	rows, err := db.Query(aliasSQL, aliasParams...)
	if err != nil {
		return resolved{}, err
	}
	aliasPairs := map[string]string{}
	for rows.Next() {
		var id, value string
		if err := rows.Scan(&id, &value); err != nil {
			rows.Close()
			return resolved{}, err
		}
		aliasPairs[id] = value
	}
	rows.Close()
	if len(aliasPairs) > 0 {
		targets, err := stableTargets(db, aliasPairs)
		if err != nil {
			return resolved{}, err
		}
		return resolved{Targets: targets, Stage: "alias", Status: statusFor(targets)}, nil
	}

	lexicalText := strings.Join(request.Terms, " ")
	tokens := lexicalTokenRE.FindAllString(norm.NFKC.String(lexicalText), -1)
	if len(tokens) == 0 {
		return resolved{Stage: "none", Status: "no_match"}, nil
	}
	if len(tokens) > maxTerms {
		return resolved{}, fmt.Errorf("lexical query exceeds %d tokens", maxTerms)
	}
	parts := make([]string, 0, len(tokens))
	for _, token := range tokens {
		parts = append(parts, `"`+strings.ReplaceAll(fold(token), `"`, `""`)+`"`)
	}
	expression := strings.Join(parts, " OR ")
	scopeSQL, scopeParams := scopeClause(request.Scope, "d")
	lexicalSQL := `SELECT d.target_id FROM documents_fts JOIN documents d ON d.target_id=documents_fts.target_id
		WHERE documents_fts MATCH ?`
	params := []any{expression}
	if scopeSQL != "" {
		lexicalSQL += " AND " + scopeSQL
		params = append(params, scopeParams...)
	}
	lexicalSQL += ` ORDER BY bm25(documents_fts) ASC,
		CASE WHEN d.title_norm=? THEN 0 ELSE 1 END ASC,d.title_norm ASC,d.target_id ASC LIMIT 20`
	params = append(params, fold(lexicalText))
	lexRows, err := db.Query(lexicalSQL, params...)
	if err != nil {
		return resolved{}, err
	}
	defer lexRows.Close()
	targets := []string{}
	for lexRows.Next() {
		var id string
		if err := lexRows.Scan(&id); err != nil {
			return resolved{}, err
		}
		targets = append(targets, id)
	}
	if err := lexRows.Err(); err != nil {
		return resolved{}, err
	}
	stage := "none"
	if len(targets) > 0 {
		stage = "lexical"
	}
	return resolved{Targets: targets, Stage: stage, Status: statusFor(targets)}, nil
}

func runSearchProbe(indexPath string, expected Expected) (map[string]QueryEvidence, map[string]any, bool, float64, float64, error) {
	db, err := sql.Open("sqlite", indexPath)
	if err != nil {
		return nil, nil, false, 0, 0, err
	}
	defer db.Close()
	if _, err := db.Exec("PRAGMA query_only=ON"); err != nil {
		return nil, nil, false, 0, 0, err
	}
	var quick string
	if err := db.QueryRow("PRAGMA quick_check").Scan(&quick); err != nil || quick != "ok" {
		return nil, nil, false, 0, 0, fmt.Errorf("quick_check=%q err=%v", quick, err)
	}
	var version string
	if err := db.QueryRow("SELECT sqlite_version()").Scan(&version); err != nil {
		return nil, nil, false, 0, 0, err
	}
	// Diagnostic only. query_only intentionally blocks this DDL; the caller proves
	// actual FTS5 support with a successful read-only lexical MATCH workload.
	fts5DDLProbe := false
	if _, err := db.Exec("CREATE VIRTUAL TABLE temp.__atlas_fts_probe USING fts5(value)"); err == nil {
		fts5DDLProbe = true
		_, _ = db.Exec("DROP TABLE temp.__atlas_fts_probe")
	}

	results := map[string]QueryEvidence{}
	allOK := true
	exactSamples := []float64{}
	lexicalSamples := []float64{}
	for _, query := range expected.Queries {
		var baseline resolved
		samples := make([]float64, 0, 40)
		for i := 0; i < 40; i++ {
			started := time.Now()
			current, err := resolveQuery(db, query)
			if err != nil {
				return nil, nil, false, 0, 0, fmt.Errorf("resolve %q: %w", query, err)
			}
			samples = append(samples, float64(time.Since(started).Nanoseconds())/1_000_000.0)
			if i == 0 {
				baseline = current
			} else if strings.Join(current.Targets, "\x00") != strings.Join(baseline.Targets, "\x00") || current.Stage != baseline.Stage || current.Status != baseline.Status {
				allOK = false
			}
		}
		want := expected.QueryExpectations[query]
		pass := strings.Join(baseline.Targets, "\x00") == strings.Join(want.Targets, "\x00") && baseline.Stage == want.Stage && baseline.Status == want.Status
		allOK = allOK && pass
		if baseline.Stage == "lexical" {
			lexicalSamples = append(lexicalSamples, samples...)
		} else {
			exactSamples = append(exactSamples, samples...)
		}
		results[query] = QueryEvidence{Pass: pass, Targets: baseline.Targets, Stage: baseline.Stage, Status: baseline.Status, P95MS: percentile(samples, 0.95)}
	}

	return results, map[string]any{"version": version, "fts5": fts5DDLProbe}, allOK, percentile(exactSamples, 0.95), percentile(lexicalSamples, 0.95), nil
}
