package search

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

func parseQuery(query string, graphDepth int) (parsedQuery, error) {
	if !utf8.ValidString(query) {
		return parsedQuery{}, invalid("query contains invalid UTF-8")
	}
	if utf8.RuneCountInString(query) > MaxQueryScalars {
		return parsedQuery{}, invalid("query exceeds %d Unicode scalar values", MaxQueryScalars)
	}
	if graphDepth < 0 || graphDepth > MaxGraphDepth {
		return parsedQuery{}, invalid("graph_depth must be between 0 and %d", MaxGraphDepth)
	}
	normalized := strings.Join(strings.Fields(norm.NFKC.String(query)), " ")
	raw := []string{}
	if normalized != "" {
		raw = strings.Split(normalized, " ")
	}
	request := parsedQuery{normalized: normalized, scope: map[string]string{}}
	filterCount := 0
	for _, term := range raw {
		parts := strings.SplitN(term, ":", 2)
		if len(parts) == 2 && parts[1] != "" {
			key := strings.ToLower(parts[0])
			if _, ok := filterKeys[key]; ok {
				request.scope[key] = parts[1]
				filterCount++
				continue
			}
		}
		request.terms = append(request.terms, term)
	}
	if len(request.terms) > MaxTerms {
		return parsedQuery{}, invalid("query exceeds %d parsed terms", MaxTerms)
	}
	if filterCount > MaxFilters {
		return parsedQuery{}, invalid("query exceeds %d structured filters", MaxFilters)
	}
	if len(request.terms) >= 2 {
		if implied, ok := scopeWords[strings.ToLower(request.terms[0])]; ok {
			for key, value := range implied {
				request.scope[key] = value
			}
			if len(request.terms) == 2 {
				request.idValue = request.terms[1]
				request.hasID = true
			}
		} else if len(request.terms) == 3 && strings.EqualFold(request.terms[0], "event") && strings.EqualFold(request.terms[1], "id") {
			request.idType = "event_id"
			request.idValue = request.terms[2]
			request.hasID = true
		}
	} else if len(request.terms) == 1 {
		request.idValue = request.terms[0]
		request.hasID = true
	}
	return request, nil
}

func validateLimit(limit int) error {
	if limit < 1 || limit > MaxTopK {
		return invalid("limit must be between 1 and %d", MaxTopK)
	}
	return nil
}
func validateFilters(filters map[string]string) (map[string]string, error) {
	if filters == nil {
		return map[string]string{}, nil
	}
	if len(filters) > MaxFilters {
		return nil, invalid("catalog filters exceed %d", MaxFilters)
	}
	out := map[string]string{}
	for key, value := range filters {
		key = strings.ToLower(key)
		if _, ok := filterKeys[key]; !ok {
			return nil, invalid("unsupported catalog filter: %s", key)
		}
		if value == "" || !utf8.ValidString(value) || utf8.RuneCountInString(value) > MaxQueryScalars {
			return nil, invalid("invalid catalog filter: %s", key)
		}
		out[key] = value
	}
	return out, nil
}
func scopeClause(scope map[string]string, alias string) (string, []any) {
	keys := sortedKeys(scope)
	clauses := make([]string, 0, len(keys))
	args := make([]any, 0, len(keys)*2)
	for _, key := range keys {
		clauses = append(clauses, fmt.Sprintf("EXISTS (SELECT 1 FROM facets sf WHERE sf.target_id=%s.target_id AND sf.facet_key=? AND sf.facet_value_norm=?)", alias))
		args = append(args, key, fold(scope[key]))
	}
	return strings.Join(clauses, " AND "), args
}
func resultStatus(count int) string {
	if count == 0 {
		return "no_match"
	}
	if count == 1 {
		return "direct"
	}
	return "disambiguation"
}
func (c *Core) envelope(query, stage string, matches []Match) Result {
	if len(matches) == 0 {
		stage = "none"
	}
	return Result{ContractVersion, query, resultStatus(len(matches)), stage, matches}
}

func (c *Core) stableMatches(pairs map[string]string, reason string) ([]Match, error) {
	ids := sortedKeys(pairs)
	if len(ids) == 0 {
		return []Match{}, nil
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	rows, err := c.db.Query(fmt.Sprintf(`SELECT d.target_id,d.entity_type,d.title,d.namespace,d.platform,d.product,d.provider,d.channel,d.lifecycle,COALESCE(pi.identifier_type,''),COALESCE(pi.value,'') FROM documents d LEFT JOIN identifiers pi ON pi.target_id=d.target_id AND pi.primary_flag=1 WHERE d.target_id IN (%s)`, placeholders), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []searchRow{}
	seen := map[string]bool{}
	for rows.Next() {
		var row searchRow
		if err = rows.Scan(&row.id, &row.entity, &row.title, &row.namespace, &row.platform, &row.product, &row.provider, &row.channel, &row.lifecycle, &row.primaryType, &row.primaryValue); err != nil {
			return nil, err
		}
		if !seen[row.id] {
			seen[row.id] = true
			items = append(items, row)
		}
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(items, func(i, j int) bool { return lessKey(stableKey(items[i]), stableKey(items[j])) })
	out := make([]Match, 0, len(items))
	for _, row := range items {
		out = append(out, row.match(pairs[row.id], reason))
	}
	return out, nil
}

func (c *Core) Resolve(query string, graphDepth, limit int) (Result, error) {
	if c == nil || c.db == nil {
		return Result{}, errors.New("search core is not open")
	}
	if err := validateLimit(limit); err != nil {
		return Result{}, err
	}
	request, err := parseQuery(query, graphDepth)
	if err != nil {
		return Result{}, err
	}
	if request.normalized == "" {
		return c.envelope(query, "none", []Match{}), nil
	}
	var target string
	err = c.db.QueryRow("SELECT target_id FROM documents WHERE target_id=?", request.normalized).Scan(&target)
	if err == nil {
		matches, e := c.stableMatches(map[string]string{target: request.normalized}, "exact canonical identifier")
		return c.envelope(query, "canonical_identifier", matches), e
	}
	if err != sql.ErrNoRows {
		return Result{}, err
	}
	if request.hasID {
		where, args := scopeClause(request.scope, "d")
		sqlText := `SELECT i.target_id,i.value FROM identifiers i JOIN documents d ON d.target_id=i.target_id WHERE ((i.case_sensitive=1 AND i.match_value=?) OR (i.case_sensitive=0 AND i.match_value=?))`
		params := []any{norm.NFKC.String(request.idValue), fold(request.idValue)}
		if request.idType != "" {
			sqlText += " AND i.identifier_type=?"
			params = append(params, request.idType)
		}
		if where != "" {
			sqlText += " AND " + where
			params = append(params, args...)
		}
		pairs, e := queryPairs(c.db, sqlText, params...)
		if e != nil {
			return Result{}, e
		}
		if len(pairs) > 0 {
			matches, e := c.stableMatches(pairs, "registry-aware exact native identifier")
			stage := "native_identifier"
			if len(request.scope) > 0 {
				stage = "scoped_identifier"
			}
			return c.envelope(query, stage, matches), e
		}
	}
	where, args := scopeClause(request.scope, "d")
	sqlText := `SELECT a.target_id,a.value FROM aliases a JOIN documents d ON d.target_id=a.target_id WHERE ((a.case_sensitive=1 AND a.match_value=?) OR (a.case_sensitive=0 AND a.match_value=?))`
	params := []any{norm.NFKC.String(request.normalized), fold(request.normalized)}
	if where != "" {
		sqlText += " AND " + where
		params = append(params, args...)
	}
	pairs, err := queryPairs(c.db, sqlText, params...)
	if err != nil {
		return Result{}, err
	}
	if len(pairs) > 0 {
		matches, e := c.stableMatches(pairs, "exact scoped alias")
		return c.envelope(query, "alias", matches), e
	}
	lexical := strings.Join(request.terms, " ")
	tokens := lexicalTokenRE.FindAllString(norm.NFKC.String(lexical), -1)
	if len(tokens) == 0 {
		return c.envelope(query, "none", []Match{}), nil
	}
	if len(tokens) > MaxTerms {
		return Result{}, invalid("query exceeds %d lexical terms", MaxTerms)
	}
	parts := make([]string, 0, len(tokens))
	for _, token := range tokens {
		parts = append(parts, `"`+strings.ReplaceAll(fold(token), `"`, `""`)+`"`)
	}
	expression := strings.Join(parts, " OR ")
	where, args = scopeClause(request.scope, "d")
	sqlText = `SELECT d.target_id,d.entity_type,d.title,d.namespace,d.platform,d.product,d.provider,d.channel,d.lifecycle,bm25(documents_fts) FROM documents_fts JOIN documents d ON d.target_id=documents_fts.target_id WHERE documents_fts MATCH ?`
	params = []any{expression}
	if where != "" {
		sqlText += " AND " + where
		params = append(params, args...)
	}
	sqlText += ` ORDER BY bm25(documents_fts) ASC,CASE WHEN d.title_norm=? THEN 0 ELSE 1 END ASC,d.title_norm ASC,d.target_id ASC LIMIT ?`
	params = append(params, fold(lexical), limit)
	rows, err := c.db.Query(sqlText, params...)
	if err != nil {
		return Result{}, err
	}
	defer rows.Close()
	matches := []Match{}
	for rows.Next() {
		var row searchRow
		var score float64
		if err = rows.Scan(&row.id, &row.entity, &row.title, &row.namespace, &row.platform, &row.product, &row.provider, &row.channel, &row.lifecycle, &score); err != nil {
			return Result{}, err
		}
		matches = append(matches, row.match(request.normalized, "bounded SQLite FTS5 lexical match"))
	}
	if err = rows.Err(); err != nil {
		return Result{}, err
	}
	return c.envelope(query, "lexical", matches), nil
}

func queryPairs(db *sql.DB, query string, args ...any) (map[string]string, error) {
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, value string
		if err = rows.Scan(&id, &value); err != nil {
			return nil, err
		}
		if _, exists := out[id]; !exists {
			out[id] = value
		}
	}
	return out, rows.Err()
}
