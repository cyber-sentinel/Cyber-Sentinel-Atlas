package search

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

func (c *Core) Browse(filters map[string]string, limit int) ([]CatalogItem, error) {
	page, err := c.BrowsePage(filters, "", "legacy", limit, 0)
	if err != nil {
		return nil, err
	}
	return page.Items, nil
}

func (c *Core) BrowsePage(filters map[string]string, textQuery, sortBy string, limit, offset int) (CatalogPage, error) {
	if err := validateLimit(limit); err != nil {
		return CatalogPage{}, err
	}
	if err := validateCatalogOffset(offset); err != nil {
		return CatalogPage{}, err
	}
	normalized, err := validateFilters(filters)
	if err != nil {
		return CatalogPage{}, err
	}
	if !utf8.ValidString(textQuery) || utf8.RuneCountInString(textQuery) > MaxQueryScalars {
		return CatalogPage{}, invalid("invalid catalog query")
	}
	textQuery = strings.Join(strings.Fields(textQuery), " ")
	sortBy = strings.ToLower(sortBy)
	if sortBy == "" {
		sortBy = "name"
	}
	orderBy := map[string]string{
		"name":   "d.title_norm ASC,d.target_id ASC",
		"id":     "primary_identifier_norm ASC,d.target_id ASC",
		"type":   "d.entity_type ASC,d.title_norm ASC,d.target_id ASC",
		"legacy": "d.platform,d.product,d.provider,d.channel,d.lifecycle,d.title_norm,d.target_id",
	}[sortBy]
	if orderBy == "" {
		return CatalogPage{}, invalid("unsupported catalog sort: %s", sortBy)
	}
	clauses := []string{}
	args := []any{}
	for _, key := range sortedKeys(normalized) {
		clauses = append(clauses, "EXISTS (SELECT 1 FROM facets f WHERE f.target_id=d.target_id AND f.facet_key=? AND f.facet_value_norm=?)")
		args = append(args, key, fold(normalized[key]))
	}
	join := ""
	if textQuery != "" {
		tokens := lexicalTokenRE.FindAllString(textQuery, -1)
		if len(tokens) == 0 || len(tokens) > MaxTerms {
			return CatalogPage{}, invalid("invalid catalog query terms")
		}
		parts := make([]string, 0, len(tokens))
		for _, token := range tokens {
			parts = append(parts, `"`+strings.ReplaceAll(fold(token), `"`, `""`)+`"`)
		}
		join = " JOIN documents_fts ON documents_fts.target_id=d.target_id"
		clauses = append(clauses, "documents_fts MATCH ?")
		args = append(args, strings.Join(parts, " OR "))
	}
	where := ""
	if len(clauses) > 0 {
		where = " WHERE " + strings.Join(clauses, " AND ")
	}
	var total int64
	if err := c.db.QueryRow("SELECT COUNT(DISTINCT d.target_id) FROM documents d"+join+where, args...).Scan(&total); err != nil {
		return CatalogPage{}, err
	}
	query := `SELECT d.target_id,d.entity_type,d.title,d.namespace,d.platform,d.product,d.provider,d.channel,d.lifecycle,
		COALESCE((SELECT i.value FROM identifiers i WHERE i.target_id=d.target_id ORDER BY i.primary_flag DESC,i.identifier_type ASC,i.value ASC LIMIT 1),''),
		COALESCE((SELECT lower(i.value) FROM identifiers i WHERE i.target_id=d.target_id ORDER BY i.primary_flag DESC,i.identifier_type ASC,i.value ASC LIMIT 1),'') AS primary_identifier_norm
		FROM documents d` + join + where + " ORDER BY " + orderBy + " LIMIT ? OFFSET ?"
	args = append(args, limit, offset)
	rows, err := c.db.Query(query, args...)
	if err != nil {
		return CatalogPage{}, err
	}
	defer rows.Close()
	out := []CatalogItem{}
	for rows.Next() {
		var row searchRow
		var primary, primaryNorm string
		if err = rows.Scan(&row.id, &row.entity, &row.title, &row.namespace, &row.platform, &row.product, &row.provider, &row.channel, &row.lifecycle, &primary, &primaryNorm); err != nil {
			return CatalogPage{}, err
		}
		out = append(out, CatalogItem{TargetID: row.id, Title: row.title, EntityType: row.entity, Scope: row.scope(), Lifecycle: nullable(row.lifecycle), PrimaryIdentifier: primary, Facets: map[string][]string{}})
	}
	if err := rows.Err(); err != nil {
		return CatalogPage{}, err
	}
	if len(out) > 0 {
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(out)), ",")
		facetArgs := make([]any, len(out))
		byID := make(map[string]*CatalogItem, len(out))
		for i := range out {
			facetArgs[i] = out[i].TargetID
			byID[out[i].TargetID] = &out[i]
		}
		facetRows, facetErr := c.db.Query(fmt.Sprintf("SELECT target_id,facet_key,facet_value FROM facets WHERE target_id IN (%s) ORDER BY target_id,facet_key,facet_value_norm,facet_value", placeholders), facetArgs...)
		if facetErr != nil {
			return CatalogPage{}, facetErr
		}
		for facetRows.Next() {
			var id, key, value string
			if err = facetRows.Scan(&id, &key, &value); err != nil {
				facetRows.Close()
				return CatalogPage{}, err
			}
			if item := byID[id]; item != nil {
				item.Facets[key] = append(item.Facets[key], value)
			}
		}
		if err = facetRows.Err(); err != nil {
			facetRows.Close()
			return CatalogPage{}, err
		}
		if err = facetRows.Close(); err != nil {
			return CatalogPage{}, err
		}
	}
	var next *int
	if int64(offset+len(out)) < total {
		value := offset + len(out)
		next = &value
	}
	return CatalogPage{Items: out, TotalCount: total, Limit: limit, Offset: offset, NextOffset: next}, nil
}

func (c *Core) FacetValues(facet string, filters map[string]string, limit int) ([]FacetValue, error) {
	if err := validateLimit(limit); err != nil {
		return nil, err
	}
	facet = strings.ToLower(facet)
	if _, ok := filterKeys[facet]; !ok {
		return nil, invalid("unsupported catalog facet: %s", facet)
	}
	normalized, err := validateFilters(filters)
	if err != nil {
		return nil, err
	}
	clauses := []string{"f.facet_key=?"}
	args := []any{facet}
	for _, key := range sortedKeys(normalized) {
		clauses = append(clauses, "EXISTS (SELECT 1 FROM facets sf WHERE sf.target_id=f.target_id AND sf.facet_key=? AND sf.facet_value_norm=?)")
		args = append(args, key, fold(normalized[key]))
	}
	query := "SELECT f.facet_value,COUNT(DISTINCT f.target_id) FROM facets f WHERE " + strings.Join(clauses, " AND ") + " GROUP BY f.facet_value,f.facet_value_norm ORDER BY f.facet_value_norm ASC,f.facet_value ASC LIMIT ?"
	args = append(args, limit)
	rows, err := c.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FacetValue{}
	for rows.Next() {
		var value FacetValue
		if err = rows.Scan(&value.Value, &value.ItemCount); err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	return out, rows.Err()
}

func (c *Core) NumericBrowse(namespace, identifierType string, limit int) ([]NumericIdentifier, error) {
	if err := validateLimit(limit); err != nil {
		return nil, err
	}
	if namespace == "" || identifierType == "" {
		return nil, invalid("namespace and identifier_type are required")
	}
	rows, err := c.db.Query(`SELECT target_id,value,derived_numeric_value FROM identifiers WHERE namespace=? AND identifier_type=? AND numeric_semantics=1 AND derived_numeric_value IS NOT NULL ORDER BY derived_numeric_value ASC,target_id ASC LIMIT ?`, namespace, identifierType, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []NumericIdentifier{}
	for rows.Next() {
		var value NumericIdentifier
		if err = rows.Scan(&value.TargetID, &value.Value, &value.DerivedNumericValue); err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	return out, rows.Err()
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
