package search

import (
	"sort"
	"strings"
)

func (c *Core) Browse(filters map[string]string, limit int) ([]CatalogItem, error) {
	if err := validateLimit(limit); err != nil {
		return nil, err
	}
	normalized, err := validateFilters(filters)
	if err != nil {
		return nil, err
	}
	clauses := []string{}
	args := []any{}
	for _, key := range sortedKeys(normalized) {
		clauses = append(clauses, "EXISTS (SELECT 1 FROM facets f WHERE f.target_id=d.target_id AND f.facet_key=? AND f.facet_value_norm=?)")
		args = append(args, key, fold(normalized[key]))
	}
	query := "SELECT d.target_id,d.entity_type,d.title,d.namespace,d.platform,d.product,d.provider,d.channel,d.lifecycle FROM documents d"
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += " ORDER BY d.platform,d.product,d.provider,d.channel,d.lifecycle,d.title_norm,d.target_id LIMIT ?"
	args = append(args, limit)
	rows, err := c.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CatalogItem{}
	for rows.Next() {
		var row searchRow
		if err = rows.Scan(&row.id, &row.entity, &row.title, &row.namespace, &row.platform, &row.product, &row.provider, &row.channel, &row.lifecycle); err != nil {
			return nil, err
		}
		out = append(out, CatalogItem{row.id, row.title, row.entity, row.scope(), nullable(row.lifecycle)})
	}
	return out, rows.Err()
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
