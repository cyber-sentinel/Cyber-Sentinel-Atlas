package search

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	_ "modernc.org/sqlite"
)

type BuildBinding struct {
	CanonicalCorpusID       string `json:"canonical_corpus_id"`
	CanonicalCorpusDigest   string `json:"canonical_corpus_digest"`
	CanonicalSchemaVersion  string `json:"canonical_schema_version"`
	RegistryBundleVersion   string `json:"registry_bundle_version"`
	RegistryBundleDigest    string `json:"registry_bundle_digest"`
	ProjectionProfileVersion string `json:"projection_profile_version"`
	ProjectionProfileDigest string `json:"projection_profile_digest"`
}

type LexicalFields struct {
	Title             string   `json:"title"`
	Aliases           []string `json:"aliases"`
	NativeIdentifiers []string `json:"native_identifiers"`
	Description       string   `json:"description"`
}

type Identifier struct {
	TargetID            string            `json:"target_id"`
	IdentifierType      string            `json:"identifier_type"`
	Value               string            `json:"value"`
	Namespace           string            `json:"namespace"`
	Scope               map[string]string `json:"scope"`
	CaseSensitive       bool              `json:"case_sensitive"`
	Primary             bool              `json:"primary"`
	NumericSemantics    bool              `json:"numeric_semantics"`
	DerivedNumericValue *int64            `json:"derived_numeric_value,omitempty"`
}

type Alias struct {
	TargetID      string            `json:"target_id"`
	Value         string            `json:"value"`
	Kind          string            `json:"kind"`
	Scope         map[string]string `json:"scope"`
	CaseSensitive bool              `json:"case_sensitive"`
}

type FilterProjection struct {
	TargetID string             `json:"target_id"`
	Facets   map[string]*string `json:"facets"`
}

func BuildIndex(bundle *Bundle, outputPath string) error {
	if err := ValidateBundle(bundle); err != nil {
		return err
	}
	if len(bundle.Identifiers) == 0 || len(bundle.Filters) == 0 {
		return fmt.Errorf("SPC bundle lacks production identifier/filter projections")
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(outputPath), ".atlas-search-*.tmp")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	if err := temp.Close(); err != nil {
		_ = os.Remove(tempPath)
		return err
	}
	_ = os.Remove(tempPath)
	defer os.Remove(tempPath)

	db, err := sql.Open("sqlite", tempPath)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			_ = db.Close()
		}
	}()
	if _, err := db.Exec("PRAGMA journal_mode=DELETE"); err != nil {
		return err
	}
	if _, err := db.Exec("PRAGMA synchronous=FULL"); err != nil {
		return err
	}
	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		return err
	}
	if _, err := db.Exec(`
CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE documents(
 target_id TEXT PRIMARY KEY, entity_type TEXT NOT NULL, title TEXT NOT NULL,
 title_norm TEXT NOT NULL, namespace TEXT, platform TEXT, product TEXT,
 provider TEXT, channel TEXT, lifecycle TEXT, description TEXT NOT NULL
) WITHOUT ROWID;
CREATE TABLE identifiers(
 target_id TEXT NOT NULL REFERENCES documents(target_id), identifier_type TEXT NOT NULL,
 value TEXT NOT NULL, match_value TEXT NOT NULL, namespace TEXT NOT NULL,
 case_sensitive INTEGER NOT NULL, primary_flag INTEGER NOT NULL,
 numeric_semantics INTEGER NOT NULL, derived_numeric_value INTEGER,
 PRIMARY KEY(target_id,identifier_type,value,namespace)
) WITHOUT ROWID;
CREATE TABLE aliases(
 target_id TEXT NOT NULL REFERENCES documents(target_id), value TEXT NOT NULL,
 match_value TEXT NOT NULL, kind TEXT NOT NULL, case_sensitive INTEGER NOT NULL,
 scope_json TEXT NOT NULL, PRIMARY KEY(target_id,value,kind)
) WITHOUT ROWID;
CREATE TABLE facets(
 target_id TEXT NOT NULL REFERENCES documents(target_id), facet_key TEXT NOT NULL,
 facet_value TEXT NOT NULL, facet_value_norm TEXT NOT NULL,
 PRIMARY KEY(target_id,facet_key,facet_value)
) WITHOUT ROWID;
CREATE INDEX idx_ident_match ON identifiers(match_value,case_sensitive,identifier_type,namespace,target_id);
CREATE INDEX idx_ident_numeric ON identifiers(namespace,identifier_type,derived_numeric_value,target_id) WHERE numeric_semantics=1 AND derived_numeric_value IS NOT NULL;
CREATE INDEX idx_alias_match ON aliases(match_value,case_sensitive,target_id);
CREATE INDEX idx_facet_lookup ON facets(facet_key,facet_value_norm,target_id);
CREATE INDEX idx_document_scope ON documents(platform,product,provider,channel,lifecycle,entity_type,namespace,target_id);
CREATE VIRTUAL TABLE documents_fts USING fts5(target_id UNINDEXED,title,aliases,native_identifiers,description,tokenize='unicode61 remove_diacritics 2');
`); err != nil {
		return fmt.Errorf("create SQLite search schema: %w", err)
	}

	docs := append([]Document(nil), bundle.Documents...)
	sort.Slice(docs, func(i, j int) bool { return docs[i].TargetID < docs[j].TargetID })
	aliasesByID := map[string][]string{}
	idsByID := map[string][]string{}
	for _, a := range bundle.Aliases {
		aliasesByID[a.TargetID] = append(aliasesByID[a.TargetID], a.Value)
	}
	for _, id := range bundle.Identifiers {
		idsByID[id.TargetID] = append(idsByID[id.TargetID], id.Value)
	}
	for _, doc := range docs {
		description := doc.LexicalFields.Description
		if _, err := db.Exec(`INSERT INTO documents VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
			doc.TargetID, doc.EntityType, doc.Title, fold(doc.Title), nullableValue(doc.Scope.Namespace),
			nullableValue(doc.Scope.Platform), nullableValue(doc.Scope.Product), nullableValue(doc.Scope.Provider),
			nullableValue(doc.Scope.Channel), nullableValue(doc.Lifecycle), description); err != nil {
			return err
		}
		aliases := append([]string(nil), aliasesByID[doc.TargetID]...)
		ids := append([]string(nil), idsByID[doc.TargetID]...)
		sort.Strings(aliases)
		sort.Strings(ids)
		if _, err := db.Exec(`INSERT INTO documents_fts VALUES(?,?,?,?,?)`, doc.TargetID, doc.Title, strings.Join(uniqueStrings(aliases), "\n"), strings.Join(uniqueStrings(ids), "\n"), description); err != nil {
			return err
		}
	}

	ids := append([]Identifier(nil), bundle.Identifiers...)
	sort.Slice(ids, func(i, j int) bool {
		li := ids[i].Namespace + "\x00" + ids[i].IdentifierType + "\x00" + ids[i].Value + "\x00" + ids[i].TargetID
		lj := ids[j].Namespace + "\x00" + ids[j].IdentifierType + "\x00" + ids[j].Value + "\x00" + ids[j].TargetID
		return li < lj
	})
	for _, id := range ids {
		match := fold(id.Value)
		if id.CaseSensitive {
			match = id.Value
		}
		var numeric any
		if id.DerivedNumericValue != nil {
			numeric = *id.DerivedNumericValue
		}
		if _, err := db.Exec(`INSERT INTO identifiers VALUES(?,?,?,?,?,?,?,?,?)`, id.TargetID, id.IdentifierType, id.Value, match, id.Namespace, boolInt(id.CaseSensitive), boolInt(id.Primary), boolInt(id.NumericSemantics), numeric); err != nil {
			return err
		}
	}

	aliases := append([]Alias(nil), bundle.Aliases...)
	sort.Slice(aliases, func(i, j int) bool {
		li := aliases[i].TargetID + "\x00" + fold(aliases[i].Value) + "\x00" + aliases[i].Kind
		lj := aliases[j].TargetID + "\x00" + fold(aliases[j].Value) + "\x00" + aliases[j].Kind
		return li < lj
	})
	for _, a := range aliases {
		match := fold(a.Value)
		if a.CaseSensitive {
			match = a.Value
		}
		scopeJSON, err := json.Marshal(a.Scope)
		if err != nil {
			return err
		}
		kind := a.Kind
		if kind == "" {
			kind = "alias"
		}
		if _, err := db.Exec(`INSERT INTO aliases VALUES(?,?,?,?,?,?)`, a.TargetID, a.Value, match, kind, boolInt(a.CaseSensitive), string(scopeJSON)); err != nil {
			return err
		}
	}

	filters := append([]FilterProjection(nil), bundle.Filters...)
	sort.Slice(filters, func(i, j int) bool { return filters[i].TargetID < filters[j].TargetID })
	for _, projection := range filters {
		keys := make([]string, 0, len(projection.Facets))
		for key := range projection.Facets {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			value := projection.Facets[key]
			if value == nil {
				continue
			}
			if _, err := db.Exec(`INSERT INTO facets VALUES(?,?,?,?)`, projection.TargetID, key, *value, fold(*value)); err != nil {
				return err
			}
		}
	}

	metadata := map[string]string{
		"index_schema_version": "1.0.0",
		"index_adapter_id": "sqlite-fts5",
		"index_adapter_version": "1.0.0",
		"search_contract_version": ContractVersion,
		"bundle_digest": bundle.BundleDigest,
	}
	unsigned, _ := json.Marshal(metadata)
	sum := sha256.Sum256(unsigned)
	metadata["manifest_digest"] = "sha256-" + hex.EncodeToString(sum[:])
	keys := make([]string, 0, len(metadata))
	for key := range metadata {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if _, err := db.Exec(`INSERT INTO metadata(key,value) VALUES(?,?)`, key, metadata[key]); err != nil {
			return err
		}
	}
	var quick string
	if err := db.QueryRow("PRAGMA quick_check").Scan(&quick); err != nil || quick != "ok" {
		return fmt.Errorf("rebuilt SQLite index failed quick_check: %q %v", quick, err)
	}
	if err := db.Close(); err != nil {
		return err
	}
	closed = true
	file, err := os.OpenFile(tempPath, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, outputPath); err != nil {
		return err
	}
	return nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func nullableValue(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}

func uniqueStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}
