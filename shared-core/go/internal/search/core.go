package search

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"

	_ "modernc.org/sqlite"
)

type Core struct {
	db       *sql.DB
	metadata map[string]string
	bundle   *Bundle
}

func sqliteReadOnlyDSN(absolute string) string {
	uriPath := filepath.ToSlash(absolute)
	if runtime.GOOS == "windows" && !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	return (&url.URL{Scheme: "file", Path: uriPath, RawQuery: "mode=ro&immutable=1"}).String()
}

func Open(path string, expected *Bundle) (*Core, error) {
	if err := ValidateBundle(expected); err != nil {
		return nil, err
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve search index path: %w", err)
	}
	dsn := sqliteReadOnlyDSN(absolute)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open SQLite search index: %w", err)
	}
	db.SetMaxOpenConns(1)
	fail := func(cause error) (*Core, error) { _ = db.Close(); return nil, cause }
	if err = db.Ping(); err != nil {
		return fail(fmt.Errorf("connect SQLite search index: %w", err))
	}
	if _, err = db.Exec("PRAGMA query_only=ON"); err != nil {
		return fail(fmt.Errorf("enable SQLite query_only: %w", err))
	}
	var quick string
	if err = db.QueryRow("PRAGMA quick_check").Scan(&quick); err != nil {
		return fail(fmt.Errorf("SQLite quick_check: %w", err))
	}
	if quick != "ok" {
		return fail(fmt.Errorf("SQLite quick_check failed: %q", quick))
	}
	metadata, err := readMetadata(db)
	if err != nil {
		return fail(err)
	}
	if err = verifyMetadata(metadata, expected); err != nil {
		return fail(err)
	}
	if err = verifyTables(db); err != nil {
		return fail(err)
	}
	return &Core{db: db, metadata: metadata, bundle: expected}, nil
}

func (c *Core) Close() error {
	if c == nil || c.db == nil {
		return nil
	}
	return c.db.Close()
}
func (c *Core) Manifest() map[string]string {
	out := map[string]string{}
	for key, value := range c.metadata {
		out[key] = value
	}
	return out
}

func readMetadata(db *sql.DB) (map[string]string, error) {
	rows, err := db.Query("SELECT key,value FROM metadata ORDER BY key")
	if err != nil {
		return nil, fmt.Errorf("search index metadata is unreadable: %w", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var key, value string
		if err = rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		out[key] = value
	}
	return out, rows.Err()
}

func verifyMetadata(metadata map[string]string, expected *Bundle) error {
	required := map[string]string{"index_schema_version": "1.0.0", "index_adapter_id": "sqlite-fts5", "index_adapter_version": "1.0.0", "search_contract_version": ContractVersion, "bundle_digest": expected.BundleDigest}
	for key, want := range required {
		if got := metadata[key]; got != want {
			return fmt.Errorf("search index metadata mismatch for %s: %q != %q", key, got, want)
		}
	}
	claimed := metadata["manifest_digest"]
	if claimed == "" {
		return errors.New("search index lacks manifest_digest")
	}
	unsigned := map[string]string{}
	for key, value := range metadata {
		if key != "manifest_digest" {
			unsigned[key] = value
		}
	}
	raw, _ := json.Marshal(unsigned)
	sum := sha256.Sum256(raw)
	if "sha256-"+hex.EncodeToString(sum[:]) != claimed {
		return errors.New("search index manifest digest mismatch")
	}
	return nil
}

func verifyTables(db *sql.DB) error {
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type IN ('table','view')")
	if err != nil {
		return err
	}
	defer rows.Close()
	actual := map[string]bool{}
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			return err
		}
		actual[name] = true
	}
	for _, name := range []string{"documents", "documents_fts", "identifiers", "aliases", "facets", "metadata"} {
		if !actual[name] {
			return fmt.Errorf("search index schema is incomplete: missing %s", name)
		}
	}
	return rows.Err()
}

type searchRow struct {
	id, entity, title                                                                     string
	namespace, platform, product, provider, channel, lifecycle, primaryType, primaryValue sql.NullString
}

func nullable(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	v := value.String
	return &v
}
func (r searchRow) scope() Scope {
	return Scope{nullable(r.namespace), nullable(r.platform), nullable(r.product), nullable(r.provider), nullable(r.channel)}
}
func (r searchRow) match(value, reason string) Match {
	return Match{r.id, r.title, r.entity, r.scope(), nullable(r.lifecycle), value, reason}
}
func stableKey(r searchRow) [8]string {
	return [8]string{fold(r.platform.String), fold(r.product.String), fold(r.provider.String), fold(r.channel.String), fold(r.primaryType.String), fold(r.primaryValue.String), fold(r.lifecycle.String), r.id}
}
func lessKey(left, right [8]string) bool {
	for i := range left {
		if left[i] != right[i] {
			return left[i] < right[i]
		}
	}
	return false
}
