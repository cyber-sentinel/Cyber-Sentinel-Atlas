package canonical

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

const SchemaVersion = "1.0.0"

var canonicalIDRE = regexp.MustCompile(`^atlas:[a-z0-9-]+:[a-z0-9-]+(?:\.[a-z0-9-]+)*:[a-z0-9._-]+$`)

var recordKinds = map[string]struct{}{
	"entity":            {},
	"claim":             {},
	"relationship":      {},
	"source":            {},
	"validation":        {},
	"version":           {},
	"coverage-snapshot": {},
}

var curationStatuses = map[string]struct{}{
	"draft": {}, "review": {}, "validated": {}, "published": {}, "withdrawn": {},
}

// Record retains the decoded canonical object. json.Number is deliberately preserved
// so deterministic serialization never converts integral canonical values through float64.
type Record map[string]any

type Store struct {
	byID map[string]Record
	ids  []string
}

func NewStore(records []Record) (*Store, error) {
	store := &Store{byID: make(map[string]Record, len(records))}
	for _, record := range records {
		if err := ValidateRecord(record); err != nil {
			return nil, err
		}
		id := record["id"].(string)
		if _, exists := store.byID[id]; exists {
			return nil, fmt.Errorf("duplicate canonical record id: %s", id)
		}
		store.byID[id] = record
		store.ids = append(store.ids, id)
	}
	sort.Strings(store.ids)
	return store, nil
}

func LoadJSONL(path string) (*Store, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open canonical JSONL: %w", err)
	}
	defer file.Close()
	return DecodeJSONL(file)
}

func DecodeJSONL(r io.Reader) (*Store, error) {
	scanner := bufio.NewScanner(r)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 8<<20)
	records := make([]Record, 0)
	line := 0
	for scanner.Scan() {
		line++
		raw := bytes.TrimSpace(scanner.Bytes())
		if len(raw) == 0 {
			continue
		}
		record, err := DecodeRecord(raw)
		if err != nil {
			return nil, fmt.Errorf("canonical JSONL line %d: %w", line, err)
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan canonical JSONL: %w", err)
	}
	if len(records) == 0 {
		return nil, errors.New("canonical JSONL contains no records")
	}
	return NewStore(records)
}

func DecodeRecord(data []byte) (Record, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var record Record
	if err := dec.Decode(&record); err != nil {
		return nil, fmt.Errorf("decode canonical record: %w", err)
	}
	if dec.More() {
		return nil, errors.New("trailing canonical JSON data")
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, errors.New("trailing canonical JSON value")
		}
		return nil, fmt.Errorf("trailing canonical JSON data: %w", err)
	}
	if err := ValidateRecord(record); err != nil {
		return nil, err
	}
	return record, nil
}

func ValidateRecord(record Record) error {
	if record == nil {
		return errors.New("canonical record must be an object")
	}
	if record["schema_version"] != SchemaVersion {
		return errors.New("unsupported canonical schema_version")
	}
	kind, ok := nonEmptyString(record, "record_kind")
	if !ok {
		return errors.New("canonical record_kind is required")
	}
	if _, ok := recordKinds[kind]; !ok {
		return fmt.Errorf("unknown AtlasRecord family: %s", kind)
	}
	id, ok := nonEmptyString(record, "id")
	if !ok || !canonicalIDRE.MatchString(id) {
		return errors.New("invalid canonical Atlas ID")
	}
	if !positiveIntegral(record["record_revision"]) {
		return errors.New("record_revision must be a positive integer")
	}
	for _, key := range []string{"created_at", "updated_at"} {
		value, ok := nonEmptyString(record, key)
		if !ok {
			return fmt.Errorf("%s is required", key)
		}
		if _, err := time.Parse(time.RFC3339, value); err != nil {
			return fmt.Errorf("%s must be RFC3339 with offset: %w", key, err)
		}
	}
	status, ok := nonEmptyString(record, "curation_status")
	if !ok {
		return errors.New("curation_status is required")
	}
	if _, ok := curationStatuses[status]; !ok {
		return fmt.Errorf("invalid curation_status: %s", status)
	}

	// Family-specific minimums are intentionally a read-model guard, not a replacement
	// for the authoritative JSON Schema validators used before pack promotion.
	switch kind {
	case "entity":
		for _, key := range []string{"entity_type", "namespace", "canonical_key", "title"} {
			if _, ok := nonEmptyString(record, key); !ok {
				return fmt.Errorf("entity %s is required", key)
			}
		}
	case "relationship":
		for _, key := range []string{"namespace", "canonical_key", "from", "to", "relationship_type", "confidence"} {
			if _, ok := nonEmptyString(record, key); !ok {
				return fmt.Errorf("relationship %s is required", key)
			}
		}
	}
	return nil
}

func (s *Store) Get(id string) (Record, bool) {
	if s == nil {
		return nil, false
	}
	record, ok := s.byID[id]
	return record, ok
}

func (s *Store) IDs() []string {
	if s == nil {
		return nil
	}
	return append([]string(nil), s.ids...)
}

func DeterministicJSON(value any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "")
	if err := enc.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func DigestValue(value any) (string, error) {
	data, err := DeterministicJSON(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256-" + hex.EncodeToString(sum[:]), nil
}

func nonEmptyString(record map[string]any, key string) (string, bool) {
	value, ok := record[key].(string)
	return value, ok && strings.TrimSpace(value) != ""
}

func positiveIntegral(value any) bool {
	switch v := value.(type) {
	case json.Number:
		i, err := v.Int64()
		return err == nil && i >= 1
	case int:
		return v >= 1
	case int64:
		return v >= 1
	case float64:
		return v >= 1 && v == float64(int64(v))
	default:
		return false
	}
}
