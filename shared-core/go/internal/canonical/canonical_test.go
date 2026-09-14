package canonical

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSevenCanonicalFamiliesAndNegativeGates(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", "..", "..", ".."))
	fixtures := map[string]string{
		"entity":            "fixtures/phase-5.2/cross-domain/aws-createaccesskey.json",
		"claim":             "fixtures/phase-5.2/record-families/claim.json",
		"relationship":      "fixtures/phase-5.2/record-families/relationship.json",
		"source":            "fixtures/phase-5.2/record-families/source.json",
		"validation":        "fixtures/phase-5.2/record-families/validation.json",
		"version":           "fixtures/phase-5.2/record-families/version.json",
		"coverage-snapshot": "fixtures/phase-5.2/record-families/coverage.json",
	}
	for kind, relative := range fixtures {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatalf("read %s: %v", relative, err)
		}
		record, err := DecodeRecord(data)
		if err != nil {
			t.Fatalf("decode %s: %v", relative, err)
		}
		if record["record_kind"] != kind {
			t.Fatalf("%s: got record_kind=%v", relative, record["record_kind"])
		}
	}

	badFamily := Record{
		"schema_version": "1.0.0", "record_kind": "eighth-family",
		"id": "atlas:test:atlas.test:invalid", "record_revision": json.Number("1"),
		"created_at": "2026-09-14T00:00:00Z", "updated_at": "2026-09-14T00:00:00Z", "curation_status": "draft",
	}
	if err := ValidateRecord(badFamily); err == nil {
		t.Fatal("unknown eighth family must be rejected")
	}
	badID := Record{
		"schema_version": "1.0.0", "record_kind": "source",
		"id": "not-an-atlas-id", "record_revision": json.Number("1"),
		"created_at": "2026-09-14T00:00:00Z", "updated_at": "2026-09-14T00:00:00Z", "curation_status": "draft",
	}
	if err := ValidateRecord(badID); err == nil {
		t.Fatal("invalid canonical ID must be rejected")
	}
}

func TestDeterministicJSON(t *testing.T) {
	value := map[string]any{
		"z": json.Number("42"),
		"a": map[string]any{"β": "<tag>&", "n": nil},
	}
	first, err := DeterministicJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	second, err := DeterministicJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatalf("deterministic bytes differ: %q != %q", first, second)
	}
	if string(first) != `{"a":{"n":null,"β":"<tag>&"},"z":42}` {
		t.Fatalf("unexpected deterministic profile: %s", first)
	}
}
