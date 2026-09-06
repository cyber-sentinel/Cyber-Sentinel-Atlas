package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

var atlasRecordKinds = map[string]bool{
	"entity":            true,
	"claim":             true,
	"relationship":      true,
	"source":            true,
	"validation":        true,
	"version":           true,
	"coverage-snapshot": true,
}

// canonicalFixturePaths deliberately span all seven frozen AtlasRecord families.
// EntityRecord is represented by a cross-domain Phase 5.2 fixture because the
// record-families directory contains the six non-entity family examples.
var canonicalFixturePaths = map[string]string{
	"entity":            "fixtures/phase-5.2/cross-domain/aws-createaccesskey.json",
	"claim":             "fixtures/phase-5.2/record-families/claim.json",
	"relationship":      "fixtures/phase-5.2/record-families/relationship.json",
	"source":            "fixtures/phase-5.2/record-families/source.json",
	"validation":        "fixtures/phase-5.2/record-families/validation.json",
	"version":           "fixtures/phase-5.2/record-families/version.json",
	"coverage-snapshot": "fixtures/phase-5.2/record-families/coverage.json",
}

func stringField(record map[string]any, key string) (string, bool) {
	value, ok := record[key].(string)
	return value, ok && value != ""
}

func positiveIntegral(value any) bool {
	switch typed := value.(type) {
	case float64:
		return typed >= 1 && typed == float64(int64(typed))
	case json.Number:
		integer, err := typed.Int64()
		return err == nil && integer >= 1
	default:
		return false
	}
}

func validateCommonAtlasRecord(record map[string]any) error {
	if record["schema_version"] != "1.0.0" {
		return fmt.Errorf("unsupported canonical schema_version")
	}
	kind, ok := stringField(record, "record_kind")
	if !ok || !atlasRecordKinds[kind] {
		return fmt.Errorf("unknown AtlasRecord family: %v", record["record_kind"])
	}
	id, ok := stringField(record, "id")
	if !ok || len(id) < 7 || id[:6] != "atlas:" {
		return fmt.Errorf("invalid canonical Atlas ID")
	}
	if !positiveIntegral(record["record_revision"]) {
		return fmt.Errorf("record_revision must be a positive integer")
	}
	for _, key := range []string{"created_at", "updated_at"} {
		value, ok := stringField(record, key)
		if !ok {
			return fmt.Errorf("missing %s", key)
		}
		if _, err := time.Parse(time.RFC3339, value); err != nil {
			return fmt.Errorf("%s must be offset-aware RFC3339: %w", key, err)
		}
	}
	for _, key := range []string{"curation_status", "namespace", "canonical_key"} {
		if _, ok := stringField(record, key); !ok {
			return fmt.Errorf("missing canonical envelope field %s", key)
		}
	}
	return nil
}

func validateEntityContract(record map[string]any) error {
	if record["record_kind"] != "entity" {
		return nil
	}
	if _, ok := stringField(record, "entity_type"); !ok {
		return fmt.Errorf("entity_type is required")
	}
	lifecycle, ok := record["lifecycle"].(map[string]any)
	if !ok {
		return fmt.Errorf("entity lifecycle object is required")
	}
	if _, ok := stringField(lifecycle, "state"); !ok {
		return fmt.Errorf("entity lifecycle.state is required")
	}
	native, ok := record["native_identifiers"].([]any)
	if !ok || len(native) == 0 {
		return fmt.Errorf("entity native_identifiers are required for the contract fixture")
	}
	primary := false
	for _, raw := range native {
		identifier, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("native identifier must be an object")
		}
		for _, key := range []string{"type", "value", "namespace"} {
			if _, ok := stringField(identifier, key); !ok {
				return fmt.Errorf("native identifier missing %s", key)
			}
		}
		if value, ok := identifier["primary"].(bool); ok && value {
			primary = true
		}
	}
	if !primary {
		return fmt.Errorf("contract fixture lacks a primary native identifier")
	}
	return nil
}

func validateClaimProvenance(record map[string]any) error {
	if record["record_kind"] != "claim" {
		return nil
	}
	evidence, ok := record["evidence"].([]any)
	if !ok || len(evidence) == 0 {
		return fmt.Errorf("claim provenance evidence is required")
	}
	for _, raw := range evidence {
		item, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("claim evidence must be an object")
		}
		for _, key := range []string{"source_id", "source_version", "retrieved_at", "transformation_type", "reviewer_status"} {
			if _, ok := stringField(item, key); !ok {
				return fmt.Errorf("claim evidence missing %s", key)
			}
		}
	}
	return nil
}

func validateAtlasContractRecord(record map[string]any) error {
	if err := validateCommonAtlasRecord(record); err != nil {
		return err
	}
	if err := validateEntityContract(record); err != nil {
		return err
	}
	if err := validateClaimProvenance(record); err != nil {
		return err
	}
	return nil
}

func loadCanonicalRecord(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytesReader(data))
	decoder.UseNumber()
	var record map[string]any
	if err := decoder.Decode(&record); err != nil {
		return nil, err
	}
	return record, nil
}

// bytesReader keeps number decoding exact without adding another dependency.
type byteSliceReader struct {
	data []byte
	off  int
}

func bytesReader(data []byte) *byteSliceReader { return &byteSliceReader{data: data} }

func (r *byteSliceReader) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, os.ErrClosed
	}
	n := copy(p, r.data[r.off:])
	r.off += n
	return n, nil
}

func runCanonicalContractProbe(repoRoot string) (map[string]any, bool, error) {
	families := map[string]bool{}
	fixtureDigests := map[string]string{}
	for expectedKind, relative := range canonicalFixturePaths {
		path := filepath.Join(repoRoot, filepath.FromSlash(relative))
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, false, fmt.Errorf("read %s: %w", relative, err)
		}
		var record map[string]any
		decoder := json.NewDecoder(bytesReader(data))
		decoder.UseNumber()
		if err := decoder.Decode(&record); err != nil {
			return nil, false, fmt.Errorf("parse %s: %w", relative, err)
		}
		if err := validateAtlasContractRecord(record); err != nil {
			return nil, false, fmt.Errorf("validate %s: %w", relative, err)
		}
		if record["record_kind"] != expectedKind {
			return nil, false, fmt.Errorf("fixture family mismatch for %s", relative)
		}
		families[expectedKind] = true
		fixtureDigests[expectedKind] = sha256Prefixed(data)
	}

	allSeven := len(families) == len(atlasRecordKinds)
	for kind := range atlasRecordKinds {
		allSeven = allSeven && families[kind]
	}

	// Negative gates: an eighth family and a malformed canonical ID must both fail.
	badFamily := map[string]any{
		"schema_version": "1.0.0", "record_kind": "eighth-family",
		"id": "atlas:test:atlas.test:invalid", "record_revision": json.Number("1"),
		"created_at": "2026-09-06T00:00:00Z", "updated_at": "2026-09-06T00:00:00Z",
		"curation_status": "draft", "namespace": "atlas.test", "canonical_key": "invalid",
	}
	unknownFamilyRejected := validateAtlasContractRecord(badFamily) != nil

	badID := map[string]any{
		"schema_version": "1.0.0", "record_kind": "source",
		"id": "not-an-atlas-id", "record_revision": json.Number("1"),
		"created_at": "2026-09-06T00:00:00Z", "updated_at": "2026-09-06T00:00:00Z",
		"curation_status": "draft", "namespace": "atlas.test", "canonical_key": "invalid",
	}
	invalidIDRejected := validateAtlasContractRecord(badID) != nil

	pass := allSeven && unknownFamilyRejected && invalidIDRejected
	return map[string]any{
		"pass":                     pass,
		"seven_families_present":   allSeven,
		"unknown_family_rejected":  unknownFamilyRejected,
		"invalid_id_rejected":      invalidIDRejected,
		"family_fixture_sha256":    fixtureDigests,
		"entity_lifecycle_native_id": families["entity"],
		"claim_provenance_evidence":  families["claim"],
	}, pass, nil
}
