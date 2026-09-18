package app

import (
	"encoding/json"
	"testing"

	"github.com/cyber-sentinel/Cyber-Sentinel-Atlas/shared-core/go/internal/canonical"
)

func detailRecord(kind, id string) canonical.Record {
	base := canonical.Record{
		"schema_version": "1.0.0",
		"record_kind": kind,
		"id": id,
		"record_revision": json.Number("1"),
		"created_at": "2026-09-18T00:00:00Z",
		"updated_at": "2026-09-18T00:00:00Z",
		"curation_status": "validated",
	}
	return base
}

func TestRecordGetDetailProjectionIsBoundedAndDeterministic(t *testing.T) {
	event := detailRecord("entity", "atlas:event:microsoft.windows.security:4688")
	event["entity_type"] = "event"
	event["namespace"] = "microsoft.windows.security"
	event["canonical_key"] = "4688"
	event["title"] = "Windows Security Event 4688"

	field := detailRecord("entity", "atlas:field:microsoft.windows.security:4688.newprocessname")
	field["entity_type"] = "field"
	field["namespace"] = "microsoft.windows.security"
	field["canonical_key"] = "4688.newprocessname"
	field["title"] = "New Process Name"

	rel := detailRecord("relationship", "atlas:relationship:atlas.graph:has-field-4688-newprocessname")
	rel["namespace"] = "atlas.graph"
	rel["canonical_key"] = "has-field-4688-newprocessname"
	rel["from"] = event["id"]
	rel["to"] = field["id"]
	rel["relationship_type"] = "HAS_FIELD"
	rel["confidence"] = "high"

	source := detailRecord("source", "atlas:source:atlas.source:windows-4688-reference")
	source["namespace"] = "atlas.source"
	source["canonical_key"] = "windows-4688-reference"

	claim := detailRecord("claim", "atlas:claim:atlas.claim:field-semantics-4688-newprocessname")
	claim["namespace"] = "atlas.claim"
	claim["canonical_key"] = "field-semantics-4688-newprocessname"
	claim["subject_id"] = field["id"]
	claim["predicate"] = "telemetry.field-semantics"
	claim["object"] = map[string]any{
		"kind": "json",
		"value": map[string]any{"meaning": "Full path of the created executable."},
	}
	claim["confidence"] = "high"
	claim["evidence"] = []any{
		map[string]any{
			"source_id": source["id"],
			"source_version": "test",
			"retrieved_at": "2026-09-18T00:00:00Z",
			"locator": map[string]any{"heading": "Process Information"},
			"transformation_type": "human-authored-synthesis",
			"reviewer_status": "approved",
		},
	}

	store, err := canonical.NewStore([]canonical.Record{claim, rel, source, field, event})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	runtime := &Runtime{Canonical: store}

	raw, opErr := runtime.Handle("record.get", json.RawMessage(`{"id":"atlas:event:microsoft.windows.security:4688"}`))
	if opErr != nil {
		t.Fatalf("raw record.get failed: %v", opErr)
	}
	rawRecord, ok := raw.(canonical.Record)
	if !ok || rawRecord["id"] != event["id"] {
		t.Fatalf("default record.get changed compatibility: %#v", raw)
	}

	detail, opErr := runtime.Handle("record.get", json.RawMessage(`{"id":"atlas:event:microsoft.windows.security:4688","detail":true}`))
	if opErr != nil {
		t.Fatalf("detail record.get failed: %v", opErr)
	}
	projection, ok := detail.(map[string]any)
	if !ok {
		t.Fatalf("detail projection type: %T", detail)
	}
	if projection["detail_version"] != "1.0.0" {
		t.Fatalf("unexpected detail version: %#v", projection["detail_version"])
	}
	fields, ok := projection["fields"].([]canonical.Record)
	if !ok || len(fields) != 1 || fields[0]["id"] != field["id"] {
		t.Fatalf("unexpected fields: %#v", projection["fields"])
	}
	claims, ok := projection["claims"].([]canonical.Record)
	if !ok || len(claims) != 1 || claims[0]["id"] != claim["id"] {
		t.Fatalf("unexpected claims: %#v", projection["claims"])
	}
	sources, ok := projection["sources"].([]canonical.Record)
	if !ok || len(sources) != 1 || sources[0]["id"] != source["id"] {
		t.Fatalf("unexpected sources: %#v", projection["sources"])
	}
	relationships, ok := projection["relationships"].([]canonical.Record)
	if !ok || len(relationships) != 1 || relationships[0]["id"] != rel["id"] {
		t.Fatalf("unexpected relationships: %#v", projection["relationships"])
	}
}
