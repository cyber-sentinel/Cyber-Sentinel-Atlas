package app

import (
	"encoding/json"
	"testing"

	"github.com/cyber-sentinel/Cyber-Sentinel-Atlas/shared-core/go/internal/canonical"
	"github.com/cyber-sentinel/Cyber-Sentinel-Atlas/shared-core/go/internal/graph"
	"github.com/cyber-sentinel/Cyber-Sentinel-Atlas/shared-core/go/internal/search"
)

func TestPackStatusIncludesActiveGenerationIdentity(t *testing.T) {
	runtime := &Runtime{
		Canonical:      &canonical.Store{},
		Search:         &search.Core{},
		Graph:          &graph.Runtime{},
		GenerationID:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		PackID:         "atlas:pack:test",
		PackVersion:    "1.0.0-test.1",
		ManifestDigest: "sha256-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	status, operationError := runtime.Handle("pack.status", json.RawMessage(`{}`))
	if operationError != nil {
		t.Fatalf("pack.status: %v", operationError)
	}
	body := status.(map[string]any)
	if body["ready"] != true || body["state"] != "read_model_ready" {
		t.Fatalf("unexpected configured status: %#v", body)
	}
	for key, want := range map[string]string{
		"generation_id":   runtime.GenerationID,
		"pack_id":         runtime.PackID,
		"pack_version":    runtime.PackVersion,
		"manifest_digest": runtime.ManifestDigest,
	} {
		if body[key] != want {
			t.Fatalf("pack.status %s mismatch: %#v", key, body[key])
		}
	}
}
