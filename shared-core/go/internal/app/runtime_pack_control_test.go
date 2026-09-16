package app

import (
	"encoding/json"
	"testing"

	"github.com/cyber-sentinel/Cyber-Sentinel-Atlas/shared-core/go/internal/protocol"
)

func TestPackStatusIncludesCoreOwnedControlState(t *testing.T) {
	runtimeRoot := t.TempDir()
	runtime := NewUnconfiguredAt(runtimeRoot)

	status, operationError := runtime.Handle("pack.status", json.RawMessage(`{}`))
	if operationError != nil {
		t.Fatalf("pack.status: %v", operationError)
	}
	body := status.(map[string]any)
	if body["ready"] != false || body["state"] != "pack_runtime_not_activated" {
		t.Fatalf("unexpected unconfigured status: %#v", body)
	}
	if body["pending_update"] != false || body["rollback_available"] != false {
		t.Fatalf("unexpected pack control state: %#v", body)
	}
}

func TestPackControlMethodsRejectCallerSuppliedFields(t *testing.T) {
	runtime := NewUnconfiguredAt(t.TempDir())
	for _, method := range []string{"pack.update", "pack.rollback"} {
		_, operationError := runtime.Handle(method, json.RawMessage([]byte("{\"path\":\"C:\\\\untrusted.atlaspack\",\"generation_id\":\"caller-selected\"}")))
		if operationError == nil || operationError.Code != protocol.CodeInvalidRequest {
			t.Fatalf("%s must reject non-empty params: %#v", method, operationError)
		}
	}
}

func TestPackControlMethodsFailClosedWithoutEligibleState(t *testing.T) {
	runtime := NewUnconfiguredAt(t.TempDir())

	_, updateError := runtime.Handle("pack.update", json.RawMessage(`{}`))
	if updateError == nil || updateError.Code != protocol.CodeStateFailure {
		t.Fatalf("pack.update without pending update must fail closed: %#v", updateError)
	}

	_, rollbackError := runtime.Handle("pack.rollback", json.RawMessage(`{}`))
	if rollbackError == nil || rollbackError.Code != protocol.CodeStateFailure {
		t.Fatalf("pack.rollback without core-recorded target must fail closed: %#v", rollbackError)
	}
}

func TestReplaceReadModelPreservesCoreOwnedRuntimeRoot(t *testing.T) {
	current := &Runtime{RuntimeRoot: `C:\\atlas-runtime`, GenerationID: "old", PackVersion: "1.0.0"}
	next := &Runtime{GenerationID: "new", PackID: "atlas:pack:test", PackVersion: "1.0.1", ManifestDigest: "sha256-test"}

	current.replaceReadModel(next)
	if current.RuntimeRoot != `C:\\atlas-runtime` {
		t.Fatalf("runtime root changed during hot swap: %q", current.RuntimeRoot)
	}
	if current.GenerationID != "new" || current.PackVersion != "1.0.1" {
		t.Fatalf("read-model identity was not replaced: %#v", current)
	}
}
