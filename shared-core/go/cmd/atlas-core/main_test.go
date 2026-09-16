package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenRuntimeAtNoActiveGenerationStaysAvailable(t *testing.T) {
	runtime, err := openRuntimeAt(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	status, operationError := runtime.Handle("pack.status", json.RawMessage(`{}`))
	if operationError != nil {
		t.Fatalf("pack.status: %v", operationError)
	}
	body := status.(map[string]any)
	if body["ready"] != false || body["state"] != "pack_runtime_not_activated" {
		t.Fatalf("unexpected no-pack status: %#v", body)
	}
}

func TestOpenRuntimeAtCorruptStateFailsClosed(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "runtime-state.json"), []byte("{not-json}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openRuntimeAt(root); err == nil {
		t.Fatal("corrupt durable runtime state must fail closed")
	}
}
