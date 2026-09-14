package app

import (
	"encoding/json"
	"testing"

	"github.com/cyber-sentinel/Cyber-Sentinel-Atlas/shared-core/go/internal/protocol"
)

func TestUnconfiguredRuntimeFailsClosed(t *testing.T) {
	runtime := NewUnconfigured()
	status, operationError := runtime.Handle("pack.status", json.RawMessage(`{}`))
	if operationError != nil {
		t.Fatalf("pack.status: %v", operationError)
	}
	body := status.(map[string]any)
	if body["ready"] != false {
		t.Fatalf("unconfigured pack status must be ready=false: %#v", body)
	}

	_, operationError = runtime.Handle("search.query", json.RawMessage(`{"query":"PowerShell"}`))
	if operationError == nil || operationError.Code != protocol.CodePackNotReady {
		t.Fatalf("unconfigured search must fail closed with pack-not-ready: %#v", operationError)
	}
}
