package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

func TestInstallBundledEngineeringPreviewAbsentIsNoop(t *testing.T) {
	runtimeRoot := filepath.Join(t.TempDir(), "runtime")
	bundleRoot := filepath.Join(t.TempDir(), "bundle")
	if err := os.MkdirAll(bundleRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	installed, err := installBundledEngineeringPreview(runtimeRoot, bundleRoot)
	if err != nil {
		t.Fatalf("absent bundle must preserve unconfigured startup: %v", err)
	}
	if installed {
		t.Fatal("absent bundle unexpectedly reported an installation")
	}
}

func TestInstallBundledEngineeringPreviewPartialBundleFailsClosed(t *testing.T) {
	for _, only := range []string{bundledPreviewPackName, bundledPreviewRootName} {
		t.Run(only, func(t *testing.T) {
			runtimeRoot := filepath.Join(t.TempDir(), "runtime")
			bundleRoot := filepath.Join(t.TempDir(), "bundle")
			if err := os.MkdirAll(bundleRoot, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(bundleRoot, only), []byte("fixture"), 0o600); err != nil {
				t.Fatal(err)
			}
			installed, err := installBundledEngineeringPreview(runtimeRoot, bundleRoot)
			if err == nil || !strings.Contains(err.Error(), "incomplete") {
				t.Fatalf("partial bundle must fail closed, installed=%v err=%v", installed, err)
			}
			if installed {
				t.Fatal("partial bundle unexpectedly reported an installation")
			}
		})
	}
}

func TestInstallBundledEngineeringPreviewRejectsUnsafeFiles(t *testing.T) {
	bundleRoot := filepath.Join(t.TempDir(), "bundle")
	if err := os.MkdirAll(bundleRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(bundleRoot, "root-target.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(bundleRoot, bundledPreviewRootName)); err != nil {
		t.Skipf("symlink creation unavailable on this platform: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bundleRoot, bundledPreviewPackName), []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	installed, err := installBundledEngineeringPreview(filepath.Join(t.TempDir(), "runtime"), bundleRoot)
	if err == nil || !strings.Contains(err.Error(), "not a normal file") {
		t.Fatalf("unsafe bundle path must fail closed, installed=%v err=%v", installed, err)
	}
}
