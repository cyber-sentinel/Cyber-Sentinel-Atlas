package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cyber-sentinel/Cyber-Sentinel-Atlas/shared-core/go/internal/pack"
)

func TestResolveRuntimeRootNamespacesEngineeringBuildByCommit(t *testing.T) {
	for _, version := range []string{"0.1.0-preview", "0.2.0-mvp2-private"} {
		t.Run(version, func(t *testing.T) {
			oldVersion, oldCommit := coreVersion, coreCommit
			defer func() {
				coreVersion, coreCommit = oldVersion, oldCommit
			}()
			coreVersion = version
			coreCommit = strings.Repeat("a", 40)

			base, err := pack.DefaultRuntimeRoot()
			if err != nil {
				t.Fatal(err)
			}
			got, err := resolveRuntimeRoot()
			if err != nil {
				t.Fatal(err)
			}
			want := filepath.Join(base, "preview-builds", coreCommit)
			if got != want {
				t.Fatalf("engineering runtime root = %q want %q", got, want)
			}
		})
	}
}

func TestResolveRuntimeRootProductionUsesStableBase(t *testing.T) {
	oldVersion, oldCommit := coreVersion, coreCommit
	defer func() {
		coreVersion, coreCommit = oldVersion, oldCommit
	}()
	coreVersion = "1.0.0"
	coreCommit = strings.Repeat("b", 40)

	want, err := pack.DefaultRuntimeRoot()
	if err != nil {
		t.Fatal(err)
	}
	got, err := resolveRuntimeRoot()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("production runtime root = %q want stable %q", got, want)
	}
}

func TestResolveRuntimeRootEngineeringRejectsUnsafeCommit(t *testing.T) {
	oldVersion, oldCommit := coreVersion, coreCommit
	defer func() {
		coreVersion, coreCommit = oldVersion, oldCommit
	}()
	coreVersion = "0.2.0-mvp2-private"
	coreCommit = "../not-a-commit"

	if _, err := resolveRuntimeRoot(); err == nil || !strings.Contains(err.Error(), "40-character hexadecimal") {
		t.Fatalf("unsafe engineering commit must fail closed: %v", err)
	}
}

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
