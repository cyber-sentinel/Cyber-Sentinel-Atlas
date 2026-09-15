//go:build phase554c_integration

package pack

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type integrationFixtures struct {
	V1Pack          string `json:"v1_pack"`
	V1Root          string `json:"v1_root"`
	V2Pack          string `json:"v2_pack"`
	V2Root          string `json:"v2_root"`
	CorruptPack     string `json:"corrupt_pack"`
	CorruptRoot     string `json:"corrupt_root"`
	RollbackOldPack string `json:"rollback_old_pack"`
	RollbackNewPack string `json:"rollback_new_pack"`
	RollbackRoot    string `json:"rollback_root"`
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func buildSignedFixtures(t *testing.T) integrationFixtures {
	t.Helper()
	python := os.Getenv("ATLAS_PHASE554C_PYTHON")
	if python == "" {
		t.Skip("ATLAS_PHASE554C_PYTHON is required for Phase 5.5.4C integration")
	}
	root := repositoryRoot(t)
	work := t.TempDir()
	out := filepath.Join(work, "fixtures.json")
	const script = `
import json, shutil, sys
from pathlib import Path
root = Path(sys.argv[1])
work = Path(sys.argv[2])
out = Path(sys.argv[3])
sys.path.insert(0, str(root))
from tests.phase55.phase552_helpers import make_signed_repository, bump_repository_metadata
from tools.pack.builder import build_verified_atlaspack

def make(name, version, **kwargs):
    fixture = make_signed_repository(work / name, pack_version=version, **kwargs)
    pack = work / f"{name}.atlaspack"
    build_verified_atlaspack(fixture.root, pack, bootstrap_root=fixture.bootstrap_root)
    root_file = work / f"{name}-root.json"
    root_file.write_bytes(fixture.bootstrap_root)
    return fixture, pack, root_file

v1, v1_pack, v1_root = make("v1", "1.0.0-test.1")
v2, v2_pack, v2_root = make("v2", "1.0.0-test.2")
corrupt, corrupt_pack, corrupt_root = make("corrupt", "1.0.0-test.3", corrupt_search_index=True)
rollback = make_signed_repository(work / "rollback", pack_version="1.0.0-test.4")
rollback_root = work / "rollback-root.json"
rollback_root.write_bytes(rollback.bootstrap_root)
rollback_old_pack = work / "rollback-old.atlaspack"
build_verified_atlaspack(rollback.root, rollback_old_pack, bootstrap_root=rollback.bootstrap_root)
bump_repository_metadata(rollback)
rollback_new_pack = work / "rollback-new.atlaspack"
build_verified_atlaspack(rollback.root, rollback_new_pack, bootstrap_root=rollback.bootstrap_root)
json.dump({
    "v1_pack": str(v1_pack), "v1_root": str(v1_root),
    "v2_pack": str(v2_pack), "v2_root": str(v2_root),
    "corrupt_pack": str(corrupt_pack), "corrupt_root": str(corrupt_root),
    "rollback_old_pack": str(rollback_old_pack),
    "rollback_new_pack": str(rollback_new_pack),
    "rollback_root": str(rollback_root),
}, out.open("w", encoding="utf-8"), sort_keys=True)
`
	cmd := exec.Command(python, "-c", script, root, work, out)
	cmd.Dir = root
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build signed Phase C fixtures: %v\n%s", err, output)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var fixtures integrationFixtures
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	return fixtures
}

func verifyArchive(t *testing.T, packPath, rootPath, work, cache string) *VerifiedPack {
	t.Helper()
	extracted := filepath.Join(work, "extracted")
	verifiedTargets := filepath.Join(work, "verified")
	if _, err := SafeExtractAtlaspack(packPath, extracted, DefaultSafetyLimits()); err != nil {
		t.Fatalf("extract %s: %v", packPath, err)
	}
	rootBytes, err := os.ReadFile(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyPackDirectory(extracted, rootBytes, cache, verifiedTargets, CurrentRuntimeVersion)
	if err != nil {
		t.Fatalf("verify %s: %v", packPath, err)
	}
	return verified
}

func restoreTempTreePermissions(root string) {
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() {
			_ = os.Chmod(path, 0o700)
		}
		return nil
	})
}

func TestSignedPackVerificationActivationAndRollbackParity(t *testing.T) {
	fixtures := buildSignedFixtures(t)
	v1 := verifyArchive(t, fixtures.V1Pack, fixtures.V1Root, filepath.Join(t.TempDir(), "v1"), filepath.Join(t.TempDir(), "v1-cache"))
	v2 := verifyArchive(t, fixtures.V2Pack, fixtures.V2Root, filepath.Join(t.TempDir(), "v2"), filepath.Join(t.TempDir(), "v2-cache"))

	runtime := filepath.Join(t.TempDir(), "runtime")
	t.Cleanup(func() {
		restoreTempTreePermissions(runtime)
	})
	g1, err := InstallVerifiedGeneration(v1, runtime, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := InstallVerifiedGeneration(v2, runtime, nil, func(string) error { return os.ErrInvalid }); err == nil || !strings.Contains(err.Error(), "LKG restored") {
		t.Fatalf("post-health failure did not restore LKG: %v", err)
	}
	state, err := LoadRuntimeState(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if state.ActiveGeneration == nil || *state.ActiveGeneration != g1 || state.LKGGeneration == nil || *state.LKGGeneration != g1 {
		t.Fatalf("LKG rollback pointers are wrong: %#v", state)
	}
	seen := state.HighestSeenPacks[v2.PackID]
	if seen.Version != v2.PackVersion || seen.ManifestDigest != v2.ManifestDigest {
		t.Fatalf("highest-seen trust was rolled back incorrectly: %#v", seen)
	}
	reports, err := filepath.Glob(filepath.Join(runtime, "reports", "rollback", "*.json"))
	if err != nil || len(reports) != 1 {
		t.Fatalf("rollback evidence missing: %v %v", reports, err)
	}
}

func TestWrongBootstrapAndCorruptSignedIndex(t *testing.T) {
	fixtures := buildSignedFixtures(t)
	work := filepath.Join(t.TempDir(), "wrong-root")
	extracted := filepath.Join(work, "extracted")
	if _, err := SafeExtractAtlaspack(fixtures.V1Pack, extracted, DefaultSafetyLimits()); err != nil {
		t.Fatal(err)
	}
	wrongRoot, err := os.ReadFile(fixtures.V2Root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPackDirectory(extracted, wrongRoot, filepath.Join(work, "cache"), filepath.Join(work, "verified"), CurrentRuntimeVersion); err == nil || !strings.Contains(err.Error(), "TUF") {
		t.Fatalf("wrong bootstrap root was not rejected: %v", err)
	}

	corrupt := verifyArchive(t, fixtures.CorruptPack, fixtures.CorruptRoot, filepath.Join(t.TempDir(), "corrupt"), filepath.Join(t.TempDir(), "corrupt-cache"))
	if !corrupt.UsedRebuiltSearchIndex {
		t.Fatal("signed corrupt search index should have been rebuilt from verified SPC")
	}
	if !strings.Contains(filepath.ToSlash(corrupt.RuntimeSearchIndex), "/_runtime-derived/search/atlas-search.sqlite3") {
		t.Fatalf("unexpected rebuilt search path: %s", corrupt.RuntimeSearchIndex)
	}
}

func TestPersistentTUFMetadataRollbackRejected(t *testing.T) {
	fixtures := buildSignedFixtures(t)
	rootBytes, err := os.ReadFile(fixtures.RollbackRoot)
	if err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(t.TempDir(), "durable-tuf")
	verify := func(packPath, name string) error {
		work := filepath.Join(t.TempDir(), name)
		extracted := filepath.Join(work, "extracted")
		if _, err := SafeExtractAtlaspack(packPath, extracted, DefaultSafetyLimits()); err != nil {
			return err
		}
		_, err := VerifyPackDirectory(extracted, rootBytes, cache, filepath.Join(work, "verified"), CurrentRuntimeVersion)
		return err
	}
	if err := verify(fixtures.RollbackOldPack, "old-first"); err != nil {
		t.Fatal(err)
	}
	if err := verify(fixtures.RollbackNewPack, "new"); err != nil {
		t.Fatal(err)
	}
	if err := verify(fixtures.RollbackOldPack, "old-replay"); err == nil {
		t.Fatal("previously valid TUF metadata replay was accepted after newer metadata")
	}
}
