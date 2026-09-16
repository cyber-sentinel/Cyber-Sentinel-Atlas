//go:build phase554c_integration

package pack

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCoreOwnedPendingUpdateUsesDurableTrustRoot(t *testing.T) {
	fixtures := buildSignedFixtures(t)
	rootBytes, err := os.ReadFile(fixtures.RollbackRoot)
	if err != nil {
		t.Fatal(err)
	}
	runtimeRoot := filepath.Join(t.TempDir(), "runtime")
	t.Cleanup(func() { restoreTempTreePermissions(runtimeRoot) })

	generationID, err := InstallAtlaspack(
		fixtures.RollbackOldPack,
		rootBytes,
		runtimeRoot,
		CurrentRuntimeVersion,
		DefaultSafetyLimits(),
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("install initial signed pack: %v", err)
	}
	if err := ensureControlRuntimeRoot(runtimeRoot); err != nil {
		t.Fatal(err)
	}
	pendingBytes, err := os.ReadFile(fixtures.RollbackNewPack)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(PendingUpdatePath(runtimeRoot), pendingBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := ApplyPendingUpdate(runtimeRoot)
	if err != nil {
		t.Fatalf("apply core-owned pending update: %v", err)
	}
	if result.GenerationID != generationID {
		t.Fatalf("metadata-only fixture update should preserve generation identity: got %s want %s", result.GenerationID, generationID)
	}
	if result.RollbackAvailable {
		t.Fatalf("same-generation metadata refresh must not create a rollback target: %#v", result)
	}
}

func TestManualRollbackPreservesHighestSeenTrust(t *testing.T) {
	fixtures := buildSignedFixtures(t)
	v1 := verifyArchive(t, fixtures.V1Pack, fixtures.V1Root, filepath.Join(t.TempDir(), "v1"), filepath.Join(t.TempDir(), "v1-cache"))
	v2 := verifyArchive(t, fixtures.V2Pack, fixtures.V2Root, filepath.Join(t.TempDir(), "v2"), filepath.Join(t.TempDir(), "v2-cache"))

	runtimeRoot := filepath.Join(t.TempDir(), "runtime")
	t.Cleanup(func() { restoreTempTreePermissions(runtimeRoot) })
	if err := GuardTrustedTime(runtimeRoot, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	g1, err := InstallVerifiedGeneration(v1, runtimeRoot, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	g2, err := InstallVerifiedUpdate(v2, runtimeRoot)
	if err != nil {
		t.Fatal(err)
	}
	if g1 == g2 {
		t.Fatal("fixture generations must differ for manual rollback coverage")
	}
	status, err := ControlState(runtimeRoot)
	if err != nil {
		t.Fatal(err)
	}
	if !status.RollbackAvailable || status.RollbackTarget == nil || status.RollbackTarget.GenerationID != g1 {
		t.Fatalf("previous active generation was not captured for rollback: %#v", status)
	}
	before, err := LoadRuntimeState(runtimeRoot)
	if err != nil {
		t.Fatal(err)
	}
	highestBefore := before.HighestSeenPacks[v2.PackID]
	if highestBefore.Version != v2.PackVersion || highestBefore.ManifestDigest != v2.ManifestDigest {
		t.Fatalf("new version was not retained as highest-seen before rollback: %#v", highestBefore)
	}

	result, err := RollbackPrevious(runtimeRoot)
	if err != nil {
		t.Fatal(err)
	}
	if result.GenerationID != g1 {
		t.Fatalf("manual rollback restored wrong generation: got %s want %s", result.GenerationID, g1)
	}
	after, err := LoadRuntimeState(runtimeRoot)
	if err != nil {
		t.Fatal(err)
	}
	if after.ActiveGeneration == nil || *after.ActiveGeneration != g1 || after.LKGGeneration == nil || *after.LKGGeneration != g1 {
		t.Fatalf("manual rollback state pointers are wrong: %#v", after)
	}
	highestAfter := after.HighestSeenPacks[v2.PackID]
	if highestAfter != highestBefore {
		t.Fatalf("manual rollback rewound highest-seen trust: before=%#v after=%#v", highestBefore, highestAfter)
	}
	if !result.RollbackAvailable || result.RollbackTarget == nil || result.RollbackTarget.GenerationID != g2 {
		t.Fatalf("successful rollback should preserve a one-step return target: %#v", result)
	}
}
