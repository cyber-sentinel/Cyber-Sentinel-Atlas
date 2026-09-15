package pack

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStrictSemverPrecedence(t *testing.T) {
	cases := []struct {
		left, right string
		want        int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.1", "1.0.0", 1},
		{"2.0.0", "10.0.0", -1},
		{"1.0.0-alpha", "1.0.0", -1},
		{"1.0.0-alpha.1", "1.0.0-alpha.beta", -1},
		{"1.0.0-beta.11", "1.0.0-rc.1", -1},
		{"1.0.0-rc.1", "1.0.0", -1},
	}
	for _, tc := range cases {
		got, err := compareSemver(tc.left, tc.right)
		if err != nil || got != tc.want {
			t.Fatalf("compareSemver(%q,%q)=%d,%v want %d", tc.left, tc.right, got, err, tc.want)
		}
		reverse, err := compareSemver(tc.right, tc.left)
		if err != nil || reverse != -tc.want {
			t.Fatalf("reverse compareSemver(%q,%q)=%d,%v want %d", tc.right, tc.left, reverse, err, -tc.want)
		}
	}
}

func TestStrictSemverRejectsLeadingZeroAndBuildMetadata(t *testing.T) {
	for _, value := range []string{"01.0.0", "1.0.0-alpha.01", "1.0.0+build.1"} {
		if _, err := parseSemver(value); err == nil {
			t.Fatalf("invalid strict SemVer accepted: %q", value)
		}
	}
}

func TestObservePackRollbackAndSameVersionSubstitution(t *testing.T) {
	state := DefaultRuntimeState()
	packID := "atlas:pack:state-test"
	a := "sha256-" + strings.Repeat("a", 64)
	b := "sha256-" + strings.Repeat("b", 64)
	if err := ObservePack(&state, packID, "1.0.0-test.1", a); err != nil {
		t.Fatal(err)
	}
	if err := ObservePack(&state, packID, "1.0.0-test.2", b); err != nil {
		t.Fatal(err)
	}
	if err := ObservePack(&state, packID, "1.0.0-test.1", a); err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("lower pack version was not rejected: %v", err)
	}
	if err := ObservePack(&state, packID, "1.0.0-test.2", a); err == nil || !strings.Contains(err.Error(), "different manifest") {
		t.Fatalf("same-version manifest substitution was not rejected: %v", err)
	}
	seen := state.HighestSeenPacks[packID]
	if seen.Version != "1.0.0-test.2" || seen.ManifestDigest != b {
		t.Fatalf("highest-seen state changed after rejected rollback/substitution: %#v", seen)
	}
}

func TestRuntimeStateRoundTripAndCorruptionFailClosed(t *testing.T) {
	root := t.TempDir()
	if err := PrepareRuntimeRoot(root); err != nil {
		t.Fatal(err)
	}
	state := DefaultRuntimeState()
	generation := strings.Repeat("a", 64)
	state.ActiveGeneration = &generation
	state.LKGGeneration = &generation
	state.HighestSeenPacks["atlas:pack:state-test"] = HighestSeen{
		Version:        "1.2.3",
		ManifestDigest: "sha256-" + strings.Repeat("b", 64),
	}
	if err := WriteRuntimeState(root, state); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadRuntimeState(root)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ActiveGeneration == nil || *loaded.ActiveGeneration != generation || loaded.LKGGeneration == nil || *loaded.LKGGeneration != generation {
		t.Fatalf("runtime state round-trip mismatch: %#v", loaded)
	}
	statePath := filepath.Join(root, "state", stateName)
	if err := os.WriteFile(statePath, []byte(`{"state_version":1,"active_generation":"../../evil"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRuntimeState(root); err == nil {
		t.Fatal("corrupt/incomplete runtime state must fail closed")
	}
}

func TestStaleInstallLockFailsClosed(t *testing.T) {
	root := t.TempDir()
	if err := PrepareRuntimeRoot(root); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(root, "state", lockName)
	if err := os.WriteFile(lockPath, []byte("stale\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireRuntimeLock(root, time.Now().UTC()); err == nil || !strings.Contains(err.Error(), "administrative recovery") {
		t.Fatalf("stale lock did not fail closed: %v", err)
	}
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("stale lock was unexpectedly removed: %v", err)
	}
}

func TestTrustedTimeRollbackAndStateLossFailClosed(t *testing.T) {
	root := t.TempDir()
	base := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	if err := GuardTrustedTime(root, base); err != nil {
		t.Fatal(err)
	}
	if err := GuardTrustedTime(root, base.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := GuardTrustedTime(root, base); err == nil || !strings.Contains(err.Error(), "clock rollback") {
		t.Fatalf("trusted-time rollback was not rejected: %v", err)
	}
	trusted := filepath.Join(root, "state", trustedTimeName)
	if err := os.Remove(trusted); err != nil {
		t.Fatal(err)
	}
	state := DefaultRuntimeState()
	if err := WriteRuntimeState(root, state); err != nil {
		t.Fatal(err)
	}
	if err := GuardTrustedTime(root, base.Add(2*time.Second)); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("trusted-time state loss was not rejected: %v", err)
	}
}
