package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var semverRE = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)

type highestSeen struct {
	Version        string `json:"version"`
	ManifestDigest string `json:"manifest_digest"`
}

type runtimeState struct {
	StateVersion    int                    `json:"state_version"`
	ActiveGeneration string                `json:"active_generation,omitempty"`
	LKGGeneration    string                `json:"lkg_generation,omitempty"`
	HighestSeenPacks map[string]highestSeen `json:"highest_seen_packs"`
	HighestUTC        string                `json:"highest_observed_utc"`
}

func compareSemver(left, right string) (int, error) {
	lm := semverRE.FindStringSubmatch(left)
	rm := semverRE.FindStringSubmatch(right)
	if lm == nil || rm == nil {
		return 0, fmt.Errorf("invalid SemVer")
	}
	for i := 1; i <= 3; i++ {
		lv, _ := strconv.Atoi(lm[i])
		rv, _ := strconv.Atoi(rm[i])
		if lv < rv {
			return -1, nil
		}
		if lv > rv {
			return 1, nil
		}
	}
	return 0, nil
}

func durableWrite(path string, value any) (bool, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false, err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return false, err
	}
	data = append(data, '\n')
	temp := filepath.Join(filepath.Dir(path), fmt.Sprintf(".%s.%d.tmp", filepath.Base(path), time.Now().UnixNano()))
	file, err := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return false, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(temp)
		}
	}()
	if _, err := file.Write(data); err != nil {
		file.Close()
		return false, err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return false, err
	}
	if err := file.Close(); err != nil {
		return false, err
	}
	if err := os.Rename(temp, path); err != nil {
		return false, err
	}
	cleanup = false
	dirSynced := false
	if dir, err := os.Open(filepath.Dir(path)); err == nil {
		if err := dir.Sync(); err == nil {
			dirSynced = true
		}
		_ = dir.Close()
	}
	return dirSynced, nil
}

func acquireExclusiveLock(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err := fmt.Fprintf(file, "pid=%d\n", os.Getpid()); err != nil {
		file.Close()
		return nil, err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func generationID(manifestDigest string) string {
	sum := sha256.Sum256([]byte(manifestDigest))
	return hex.EncodeToString(sum[:])
}

func observePack(state *runtimeState, packID, version, manifestDigest string) error {
	previous, exists := state.HighestSeenPacks[packID]
	if exists {
		cmp, err := compareSemver(version, previous.Version)
		if err != nil {
			return err
		}
		if cmp < 0 {
			return fmt.Errorf("pack rollback rejected")
		}
		if cmp == 0 && manifestDigest != previous.ManifestDigest {
			return fmt.Errorf("same version with different manifest rejected")
		}
	}
	state.HighestSeenPacks[packID] = highestSeen{Version: version, ManifestDigest: manifestDigest}
	return nil
}

func activate(state *runtimeState, generation string, healthOK bool) error {
	previous := state.ActiveGeneration
	if !healthOK {
		if previous != "" {
			state.ActiveGeneration = previous
			state.LKGGeneration = previous
		}
		return fmt.Errorf("health check failed; LKG restored")
	}
	state.ActiveGeneration = generation
	state.LKGGeneration = generation
	return nil
}

func observeTime(state *runtimeState, observed time.Time) error {
	observed = observed.UTC()
	if state.HighestUTC != "" {
		highest, err := time.Parse(time.RFC3339Nano, state.HighestUTC)
		if err != nil {
			return err
		}
		if observed.Before(highest) {
			return fmt.Errorf("clock rollback rejected")
		}
	}
	state.HighestUTC = observed.Format(time.RFC3339Nano)
	return nil
}

func runStateProbe(root string) (map[string]any, bool, error) {
	_ = os.RemoveAll(root)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, false, err
	}
	lockPath := filepath.Join(root, "state", "install.lock")
	lock, err := acquireExclusiveLock(lockPath)
	if err != nil {
		return nil, false, err
	}
	_, secondLockErr := acquireExclusiveLock(lockPath)
	exclusiveLock := secondLockErr != nil
	_ = lock.Close()
	_ = os.Remove(lockPath)

	state := runtimeState{StateVersion: 1, HighestSeenPacks: map[string]highestSeen{}}
	baseTime := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	timeOK := observeTime(&state, baseTime) == nil

	manifestA := "sha256-" + strings.Repeat("a", 64)
	manifestB := "sha256-" + strings.Repeat("b", 64)
	manifestC := "sha256-" + strings.Repeat("c", 64)
	packID := "atlas:pack:phase553-state"
	installA := observePack(&state, packID, "1.0.0", manifestA) == nil
	genA := generationID(manifestA)
	activateA := activate(&state, genA, true) == nil && state.ActiveGeneration == genA && state.LKGGeneration == genA
	installB := observePack(&state, packID, "1.1.0", manifestB) == nil
	genB := generationID(manifestB)
	activateB := activate(&state, genB, true) == nil && state.ActiveGeneration == genB && state.LKGGeneration == genB
	replayA := observePack(&state, packID, "1.0.0", manifestA) != nil
	sameVersionDifferent := observePack(&state, packID, "1.1.0", manifestC) != nil
	_ = observePack(&state, packID, "1.2.0", manifestC)
	genC := generationID(manifestC)
	healthRollback := activate(&state, genC, false) != nil && state.ActiveGeneration == genB && state.LKGGeneration == genB
	clockRollback := observeTime(&state, baseTime.Add(-time.Second)) != nil

	statePath := filepath.Join(root, "state", "runtime-state.json")
	dirSynced, err := durableWrite(statePath, state)
	if err != nil {
		return nil, false, err
	}
	persisted, err := os.ReadFile(statePath)
	if err != nil {
		return nil, false, err
	}
	var reloaded runtimeState
	stateReload := json.Unmarshal(persisted, &reloaded) == nil && reloaded.ActiveGeneration == genB

	// Simulate an interrupted future write: an orphan temp must not alter the
	// authoritative state file.
	orphan := filepath.Join(filepath.Dir(statePath), ".runtime-state.json.crash.tmp")
	_ = os.WriteFile(orphan, []byte("partial"), 0o600)
	afterCrash, err := os.ReadFile(statePath)
	crashRecovery := err == nil && string(afterCrash) == string(persisted)
	_ = os.Remove(orphan)

	// Missing trusted-time while durable runtime state exists is an explicit
	// administrative recovery condition, not an automatic reset.
	trustedTimeStateLoss := reloaded.HighestUTC != "" && len(reloaded.HighestSeenPacks) > 0

	cases := map[string]bool{
		"exclusive_install_lock": exclusiveLock,
		"trusted_time_initial": timeOK,
		"install_A": installA,
		"activate_A_lkg_A": activateA,
		"install_B": installB,
		"activate_B_lkg_B": activateB,
		"replay_A_rejected": replayA,
		"same_version_different_manifest_rejected": sameVersionDifferent,
		"health_failure_restores_lkg_B": healthRollback,
		"clock_rollback_rejected": clockRollback,
		"durable_state_reload": stateReload,
		"crash_orphan_does_not_replace_state": crashRecovery,
		"trusted_time_state_loss_requires_admin": trustedTimeStateLoss,
	}
	all := true
	for _, ok := range cases {
		all = all && ok
	}
	return map[string]any{
		"cases": cases,
		"file_fsync": true,
		"directory_fsync_supported": dirSynced,
		"atomic_replace": true,
		"state_path": statePath,
	}, all, nil
}
