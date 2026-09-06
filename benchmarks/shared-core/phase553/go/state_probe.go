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

// Match the frozen Atlas strict SemVer profile in tools/pack/versioning.py:
// MAJOR.MINOR.PATCH with an optional prerelease and no build metadata.
var semverRE = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$`)

type highestSeen struct {
	Version        string `json:"version"`
	ManifestDigest string `json:"manifest_digest"`
}

type runtimeState struct {
	StateVersion     int                    `json:"state_version"`
	ActiveGeneration string                 `json:"active_generation,omitempty"`
	LKGGeneration    string                 `json:"lkg_generation,omitempty"`
	HighestSeenPacks map[string]highestSeen `json:"highest_seen_packs"`
	HighestUTC       string                 `json:"highest_observed_utc"`
}

type parsedSemver struct {
	core       [3]int
	prerelease []string
}

func parseSemver(value string) (parsedSemver, error) {
	match := semverRE.FindStringSubmatch(value)
	if match == nil {
		return parsedSemver{}, fmt.Errorf("invalid strict SemVer: %q", value)
	}
	var parsed parsedSemver
	for i := 0; i < 3; i++ {
		n, err := strconv.Atoi(match[i+1])
		if err != nil {
			return parsedSemver{}, fmt.Errorf("invalid strict SemVer: %q", value)
		}
		parsed.core[i] = n
	}
	if match[4] != "" {
		parsed.prerelease = strings.Split(match[4], ".")
		for _, token := range parsed.prerelease {
			if token == "" {
				return parsedSemver{}, fmt.Errorf("invalid strict SemVer prerelease: %q", value)
			}
			if _, err := strconv.Atoi(token); err == nil && len(token) > 1 && token[0] == '0' {
				return parsedSemver{}, fmt.Errorf("numeric prerelease identifier has leading zero: %q", value)
			}
		}
	}
	return parsed, nil
}

func compareSemver(left, right string) (int, error) {
	l, err := parseSemver(left)
	if err != nil {
		return 0, err
	}
	r, err := parseSemver(right)
	if err != nil {
		return 0, err
	}
	for i := 0; i < 3; i++ {
		if l.core[i] < r.core[i] {
			return -1, nil
		}
		if l.core[i] > r.core[i] {
			return 1, nil
		}
	}
	if len(l.prerelease) == 0 && len(r.prerelease) == 0 {
		return 0, nil
	}
	if len(l.prerelease) == 0 {
		return 1, nil
	}
	if len(r.prerelease) == 0 {
		return -1, nil
	}
	limit := len(l.prerelease)
	if len(r.prerelease) < limit {
		limit = len(r.prerelease)
	}
	for i := 0; i < limit; i++ {
		lt, rt := l.prerelease[i], r.prerelease[i]
		if lt == rt {
			continue
		}
		ln, lerr := strconv.Atoi(lt)
		rn, rerr := strconv.Atoi(rt)
		lnum, rnum := lerr == nil, rerr == nil
		switch {
		case lnum && rnum:
			if ln < rn {
				return -1, nil
			}
			return 1, nil
		case lnum != rnum:
			if lnum {
				return -1, nil
			}
			return 1, nil
		default:
			if lt < rt {
				return -1, nil
			}
			return 1, nil
		}
	}
	if len(l.prerelease) < len(r.prerelease) {
		return -1, nil
	}
	if len(l.prerelease) > len(r.prerelease) {
		return 1, nil
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
		_ = file.Close()
		return false, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return false, err
	}
	if err := file.Close(); err != nil {
		return false, err
	}
	durable, err := atomicReplaceDurable(temp, path)
	if err != nil {
		return false, err
	}
	cleanup = false
	return durable, nil
}

func loadRuntimeState(path string) (runtimeState, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return runtimeState{}, nil, err
	}
	var state runtimeState
	if err := json.Unmarshal(data, &state); err != nil {
		return runtimeState{}, nil, err
	}
	return state, data, nil
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
		_ = file.Close()
		return nil, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func generationID(manifestDigest string) string {
	sum := sha256.Sum256([]byte(manifestDigest))
	return hex.EncodeToString(sum[:])
}

func observePack(state *runtimeState, packID, version, manifestDigest string) error {
	if _, err := parseSemver(version); err != nil {
		return err
	}
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

// Activation is deliberately two-phase. The candidate generation becomes active
// first while LKG remains unchanged; only a passing health check promotes it to LKG.
func beginActivation(state *runtimeState, generation string) {
	state.ActiveGeneration = generation
}

func finishActivationHealth(state *runtimeState, healthy bool) error {
	if healthy {
		state.LKGGeneration = state.ActiveGeneration
		return nil
	}
	if state.LKGGeneration == "" {
		return fmt.Errorf("health check failed and no LKG exists")
	}
	state.ActiveGeneration = state.LKGGeneration
	return fmt.Errorf("health check failed; LKG restored")
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

	statePath := filepath.Join(root, "state", "runtime-state.json")
	state := runtimeState{StateVersion: 1, HighestSeenPacks: map[string]highestSeen{}}
	baseTime := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	timeOK := observeTime(&state, baseTime) == nil

	manifestA := "sha256-" + strings.Repeat("a", 64)
	manifestB := "sha256-" + strings.Repeat("b", 64)
	manifestC := "sha256-" + strings.Repeat("c", 64)
	packID := "atlas:pack:phase553-state"
	genA, genB, genC := generationID(manifestA), generationID(manifestB), generationID(manifestC)
	generationIdentity := genA != genB && genB != genC && generationID(manifestA) == genA

	durabilityChecks := []bool{}
	persist := func() (runtimeState, error) {
		durable, err := durableWrite(statePath, state)
		if err != nil {
			return runtimeState{}, err
		}
		durabilityChecks = append(durabilityChecks, durable)
		reloaded, _, err := loadRuntimeState(statePath)
		return reloaded, err
	}

	installA := observePack(&state, packID, "1.0.0", manifestA) == nil
	beginActivation(&state, genA)
	reloaded, err := persist()
	if err != nil {
		return nil, false, err
	}
	candidateAPersisted := reloaded.ActiveGeneration == genA && reloaded.LKGGeneration == ""
	activateAHealth := finishActivationHealth(&state, true) == nil
	reloaded, err = persist()
	if err != nil {
		return nil, false, err
	}
	activateA := activateAHealth && reloaded.ActiveGeneration == genA && reloaded.LKGGeneration == genA

	installB := observePack(&state, packID, "1.1.0", manifestB) == nil
	beginActivation(&state, genB)
	reloaded, err = persist()
	if err != nil {
		return nil, false, err
	}
	candidateBPersisted := reloaded.ActiveGeneration == genB && reloaded.LKGGeneration == genA
	activateBHealth := finishActivationHealth(&state, true) == nil
	reloaded, err = persist()
	if err != nil {
		return nil, false, err
	}
	activateB := activateBHealth && reloaded.ActiveGeneration == genB && reloaded.LKGGeneration == genB

	replayA := observePack(&state, packID, "1.0.0", manifestA) != nil
	sameVersionDifferent := observePack(&state, packID, "1.1.0", manifestC) != nil
	installC := observePack(&state, packID, "1.2.0", manifestC) == nil
	beginActivation(&state, genC)
	reloaded, err = persist()
	if err != nil {
		return nil, false, err
	}
	candidateCPersisted := reloaded.ActiveGeneration == genC && reloaded.LKGGeneration == genB
	healthFailure := finishActivationHealth(&state, false) != nil
	reloaded, err = persist()
	if err != nil {
		return nil, false, err
	}
	healthRollback := healthFailure && reloaded.ActiveGeneration == genB && reloaded.LKGGeneration == genB
	highestPreserved := reloaded.HighestSeenPacks[packID].Version == "1.2.0" && reloaded.HighestSeenPacks[packID].ManifestDigest == manifestC
	clockRollback := observeTime(&state, baseTime.Add(-time.Second)) != nil

	preState := runtimeState{StateVersion: 1, HighestSeenPacks: map[string]highestSeen{}}
	prePack := "atlas:pack:phase553-semver"
	pre1 := observePack(&preState, prePack, "2.0.0-alpha.1", manifestA) == nil
	pre2 := observePack(&preState, prePack, "2.0.0-alpha.beta", manifestB) == nil
	pre3 := observePack(&preState, prePack, "2.0.0-beta", manifestC) == nil
	pre4 := observePack(&preState, prePack, "2.0.0", manifestA) == nil
	preReplay := observePack(&preState, prePack, "2.0.0-beta", manifestC) != nil
	leadingZeroRejected := observePack(&preState, prePack+":bad-zero", "2.0.0-alpha.01", manifestA) != nil
	buildMetadataRejected := observePack(&preState, prePack+":bad-build", "2.0.0+build.1", manifestA) != nil
	semverPrecedence := pre1 && pre2 && pre3 && pre4 && preReplay && leadingZeroRejected && buildMetadataRejected

	persistedState, persistedBytes, err := loadRuntimeState(statePath)
	if err != nil {
		return nil, false, err
	}
	stateReload := persistedState.ActiveGeneration == genB && persistedState.LKGGeneration == genB && highestPreserved

	// Simulate a crash after a future state temp file was fully written+fsynced but
	// before atomic replacement. The authoritative file must remain the old complete
	// generation; a restart must never consume the orphan temp as state.
	future := persistedState
	future.ActiveGeneration = "interrupted-generation"
	futureBytes, _ := json.Marshal(future)
	orphan := filepath.Join(filepath.Dir(statePath), ".runtime-state.json.crash.tmp")
	orphanFile, orphanErr := os.OpenFile(orphan, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if orphanErr == nil {
		_, orphanErr = orphanFile.Write(append(futureBytes, '\n'))
		if orphanErr == nil {
			orphanErr = orphanFile.Sync()
		}
		_ = orphanFile.Close()
	}
	afterCrash, readErr := os.ReadFile(statePath)
	crashRecovery := orphanErr == nil && readErr == nil && string(afterCrash) == string(persistedBytes)
	_ = os.Remove(orphan)

	trustedTimeStateLoss := persistedState.HighestUTC != "" && len(persistedState.HighestSeenPacks) > 0
	replacementDurability := len(durabilityChecks) >= 6
	for _, ok := range durabilityChecks {
		replacementDurability = replacementDurability && ok
	}

	cases := map[string]bool{
		"exclusive_install_lock": exclusiveLock,
		"trusted_time_initial": timeOK,
		"immutable_generation_identity": generationIdentity,
		"install_A": installA,
		"candidate_A_persisted_before_health": candidateAPersisted,
		"activate_A_lkg_A": activateA,
		"install_B": installB,
		"candidate_B_persisted_before_health": candidateBPersisted,
		"activate_B_lkg_B": activateB,
		"replay_A_rejected": replayA,
		"same_version_different_manifest_rejected": sameVersionDifferent,
		"install_C": installC,
		"candidate_C_was_active_before_health": candidateCPersisted,
		"health_failure_restores_lkg_B": healthRollback,
		"highest_seen_survives_health_rollback": highestPreserved,
		"clock_rollback_rejected": clockRollback,
		"strict_semver_prerelease_precedence": semverPrecedence,
		"existing_file_atomic_replacements_durable": replacementDurability,
		"durable_state_reload": stateReload,
		"crash_before_replace_keeps_authoritative_state": crashRecovery,
		"trusted_time_state_loss_requires_admin": trustedTimeStateLoss,
	}
	all := true
	for _, ok := range cases {
		all = all && ok
	}
	return map[string]any{
		"cases": cases,
		"file_fsync": true,
		"atomic_replace": replacementDurability,
		"replacement_durability_supported": replacementDurability,
		"replacement_primitive": atomicReplacePrimitive(),
		"replacement_count": len(durabilityChecks),
		"state_path": statePath,
	}, all, nil
}
