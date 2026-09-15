package pack

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	StateVersion       = 1
	TrustedTimeVersion = 1
	GenerationVersion  = 1
	stateName          = "runtime-state.json"
	trustedTimeName    = "trusted-time.json"
	lockName           = "install.lock"
)

type HighestSeen struct {
	Version        string `json:"version"`
	ManifestDigest string `json:"manifest_digest"`
}

type RuntimeState struct {
	StateVersion     int                    `json:"state_version"`
	ActiveGeneration *string                `json:"active_generation"`
	LKGGeneration    *string                `json:"lkg_generation"`
	HighestSeenPacks map[string]HighestSeen `json:"highest_seen_packs"`
}

type TrustedTimeState struct {
	TrustedTimeVersion int    `json:"trusted_time_version"`
	HighestObservedUTC string `json:"highest_observed_utc"`
}

type RuntimeLock struct {
	path string
	file *os.File
}

func DefaultRuntimeState() RuntimeState {
	return RuntimeState{StateVersion: StateVersion, HighestSeenPacks: map[string]HighestSeen{}}
}

func PrepareRuntimeRoot(root string) error {
	info, err := os.Lstat(root)
	if err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("runtime root must be a normal directory")
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(root, 0o700); err != nil {
			return err
		}
	} else {
		return err
	}
	for _, name := range []string{"state", "staging", "tuf", "generations", "reports"} {
		p := filepath.Join(root, name)
		if info, err := os.Lstat(p); err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("runtime subdirectory is unsafe: %s", name)
			}
		} else if errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(p, 0o700); err != nil {
				return err
			}
		} else {
			return err
		}
	}
	return nil
}

func AcquireRuntimeLock(runtimeRoot string, now time.Time) (*RuntimeLock, error) {
	if err := PrepareRuntimeRoot(runtimeRoot); err != nil {
		return nil, err
	}
	path := filepath.Join(runtimeRoot, "state", lockName)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("runtime install lock already exists; administrative recovery is required")
		}
		return nil, err
	}
	payload := map[string]any{"pid": os.Getpid(), "created_at": formatTrustedTime(now)}
	data, err := json.Marshal(payload)
	if err == nil {
		data = append(data, '\n')
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	if err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, err
	}
	return &RuntimeLock{path: path, file: file}, nil
}

func (l *RuntimeLock) Close() error {
	if l == nil {
		return nil
	}
	var first error
	if l.file != nil {
		if err := l.file.Close(); err != nil {
			first = err
		}
		l.file = nil
	}
	if err := os.Remove(l.path); err != nil && !errors.Is(err, os.ErrNotExist) && first == nil {
		first = err
	}
	return first
}

func validateState(state RuntimeState) error {
	if state.StateVersion != StateVersion {
		return fmt.Errorf("unsupported runtime state version")
	}
	if state.HighestSeenPacks == nil {
		return fmt.Errorf("highest_seen_packs must be an object")
	}
	for name, ptr := range map[string]*string{"active_generation": state.ActiveGeneration, "lkg_generation": state.LKGGeneration} {
		if ptr != nil && !hex64RE.MatchString(*ptr) {
			return fmt.Errorf("invalid runtime generation pointer: %s", name)
		}
	}
	for packID, seen := range state.HighestSeenPacks {
		if !packIDRE.MatchString(packID) || !digestRE.MatchString(seen.ManifestDigest) {
			return fmt.Errorf("invalid highest-seen pack record")
		}
		if _, err := parseSemver(seen.Version); err != nil {
			return fmt.Errorf("invalid highest-seen SemVer: %w", err)
		}
	}
	return nil
}

func LoadRuntimeState(runtimeRoot string) (RuntimeState, error) {
	path := filepath.Join(runtimeRoot, "state", stateName)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return DefaultRuntimeState(), nil
	}
	if err != nil {
		return RuntimeState{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return RuntimeState{}, fmt.Errorf("runtime state path is not a normal file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return RuntimeState{}, err
	}
	var state RuntimeState
	if err := decodeStrictJSON(data, &state); err != nil {
		return RuntimeState{}, fmt.Errorf("runtime state is corrupt/unreadable: %w", err)
	}
	if err := validateState(state); err != nil {
		return RuntimeState{}, err
	}
	return state, nil
}

func durableWriteJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	temp := filepath.Join(filepath.Dir(path), fmt.Sprintf(".%s.%d.tmp", filepath.Base(path), time.Now().UnixNano()))
	file, err := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(temp)
		}
	}()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := atomicReplaceDurable(temp, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func WriteRuntimeState(runtimeRoot string, state RuntimeState) error {
	if err := validateState(state); err != nil {
		return err
	}
	return durableWriteJSON(filepath.Join(runtimeRoot, "state", stateName), state)
}

func ObservePack(state *RuntimeState, packID, version, manifestDigest string) error {
	if state == nil {
		return fmt.Errorf("runtime state is required")
	}
	if !packIDRE.MatchString(packID) || !digestRE.MatchString(manifestDigest) {
		return fmt.Errorf("invalid pack rollback identity")
	}
	if _, err := parseSemver(version); err != nil {
		return err
	}
	if state.HighestSeenPacks == nil {
		state.HighestSeenPacks = map[string]HighestSeen{}
	}
	previous, exists := state.HighestSeenPacks[packID]
	if exists {
		order, err := compareSemver(version, previous.Version)
		if err != nil {
			return err
		}
		if order < 0 {
			return fmt.Errorf("pack rollback rejected")
		}
		if order == 0 && manifestDigest != previous.ManifestDigest {
			return fmt.Errorf("same pack version was previously trusted with different manifest bytes")
		}
		if order == 0 {
			return nil
		}
	}
	state.HighestSeenPacks[packID] = HighestSeen{Version: version, ManifestDigest: manifestDigest}
	return nil
}

func GenerationID(manifestBytes []byte) string {
	sum := sha256.Sum256(manifestBytes)
	return hex.EncodeToString(sum[:])
}

func formatTrustedTime(value time.Time) string {
	return value.UTC().Format("2006-01-02T15:04:05.000000Z")
}

func parseTrustedTime(value string) (time.Time, error) {
	parsed, err := time.Parse("2006-01-02T15:04:05.000000Z", value)
	if err != nil || formatTrustedTime(parsed) != value {
		return time.Time{}, fmt.Errorf("trusted-time state is not canonical UTC")
	}
	return parsed, nil
}

func durableTrustStateExists(runtimeRoot string) bool {
	if info, err := os.Lstat(filepath.Join(runtimeRoot, "state", stateName)); err == nil && info.Mode().IsRegular() {
		return true
	}
	for _, dir := range []string{filepath.Join(runtimeRoot, "tuf", "metadata"), filepath.Join(runtimeRoot, "generations")} {
		found := false
		_ = filepath.WalkDir(dir, func(_ string, entry os.DirEntry, err error) error {
			if err == nil && entry != nil && !entry.IsDir() {
				found = true
			}
			return nil
		})
		if found {
			return true
		}
	}
	return false
}

func GuardTrustedTime(runtimeRoot string, observed time.Time) error {
	if observed.IsZero() {
		return fmt.Errorf("trusted wall-clock observation is required")
	}
	if err := PrepareRuntimeRoot(runtimeRoot); err != nil {
		return err
	}
	observed = observed.UTC()
	path := filepath.Join(runtimeRoot, "state", trustedTimeName)
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("trusted-time state path is not a normal file")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var state TrustedTimeState
		if err := decodeStrictJSON(data, &state); err != nil || state.TrustedTimeVersion != TrustedTimeVersion {
			return fmt.Errorf("trusted-time state is corrupt/unreadable")
		}
		highest, err := parseTrustedTime(state.HighestObservedUTC)
		if err != nil {
			return err
		}
		if observed.Before(highest) {
			return fmt.Errorf("local clock rollback detected; administrative trusted-time recovery is required")
		}
		if observed.Equal(highest) {
			return nil
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if durableTrustStateExists(runtimeRoot) {
			return fmt.Errorf("trusted-time state is missing while durable trust state exists; administrative recovery is required")
		}
	} else {
		return err
	}
	return durableWriteJSON(path, TrustedTimeState{TrustedTimeVersion: TrustedTimeVersion, HighestObservedUTC: formatTrustedTime(observed)})
}
