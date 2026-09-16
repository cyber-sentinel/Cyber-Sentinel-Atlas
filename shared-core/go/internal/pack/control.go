package pack

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	rollbackControlVersion = 1
	rollbackControlName    = "manual-rollback.json"
	pendingUpdateName      = "pending.atlaspack"
)

var (
	ErrNoPendingUpdate  = errors.New("no pending Atlas pack update")
	ErrNoRollbackTarget = errors.New("no safe manual rollback target")
	ErrPackControlTrust = errors.New("pack control trust verification failed")
)

type RollbackTarget struct {
	GenerationID   string `json:"generation_id"`
	PackID         string `json:"pack_id"`
	PackVersion    string `json:"pack_version"`
	ManifestDigest string `json:"manifest_digest"`
}

type rollbackControl struct {
	ControlVersion int             `json:"control_version"`
	Target         *RollbackTarget `json:"target"`
}

type ControlStatus struct {
	PendingUpdate     bool            `json:"pending_update"`
	RollbackAvailable bool            `json:"rollback_available"`
	RollbackTarget    *RollbackTarget `json:"rollback_target,omitempty"`
}

type UpdateResult struct {
	GenerationID      string          `json:"generation_id"`
	PackID            string          `json:"pack_id"`
	PackVersion       string          `json:"pack_version"`
	ManifestDigest    string          `json:"manifest_digest"`
	RollbackAvailable bool            `json:"rollback_available"`
	RollbackTarget    *RollbackTarget `json:"rollback_target,omitempty"`
}

type RollbackResult struct {
	GenerationID      string          `json:"generation_id"`
	PackID            string          `json:"pack_id"`
	PackVersion       string          `json:"pack_version"`
	ManifestDigest    string          `json:"manifest_digest"`
	RollbackAvailable bool            `json:"rollback_available"`
	RollbackTarget    *RollbackTarget `json:"rollback_target,omitempty"`
}

func ensureControlRuntimeRoot(runtimeRoot string) error {
	if err := PrepareRuntimeRoot(runtimeRoot); err != nil {
		return err
	}
	inbox := filepath.Join(runtimeRoot, "inbox")
	info, err := os.Lstat(inbox)
	if errors.Is(err, os.ErrNotExist) {
		return os.Mkdir(inbox, 0o700)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("runtime update inbox is unsafe")
	}
	return nil
}

// PendingUpdatePath is the single core-owned location consumed by pack.update.
// The Desktop protocol never accepts an archive path from the caller.
func PendingUpdatePath(runtimeRoot string) string {
	return filepath.Join(runtimeRoot, "inbox", pendingUpdateName)
}

func rollbackControlPath(runtimeRoot string) string {
	return filepath.Join(runtimeRoot, "state", rollbackControlName)
}

func validateRollbackTarget(target *RollbackTarget) error {
	if target == nil {
		return nil
	}
	if !hex64RE.MatchString(target.GenerationID) || !packIDRE.MatchString(target.PackID) || !digestRE.MatchString(target.ManifestDigest) {
		return errors.New("invalid manual rollback target identity")
	}
	if _, err := parseSemver(target.PackVersion); err != nil {
		return fmt.Errorf("invalid manual rollback target version: %w", err)
	}
	return nil
}

func loadRollbackControl(runtimeRoot string) (rollbackControl, error) {
	path := rollbackControlPath(runtimeRoot)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return rollbackControl{ControlVersion: rollbackControlVersion}, nil
	}
	if err != nil {
		return rollbackControl{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return rollbackControl{}, errors.New("manual rollback control path is unsafe")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return rollbackControl{}, err
	}
	var control rollbackControl
	if err := decodeStrictJSON(data, &control); err != nil {
		return rollbackControl{}, fmt.Errorf("manual rollback control is corrupt/unreadable: %w", err)
	}
	if control.ControlVersion != rollbackControlVersion {
		return rollbackControl{}, errors.New("unsupported manual rollback control version")
	}
	if err := validateRollbackTarget(control.Target); err != nil {
		return rollbackControl{}, err
	}
	return control, nil
}

func writeRollbackControl(runtimeRoot string, control rollbackControl) error {
	if control.ControlVersion != rollbackControlVersion {
		return errors.New("invalid manual rollback control version")
	}
	if err := validateRollbackTarget(control.Target); err != nil {
		return err
	}
	return durableWriteJSON(rollbackControlPath(runtimeRoot), control)
}

func captureActiveTarget(runtimeRoot string) (*RollbackTarget, error) {
	state, err := LoadRuntimeState(runtimeRoot)
	if err != nil {
		return nil, err
	}
	if state.ActiveGeneration == nil {
		return nil, nil
	}
	generation := filepath.Join(runtimeRoot, "generations", *state.ActiveGeneration)
	if err := healthGeneration(generation); err != nil {
		return nil, fmt.Errorf("active generation is not healthy enough for rollback capture: %w", err)
	}
	metadata, err := loadGenerationMetadata(generation)
	if err != nil {
		return nil, err
	}
	return &RollbackTarget{
		GenerationID:   metadata.GenerationID,
		PackID:         metadata.PackID,
		PackVersion:    metadata.PackVersion,
		ManifestDigest: metadata.ManifestDigest,
	}, nil
}

func validateInstalledRollbackTarget(runtimeRoot string, target *RollbackTarget) error {
	if err := validateRollbackTarget(target); err != nil {
		return err
	}
	if target == nil {
		return ErrNoRollbackTarget
	}
	generation := filepath.Join(runtimeRoot, "generations", target.GenerationID)
	if err := healthGeneration(generation); err != nil {
		return fmt.Errorf("manual rollback target failed health validation: %w", err)
	}
	metadata, err := loadGenerationMetadata(generation)
	if err != nil {
		return err
	}
	if metadata.GenerationID != target.GenerationID || metadata.PackID != target.PackID || metadata.PackVersion != target.PackVersion || metadata.ManifestDigest != target.ManifestDigest {
		return errors.New("manual rollback target identity mismatch")
	}
	return nil
}

func pendingUpdateAvailable(runtimeRoot string) (bool, error) {
	path := PendingUpdatePath(runtimeRoot)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false, errors.New("pending Atlas pack path is unsafe")
	}
	return true, nil
}

func ControlState(runtimeRoot string) (ControlStatus, error) {
	if err := ensureControlRuntimeRoot(runtimeRoot); err != nil {
		return ControlStatus{}, err
	}
	pending, err := pendingUpdateAvailable(runtimeRoot)
	if err != nil {
		return ControlStatus{}, err
	}
	control, err := loadRollbackControl(runtimeRoot)
	if err != nil {
		return ControlStatus{}, err
	}
	status := ControlStatus{PendingUpdate: pending}
	if control.Target == nil {
		return status, nil
	}
	state, err := LoadRuntimeState(runtimeRoot)
	if err != nil {
		return ControlStatus{}, err
	}
	if state.ActiveGeneration != nil && *state.ActiveGeneration == control.Target.GenerationID {
		return status, nil
	}
	if err := validateInstalledRollbackTarget(runtimeRoot, control.Target); err != nil {
		return ControlStatus{}, err
	}
	status.RollbackAvailable = true
	status.RollbackTarget = control.Target
	return status, nil
}

func installVerifiedUpdateLocked(verified *VerifiedPack, runtimeRoot string) (string, error) {
	if verified == nil || verified.Manifest == nil {
		return "", errors.New("verified pack is required")
	}
	oldControl, err := loadRollbackControl(runtimeRoot)
	if err != nil {
		return "", err
	}
	previous, err := captureActiveTarget(runtimeRoot)
	if err != nil {
		return "", err
	}
	newGenerationID := GenerationID(verified.ManifestBytes)
	controlChanged := false
	if previous == nil {
		if oldControl.Target != nil {
			if err := writeRollbackControl(runtimeRoot, rollbackControl{ControlVersion: rollbackControlVersion}); err != nil {
				return "", err
			}
			controlChanged = true
		}
	} else if previous.GenerationID != newGenerationID {
		if err := writeRollbackControl(runtimeRoot, rollbackControl{ControlVersion: rollbackControlVersion, Target: previous}); err != nil {
			return "", err
		}
		controlChanged = true
	}

	generationID, err := installVerifiedGenerationLocked(verified, runtimeRoot, nil, nil)
	if err != nil {
		if controlChanged {
			if restoreErr := writeRollbackControl(runtimeRoot, oldControl); restoreErr != nil {
				return "", fmt.Errorf("verified update failed and rollback-control restore failed: %v; restore: %w", err, restoreErr)
			}
		}
		return "", err
	}
	return generationID, nil
}

// InstallVerifiedUpdate is the already-verified update primitive. Archive/TUF
// verification is performed by ApplyPendingUpdate before this primitive is used
// in production. It exists separately so activation/rollback semantics remain
// independently testable.
func InstallVerifiedUpdate(verified *VerifiedPack, runtimeRoot string) (string, error) {
	if err := ensureControlRuntimeRoot(runtimeRoot); err != nil {
		return "", err
	}
	lock, err := AcquireRuntimeLock(runtimeRoot, time.Now().UTC())
	if err != nil {
		return "", err
	}
	defer lock.Close()
	return installVerifiedUpdateLocked(verified, runtimeRoot)
}

func durableTrustedRoot(runtimeRoot string) ([]byte, error) {
	path := filepath.Join(runtimeRoot, "tuf", "metadata", "root.json")
	data, err := safeRegularFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: durable TUF root is unavailable: %v", ErrPackControlTrust, err)
	}
	return data, nil
}

// ApplyPendingUpdate verifies and installs only the core-owned pending archive.
// The caller cannot supply a path, trust root, runtime version or safety profile.
func ApplyPendingUpdate(runtimeRoot string) (UpdateResult, error) {
	if err := ensureControlRuntimeRoot(runtimeRoot); err != nil {
		return UpdateResult{}, err
	}
	lock, err := AcquireRuntimeLock(runtimeRoot, time.Now().UTC())
	if err != nil {
		return UpdateResult{}, err
	}
	defer lock.Close()
	available, err := pendingUpdateAvailable(runtimeRoot)
	if err != nil {
		return UpdateResult{}, err
	}
	if !available {
		return UpdateResult{}, ErrNoPendingUpdate
	}
	pendingPath := PendingUpdatePath(runtimeRoot)
	pendingInfo, err := os.Lstat(pendingPath)
	if err != nil {
		return UpdateResult{}, err
	}
	if err := GuardTrustedTime(runtimeRoot, time.Now().UTC()); err != nil {
		return UpdateResult{}, err
	}
	trustedRoot, err := durableTrustedRoot(runtimeRoot)
	if err != nil {
		return UpdateResult{}, err
	}

	work, err := os.MkdirTemp(filepath.Join(runtimeRoot, "staging"), "desktop-update-*")
	if err != nil {
		return UpdateResult{}, err
	}
	defer os.RemoveAll(work)
	extracted := filepath.Join(work, "extracted")
	verifiedTargets := filepath.Join(work, "verified-targets")
	if _, err := SafeExtractAtlaspack(pendingPath, extracted, DefaultSafetyLimits()); err != nil {
		return UpdateResult{}, fmt.Errorf("%w: pending archive rejected: %v", ErrPackControlTrust, err)
	}
	verified, err := VerifyPackDirectory(extracted, trustedRoot, filepath.Join(runtimeRoot, "tuf"), verifiedTargets, CurrentRuntimeVersion)
	if err != nil {
		return UpdateResult{}, fmt.Errorf("%w: pending archive verification failed: %v", ErrPackControlTrust, err)
	}
	generationID, err := installVerifiedUpdateLocked(verified, runtimeRoot)
	if err != nil {
		return UpdateResult{}, err
	}

	// Consume only the exact pending file that was verified. If an external
	// producer replaced the fixed inbox path while verification was running,
	// leave the replacement untouched for the next explicit update request.
	if currentInfo, statErr := os.Lstat(pendingPath); statErr == nil &&
		os.SameFile(pendingInfo, currentInfo) &&
		pendingInfo.Size() == currentInfo.Size() &&
		pendingInfo.ModTime().Equal(currentInfo.ModTime()) {
		consumedPath := filepath.Join(work, "consumed.atlaspack")
		_ = os.Rename(pendingPath, consumedPath)
	}

	status, err := ControlState(runtimeRoot)
	if err != nil {
		return UpdateResult{}, err
	}
	return UpdateResult{
		GenerationID:      generationID,
		PackID:            verified.PackID,
		PackVersion:       verified.PackVersion,
		ManifestDigest:    verified.ManifestDigest,
		RollbackAvailable: status.RollbackAvailable,
		RollbackTarget:    status.RollbackTarget,
	}, nil
}

// RollbackPrevious switches only to the core-recorded previous active generation.
// It never accepts a caller-supplied generation identifier and never rewinds
// HighestSeenPacks or durable TUF metadata.
func RollbackPrevious(runtimeRoot string) (RollbackResult, error) {
	if err := ensureControlRuntimeRoot(runtimeRoot); err != nil {
		return RollbackResult{}, err
	}
	lock, err := AcquireRuntimeLock(runtimeRoot, time.Now().UTC())
	if err != nil {
		return RollbackResult{}, err
	}
	defer lock.Close()
	if err := GuardTrustedTime(runtimeRoot, time.Now().UTC()); err != nil {
		return RollbackResult{}, err
	}

	control, err := loadRollbackControl(runtimeRoot)
	if err != nil {
		return RollbackResult{}, err
	}
	if control.Target == nil {
		return RollbackResult{}, ErrNoRollbackTarget
	}
	if err := validateInstalledRollbackTarget(runtimeRoot, control.Target); err != nil {
		return RollbackResult{}, err
	}
	current, err := captureActiveTarget(runtimeRoot)
	if err != nil {
		return RollbackResult{}, err
	}
	if current == nil || current.GenerationID == control.Target.GenerationID {
		return RollbackResult{}, ErrNoRollbackTarget
	}
	oldState, err := LoadRuntimeState(runtimeRoot)
	if err != nil {
		return RollbackResult{}, err
	}
	oldControl := control
	nextControl := rollbackControl{ControlVersion: rollbackControlVersion, Target: current}
	if err := writeRollbackControl(runtimeRoot, nextControl); err != nil {
		return RollbackResult{}, err
	}

	targetID := control.Target.GenerationID
	state := oldState
	state.ActiveGeneration = &targetID
	state.LKGGeneration = &targetID
	if err := WriteRuntimeState(runtimeRoot, state); err != nil {
		_ = writeRollbackControl(runtimeRoot, oldControl)
		return RollbackResult{}, err
	}
	active, healthErr := ResolveActiveGeneration(runtimeRoot)
	if healthErr == nil {
		healthErr = healthGeneration(active)
	}
	if healthErr != nil {
		_ = WriteRuntimeState(runtimeRoot, oldState)
		_ = writeRollbackControl(runtimeRoot, oldControl)
		return RollbackResult{}, fmt.Errorf("manual rollback target failed after activation; previous state restored: %w", healthErr)
	}
	if err := recordRollback(runtimeRoot, map[string]any{
		"mode":                "manual",
		"from_generation":     current.GenerationID,
		"restored_generation": targetID,
		"pack_id":             control.Target.PackID,
		"pack_version":        control.Target.PackVersion,
		"reason":              "explicit core-controlled manual rollback",
	}); err != nil {
		_ = WriteRuntimeState(runtimeRoot, oldState)
		_ = writeRollbackControl(runtimeRoot, oldControl)
		return RollbackResult{}, fmt.Errorf("manual rollback evidence write failed; previous state restored: %w", err)
	}

	status, err := ControlState(runtimeRoot)
	if err != nil {
		return RollbackResult{}, err
	}
	return RollbackResult{
		GenerationID:      control.Target.GenerationID,
		PackID:            control.Target.PackID,
		PackVersion:       control.Target.PackVersion,
		ManifestDigest:    control.Target.ManifestDigest,
		RollbackAvailable: status.RollbackAvailable,
		RollbackTarget:    status.RollbackTarget,
	}, nil
}
