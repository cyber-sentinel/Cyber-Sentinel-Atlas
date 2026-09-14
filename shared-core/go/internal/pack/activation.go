package pack

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/cyber-sentinel/Cyber-Sentinel-Atlas/shared-core/go/internal/canonical"
	"github.com/cyber-sentinel/Cyber-Sentinel-Atlas/shared-core/go/internal/search"
)

type HealthCheck func(generation string) error

type GenerationMetadata struct {
	GenerationMetadataVersion int    `json:"generation_metadata_version"`
	GenerationID              string `json:"generation_id"`
	PackID                    string `json:"pack_id"`
	PackVersion               string `json:"pack_version"`
	ManifestDigest            string `json:"manifest_digest"`
	RuntimeSearchIndex        string `json:"runtime_search_index"`
	SearchIndexRebuilt        bool   `json:"search_index_rebuilt"`
}

func validateGenerationMetadata(value GenerationMetadata) error {
	if value.GenerationMetadataVersion != GenerationVersion || !hex64RE.MatchString(value.GenerationID) {
		return fmt.Errorf("invalid generation metadata identity")
	}
	if !packIDRE.MatchString(value.PackID) || !digestRE.MatchString(value.ManifestDigest) {
		return fmt.Errorf("invalid generation pack identity")
	}
	if _, err := parseSemver(value.PackVersion); err != nil {
		return err
	}
	if value.RuntimeSearchIndex != "derived/search/atlas-search.sqlite3" {
		return fmt.Errorf("unexpected generation search-index location")
	}
	return nil
}

func loadGenerationMetadata(generation string) (GenerationMetadata, error) {
	path := filepath.Join(generation, "generation.json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return GenerationMetadata{}, fmt.Errorf("generation metadata path is missing/unsafe")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return GenerationMetadata{}, err
	}
	var metadata GenerationMetadata
	if err := decodeStrictJSON(data, &metadata); err != nil {
		return GenerationMetadata{}, err
	}
	if err := validateGenerationMetadata(metadata); err != nil {
		return GenerationMetadata{}, err
	}
	return metadata, nil
}

func copyFileExact(source, destination string) error {
	info, err := os.Lstat(source)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("verified source target is missing/unsafe")
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := output.ReadFrom(input); err != nil {
		_ = output.Close()
		return err
	}
	if err := output.Sync(); err != nil {
		_ = output.Close()
		return err
	}
	return output.Close()
}

func makeTreeReadOnly(root string) {
	paths := make([]string, 0)
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err == nil && path != root {
			paths = append(paths, path)
		}
		return nil
	})
	sort.Slice(paths, func(i, j int) bool { return len(paths[i]) > len(paths[j]) })
	for _, path := range paths {
		if info, err := os.Lstat(path); err == nil {
			if info.IsDir() {
				_ = os.Chmod(path, 0o555)
			} else if info.Mode().IsRegular() {
				_ = os.Chmod(path, 0o444)
			}
		}
	}
	_ = os.Chmod(root, 0o555)
}

func stageGeneration(verified *VerifiedPack, runtimeRoot string) (string, error) {
	if verified == nil || verified.Manifest == nil {
		return "", fmt.Errorf("verified pack is required")
	}
	generations := filepath.Join(runtimeRoot, "generations")
	if err := os.MkdirAll(generations, 0o700); err != nil {
		return "", err
	}
	generationID := GenerationID(verified.ManifestBytes)
	final := filepath.Join(generations, generationID)
	if info, err := os.Lstat(final); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("existing generation path is unsafe")
		}
		metadata, err := loadGenerationMetadata(final)
		if err != nil || metadata.GenerationID != generationID || metadata.ManifestDigest != verified.ManifestDigest {
			return "", fmt.Errorf("existing generation identity conflicts with verified manifest")
		}
		return final, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	staging, err := os.MkdirTemp(generations, "."+generationID+".*.staging")
	if err != nil {
		return "", err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(staging)
		}
	}()

	required := []string{"atlas/pack-manifest.json", "atlas/source-license-inventory.json"}
	for _, artifact := range verified.Manifest.Artifacts {
		required = append(required, artifact.Path)
	}
	sort.Strings(required)
	for _, relative := range required {
		parts, err := safeRelative(relative)
		if err != nil {
			return "", err
		}
		source := filepath.Join(append([]string{verified.VerifiedTargetsDir}, parts...)...)
		destination := filepath.Join(append([]string{staging, "targets"}, parts...)...)
		if err := copyFileExact(source, destination); err != nil {
			return "", err
		}
	}

	derived := filepath.Join(staging, "derived", "search", "atlas-search.sqlite3")
	if err := copyFileExact(verified.RuntimeSearchIndex, derived); err != nil {
		return "", err
	}
	metadata := GenerationMetadata{
		GenerationMetadataVersion: GenerationVersion,
		GenerationID:              generationID,
		PackID:                    verified.PackID,
		PackVersion:               verified.PackVersion,
		ManifestDigest:            verified.ManifestDigest,
		RuntimeSearchIndex:        "derived/search/atlas-search.sqlite3",
		SearchIndexRebuilt:        verified.UsedRebuiltSearchIndex,
	}
	if err := validateGenerationMetadata(metadata); err != nil {
		return "", err
	}
	if err := durableWriteJSON(filepath.Join(staging, "generation.json"), metadata); err != nil {
		return "", err
	}
	makeTreeReadOnly(staging)
	durable, err := atomicReplaceDurable(staging, final)
	if err != nil {
		return "", err
	}
	if !durable {
		return "", fmt.Errorf("generation publication did not provide durable semantics")
	}
	cleanup = false
	return final, nil
}

func healthGeneration(generation string) error {
	metadata, err := loadGenerationMetadata(generation)
	if err != nil {
		return err
	}
	if metadata.GenerationID != filepath.Base(generation) {
		return fmt.Errorf("installed generation directory/id mismatch")
	}
	manifestBytes, err := os.ReadFile(filepath.Join(generation, "targets", "atlas", "pack-manifest.json"))
	if err != nil {
		return err
	}
	inventoryBytes, err := os.ReadFile(filepath.Join(generation, "targets", "atlas", "source-license-inventory.json"))
	if err != nil {
		return err
	}
	manifest, _, err := validateContractPair(manifestBytes, inventoryBytes, true)
	if err != nil {
		return err
	}
	if sha256Prefixed(manifestBytes) != metadata.ManifestDigest || manifest.PackID != metadata.PackID || manifest.PackVersion != metadata.PackVersion {
		return fmt.Errorf("installed generation manifest identity mismatch")
	}

	var spcData, canonicalData []byte
	for _, artifact := range manifest.Artifacts {
		parts, err := safeRelative(artifact.Path)
		if err != nil {
			return err
		}
		path := filepath.Join(append([]string{generation, "targets"}, parts...)...)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("installed generation artifact missing/unsafe")
		}
		data, err := os.ReadFile(path)
		if err != nil || int64(len(data)) != artifact.Length || sha256Prefixed(data) != artifact.Digest {
			return fmt.Errorf("installed generation artifact binding failed")
		}
		if artifact.Kind == "spc" {
			spcData = data
		}
		if artifact.Kind == "canonical-records" {
			canonicalData = data
		}
	}
	if _, err := canonical.DecodeJSONL(bytes.NewReader(canonicalData)); err != nil {
		return err
	}
	bundle, err := validateSPC(spcData)
	if err != nil {
		return err
	}
	searchPath := filepath.Join(generation, filepath.FromSlash(metadata.RuntimeSearchIndex))
	core, err := search.Open(searchPath, &bundle)
	if err != nil {
		return err
	}
	return core.Close()
}

func ResolveActiveGeneration(runtimeRoot string) (string, error) {
	state, err := LoadRuntimeState(runtimeRoot)
	if err != nil {
		return "", err
	}
	if state.ActiveGeneration == nil {
		return "", fmt.Errorf("no active Atlas pack generation")
	}
	path := filepath.Join(runtimeRoot, "generations", *state.ActiveGeneration)
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("active generation pointer is missing/unsafe")
	}
	metadata, err := loadGenerationMetadata(path)
	if err != nil || metadata.GenerationID != *state.ActiveGeneration {
		return "", fmt.Errorf("active generation identity mismatch")
	}
	return path, nil
}

func recordRollback(runtimeRoot string, payload map[string]any) error {
	payload["report_version"] = 1
	payload["recorded_at"] = formatTrustedTime(time.Now().UTC())
	reports := filepath.Join(runtimeRoot, "reports", "rollback")
	if err := os.MkdirAll(reports, 0o700); err != nil {
		return err
	}
	return durableWriteJSON(filepath.Join(reports, fmt.Sprintf("%d.json", time.Now().UnixNano())), payload)
}

func installVerifiedGenerationLocked(verified *VerifiedPack, runtimeRoot string, preHealth, postHealth HealthCheck) (string, error) {
	state, err := LoadRuntimeState(runtimeRoot)
	if err != nil {
		return "", err
	}
	var previousActive, previousLKG *string
	if state.ActiveGeneration != nil {
		v := *state.ActiveGeneration
		previousActive = &v
	}
	if state.LKGGeneration != nil {
		v := *state.LKGGeneration
		previousLKG = &v
	}
	if err := ObservePack(&state, verified.PackID, verified.PackVersion, verified.ManifestDigest); err != nil {
		return "", err
	}
	generation, err := stageGeneration(verified, runtimeRoot)
	if err != nil {
		return "", err
	}
	if err := healthGeneration(generation); err != nil {
		return "", err
	}
	if preHealth != nil {
		if err := preHealth(generation); err != nil {
			return "", err
		}
	}

	// Trust advancement is durably committed before the active pointer moves.
	if err := WriteRuntimeState(runtimeRoot, state); err != nil {
		return "", err
	}
	generationID := filepath.Base(generation)
	state.ActiveGeneration = &generationID
	if err := WriteRuntimeState(runtimeRoot, state); err != nil {
		return "", err
	}

	active, healthErr := ResolveActiveGeneration(runtimeRoot)
	if healthErr == nil {
		healthErr = healthGeneration(active)
	}
	if healthErr == nil && postHealth != nil {
		healthErr = postHealth(active)
	}
	if healthErr != nil {
		rollback := state
		rollback.LKGGeneration = previousLKG
		if previousLKG != nil {
			v := *previousLKG
			rollback.ActiveGeneration = &v
		} else if previousActive != nil {
			v := *previousActive
			rollback.ActiveGeneration = &v
		} else {
			rollback.ActiveGeneration = nil
		}
		if err := WriteRuntimeState(runtimeRoot, rollback); err != nil {
			return "", fmt.Errorf("post-activation health failed and rollback state write failed: %w", err)
		}
		if err := recordRollback(runtimeRoot, map[string]any{
			"pack_id":             verified.PackID,
			"pack_version":        verified.PackVersion,
			"failed_generation":   generationID,
			"restored_generation": rollback.ActiveGeneration,
			"reason":              healthErr.Error(),
		}); err != nil {
			return "", fmt.Errorf("post-activation health failed; state restored but rollback evidence write failed: %w", err)
		}
		return "", fmt.Errorf("post-activation health failed; LKG restored: %w", healthErr)
	}

	state.LKGGeneration = &generationID
	if err := WriteRuntimeState(runtimeRoot, state); err != nil {
		return "", err
	}
	return generationID, nil
}

func InstallVerifiedGeneration(verified *VerifiedPack, runtimeRoot string, preHealth, postHealth HealthCheck) (string, error) {
	if err := PrepareRuntimeRoot(runtimeRoot); err != nil {
		return "", err
	}
	lock, err := AcquireRuntimeLock(runtimeRoot, time.Now().UTC())
	if err != nil {
		return "", err
	}
	defer lock.Close()
	return installVerifiedGenerationLocked(verified, runtimeRoot, preHealth, postHealth)
}

func InstallAtlaspack(archivePath string, bootstrapRoot []byte, runtimeRoot, currentRuntimeVersion string, limits SafetyLimits, preHealth, postHealth HealthCheck) (string, error) {
	if err := PrepareRuntimeRoot(runtimeRoot); err != nil {
		return "", err
	}
	lock, err := AcquireRuntimeLock(runtimeRoot, time.Now().UTC())
	if err != nil {
		return "", err
	}
	defer lock.Close()
	if err := GuardTrustedTime(runtimeRoot, time.Now().UTC()); err != nil {
		return "", err
	}
	work, err := os.MkdirTemp(filepath.Join(runtimeRoot, "staging"), "atlaspack-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(work)
	extracted := filepath.Join(work, "extracted")
	verifiedTargets := filepath.Join(work, "verified-targets")
	if limits.ProfileVersion == "" {
		limits = DefaultSafetyLimits()
	}
	if _, err := SafeExtractAtlaspack(archivePath, extracted, limits); err != nil {
		return "", err
	}
	verified, err := VerifyPackDirectory(extracted, bootstrapRoot, filepath.Join(runtimeRoot, "tuf"), verifiedTargets, currentRuntimeVersion)
	if err != nil {
		return "", err
	}
	return installVerifiedGenerationLocked(verified, runtimeRoot, preHealth, postHealth)
}

func MarshalRuntimeState(runtimeRoot string) ([]byte, error) {
	state, err := LoadRuntimeState(runtimeRoot)
	if err != nil {
		return nil, err
	}
	return json.Marshal(state)
}
