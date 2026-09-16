package pack

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/cyber-sentinel/Cyber-Sentinel-Atlas/shared-core/go/internal/canonical"
	"github.com/cyber-sentinel/Cyber-Sentinel-Atlas/shared-core/go/internal/search"
)

var ErrNoActiveGeneration = errors.New("no active Atlas pack generation")

// ActiveReadModel is the validated, immutable read model for the generation
// selected by durable Atlas runtime state. The caller owns Search and must
// close the model when the child process terminates.
type ActiveReadModel struct {
	GenerationID   string
	PackID         string
	PackVersion    string
	ManifestDigest string
	Canonical      *canonical.Store
	Bundle         search.Bundle
	Search         *search.Core
}

func (m *ActiveReadModel) Close() error {
	if m == nil || m.Search == nil {
		return nil
	}
	err := m.Search.Close()
	m.Search = nil
	return err
}

// DefaultRuntimeRoot returns the core-owned durable runtime root. Windows uses
// LOCALAPPDATA so trust state and installed generations remain local to the
// current user and are not treated as disposable cache data.
func DefaultRuntimeRoot() (string, error) {
	var base string
	if runtime.GOOS == "windows" {
		base = strings.TrimSpace(os.Getenv("LOCALAPPDATA"))
		if base == "" {
			return "", errors.New("LOCALAPPDATA is required to resolve the Atlas runtime root")
		}
	} else {
		var err error
		base, err = os.UserConfigDir()
		if err != nil {
			return "", fmt.Errorf("resolve user config directory: %w", err)
		}
	}
	root, err := filepath.Abs(filepath.Join(base, "Cyber-Sentinel", "ATLAS", "runtime"))
	if err != nil {
		return "", fmt.Errorf("resolve Atlas runtime root: %w", err)
	}
	return filepath.Clean(root), nil
}

func validateRuntimeRootForRead(runtimeRoot string) error {
	info, err := os.Lstat(runtimeRoot)
	if errors.Is(err, os.ErrNotExist) {
		return ErrNoActiveGeneration
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("Atlas runtime root is not a normal directory")
	}
	for _, name := range []string{"state", "generations"} {
		path := filepath.Join(runtimeRoot, name)
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("Atlas runtime subdirectory is unsafe: %s", name)
		}
	}
	return nil
}

// LoadActiveReadModel resolves only the generation selected by durable runtime
// state. It never scans for an alternative generation and never silently falls
// back from corrupt or unsafe active state. No active generation is reported
// with ErrNoActiveGeneration so callers may still expose handshake/status
// before the first verified pack is installed.
func LoadActiveReadModel(runtimeRoot string) (*ActiveReadModel, error) {
	if err := validateRuntimeRootForRead(runtimeRoot); err != nil {
		return nil, err
	}
	state, err := LoadRuntimeState(runtimeRoot)
	if err != nil {
		return nil, fmt.Errorf("load Atlas runtime state: %w", err)
	}
	if state.ActiveGeneration == nil {
		return nil, ErrNoActiveGeneration
	}

	generation, err := ResolveActiveGeneration(runtimeRoot)
	if err != nil {
		return nil, err
	}
	if err := healthGeneration(generation); err != nil {
		return nil, fmt.Errorf("active Atlas generation failed health validation: %w", err)
	}

	metadata, err := loadGenerationMetadata(generation)
	if err != nil {
		return nil, err
	}
	manifestBytes, err := os.ReadFile(filepath.Join(generation, "targets", "atlas", "pack-manifest.json"))
	if err != nil {
		return nil, err
	}
	inventoryBytes, err := os.ReadFile(filepath.Join(generation, "targets", "atlas", "source-license-inventory.json"))
	if err != nil {
		return nil, err
	}
	manifest, _, err := validateContractPair(manifestBytes, inventoryBytes, true)
	if err != nil {
		return nil, err
	}
	if sha256Prefixed(manifestBytes) != metadata.ManifestDigest || manifest.PackID != metadata.PackID || manifest.PackVersion != metadata.PackVersion {
		return nil, errors.New("active Atlas generation manifest identity mismatch")
	}

	var canonicalData, spcData []byte
	for _, artifact := range manifest.Artifacts {
		parts, err := safeRelative(artifact.Path)
		if err != nil {
			return nil, err
		}
		path := filepath.Join(append([]string{generation, "targets"}, parts...)...)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("active Atlas generation artifact missing/unsafe")
		}
		data, err := os.ReadFile(path)
		if err != nil || int64(len(data)) != artifact.Length || sha256Prefixed(data) != artifact.Digest {
			return nil, errors.New("active Atlas generation artifact binding failed")
		}
		switch artifact.Kind {
		case "canonical-records":
			canonicalData = data
		case "spc":
			spcData = data
		}
	}
	if len(canonicalData) == 0 || len(spcData) == 0 {
		return nil, errors.New("active Atlas generation lacks required read-model artifacts")
	}

	store, err := canonical.DecodeJSONL(bytes.NewReader(canonicalData))
	if err != nil {
		return nil, err
	}
	bundle, err := validateSPC(spcData)
	if err != nil {
		return nil, err
	}
	searchPath := filepath.Join(generation, filepath.FromSlash(metadata.RuntimeSearchIndex))
	searchCore, err := search.Open(searchPath, &bundle)
	if err != nil {
		return nil, err
	}

	return &ActiveReadModel{
		GenerationID:   metadata.GenerationID,
		PackID:         metadata.PackID,
		PackVersion:    metadata.PackVersion,
		ManifestDigest: metadata.ManifestDigest,
		Canonical:      store,
		Bundle:         bundle,
		Search:         searchCore,
	}, nil
}
