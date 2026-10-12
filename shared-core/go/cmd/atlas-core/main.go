package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cyber-sentinel/Cyber-Sentinel-Atlas/shared-core/go/internal/app"
	"github.com/cyber-sentinel/Cyber-Sentinel-Atlas/shared-core/go/internal/pack"
	"github.com/cyber-sentinel/Cyber-Sentinel-Atlas/shared-core/go/internal/protocol"
)

const (
	bundledPreviewPackName = "atlas-engineering-preview.atlaspack"
	bundledPreviewRootName = "atlas-engineering-preview-root.json"
)

var (
	coreVersion = "0.1.0-dev"
	coreCommit  = "unknown"
)

func validCommitNamespace(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, ch := range value {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
			return false
		}
	}
	return true
}

func isolatedEngineeringBuild(version string) bool {
	value := strings.ToLower(version)
	return strings.Contains(value, "preview") ||
		(strings.Contains(value, "mvp2") && strings.Contains(value, "private"))
}

func bundledEngineeringPreviewPresent(bundleRoot string) (bool, error) {
	archivePath := filepath.Join(bundleRoot, bundledPreviewPackName)
	rootPath := filepath.Join(bundleRoot, bundledPreviewRootName)
	var archiveErr error
	var rootErr error
	if _, err := os.Lstat(archivePath); err != nil {
		archiveErr = err
	}
	if _, err := os.Lstat(rootPath); err != nil {
		rootErr = err
	}
	archiveMissing := errors.Is(archiveErr, os.ErrNotExist)
	rootMissing := errors.Is(rootErr, os.ErrNotExist)
	if archiveErr != nil && !archiveMissing {
		return false, fmt.Errorf("inspect bundled engineering preview pack: %w", archiveErr)
	}
	if rootErr != nil && !rootMissing {
		return false, fmt.Errorf("inspect bundled engineering preview trust root: %w", rootErr)
	}
	return !(archiveMissing && rootMissing), nil
}

// resolveRuntimeRoot keeps release/runtime state stable while isolating
// engineering preview/private-alpha builds by their exact source commit.
// Engineering-preview TUF roots are created ephemerally per build, so sharing
// one durable engineering root across different commits would allow an older
// active generation to shadow the newly bundled pack and would also create
// invalid trust continuity between unrelated preview roots. Production and
// ordinary development builds retain the canonical stable runtime root.
func resolveRuntimeRoot(bundleRoot string) (string, error) {
	base, err := pack.DefaultRuntimeRoot()
	if err != nil {
		return "", err
	}
	bundledPreview, err := bundledEngineeringPreviewPresent(bundleRoot)
	if err != nil {
		return "", err
	}
	if !isolatedEngineeringBuild(coreVersion) && !bundledPreview {
		return base, nil
	}
	if !validCommitNamespace(coreCommit) {
		return "", errors.New("isolated engineering build requires an exact 40-character hexadecimal source commit")
	}
	return filepath.Join(base, "preview-builds", strings.ToLower(coreCommit)), nil
}

func openRuntimeAt(runtimeRoot string) (*app.Runtime, error) {
	runtime, err := app.NewFromRuntimeRoot(runtimeRoot)
	if errors.Is(err, pack.ErrNoActiveGeneration) {
		return app.NewUnconfiguredAt(runtimeRoot), nil
	}
	if err != nil {
		return nil, err
	}
	return runtime, nil
}

// installBundledEngineeringPreview performs an initial, local-only bootstrap from
// fixed filenames adjacent to atlas-core. It never accepts a caller-controlled
// archive/root path. Engineering builds use a source-commit-namespaced runtime
// root, so an active generation here belongs to this exact build rather than a
// previous package. Both files are required together; partial/tampered bundles
// fail closed through the existing TUF + pack verification and activation path.
func installBundledEngineeringPreview(runtimeRoot, bundleRoot string) (bool, error) {
	archivePath := filepath.Join(bundleRoot, bundledPreviewPackName)
	rootPath := filepath.Join(bundleRoot, bundledPreviewRootName)

	archiveInfo, archiveErr := os.Lstat(archivePath)
	rootInfo, rootErr := os.Lstat(rootPath)
	archiveMissing := errors.Is(archiveErr, os.ErrNotExist)
	rootMissing := errors.Is(rootErr, os.ErrNotExist)
	if archiveMissing && rootMissing {
		return false, nil
	}
	if archiveErr != nil && !archiveMissing {
		return false, fmt.Errorf("inspect bundled engineering preview pack: %w", archiveErr)
	}
	if rootErr != nil && !rootMissing {
		return false, fmt.Errorf("inspect bundled engineering preview trust root: %w", rootErr)
	}
	if archiveMissing || rootMissing {
		return false, errors.New("bundled engineering preview is incomplete")
	}
	if !archiveInfo.Mode().IsRegular() || archiveInfo.Mode()&os.ModeSymlink != 0 {
		return false, errors.New("bundled engineering preview pack is not a normal file")
	}
	if !rootInfo.Mode().IsRegular() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return false, errors.New("bundled engineering preview trust root is not a normal file")
	}
	bootstrapRoot, err := os.ReadFile(rootPath)
	if err != nil {
		return false, fmt.Errorf("read bundled engineering preview trust root: %w", err)
	}
	if len(bootstrapRoot) == 0 {
		return false, errors.New("bundled engineering preview trust root is empty")
	}
	if _, err := pack.InstallAtlaspack(
		archivePath,
		bootstrapRoot,
		runtimeRoot,
		pack.CurrentRuntimeVersion,
		pack.DefaultSafetyLimits(),
		nil,
		nil,
	); err != nil {
		return false, fmt.Errorf("activate bundled engineering preview: %w", err)
	}
	return true, nil
}

func openRuntimeWithBundle(runtimeRoot, bundleRoot string) (*app.Runtime, error) {
	runtime, err := app.NewFromRuntimeRoot(runtimeRoot)
	if err == nil {
		return runtime, nil
	}
	if !errors.Is(err, pack.ErrNoActiveGeneration) {
		return nil, err
	}
	installed, installErr := installBundledEngineeringPreview(runtimeRoot, bundleRoot)
	if installErr != nil {
		return nil, installErr
	}
	if !installed {
		return app.NewUnconfiguredAt(runtimeRoot), nil
	}
	return app.NewFromRuntimeRoot(runtimeRoot)
}

func openRuntime() (*app.Runtime, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve atlas-core executable: %w", err)
	}
	bundleRoot := filepath.Dir(executable)
	runtimeRoot, err := resolveRuntimeRoot(bundleRoot)
	if err != nil {
		return nil, err
	}
	return openRuntimeWithBundle(runtimeRoot, bundleRoot)
}

func main() {
	if len(os.Args) != 2 || os.Args[1] != "--serve-stdio" {
		fmt.Fprintln(os.Stderr, "usage: atlas-core --serve-stdio")
		os.Exit(2)
	}

	runtime, err := openRuntime()
	if err != nil {
		fmt.Fprintf(os.Stderr, "atlas-core startup failed: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if err := runtime.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "atlas-core shutdown failed: %v\n", err)
		}
	}()

	server := protocol.Server{
		Build:      protocol.BuildInfo{Version: coreVersion, Commit: coreCommit},
		Operations: runtime,
	}
	if err := server.Serve(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "atlas-core protocol session terminated: %v\n", err)
		os.Exit(1)
	}
}
