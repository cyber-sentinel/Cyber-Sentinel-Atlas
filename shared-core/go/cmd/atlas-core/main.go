package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

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
// archive/root path and never runs when an active generation already exists.
// Both files are required together; partial/tampered bundles fail closed through
// the existing TUF + pack verification and activation path.
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
	runtimeRoot, err := pack.DefaultRuntimeRoot()
	if err != nil {
		return nil, err
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve atlas-core executable: %w", err)
	}
	return openRuntimeWithBundle(runtimeRoot, filepath.Dir(executable))
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
