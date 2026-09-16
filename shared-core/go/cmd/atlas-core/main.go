package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/cyber-sentinel/Cyber-Sentinel-Atlas/shared-core/go/internal/app"
	"github.com/cyber-sentinel/Cyber-Sentinel-Atlas/shared-core/go/internal/pack"
	"github.com/cyber-sentinel/Cyber-Sentinel-Atlas/shared-core/go/internal/protocol"
)

var (
	coreVersion = "0.1.0-dev"
	coreCommit  = "unknown"
)

func openRuntimeAt(runtimeRoot string) (*app.Runtime, error) {
	runtime, err := app.NewFromRuntimeRoot(runtimeRoot)
	if errors.Is(err, pack.ErrNoActiveGeneration) {
		return app.NewUnconfigured(), nil
	}
	if err != nil {
		return nil, err
	}
	return runtime, nil
}

func openRuntime() (*app.Runtime, error) {
	runtimeRoot, err := pack.DefaultRuntimeRoot()
	if err != nil {
		return nil, err
	}
	return openRuntimeAt(runtimeRoot)
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
