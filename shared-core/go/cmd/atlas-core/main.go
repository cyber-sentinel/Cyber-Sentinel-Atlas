package main

import (
	"fmt"
	"os"

	"github.com/cyber-sentinel/Cyber-Sentinel-Atlas/shared-core/go/internal/protocol"
)

var (
	coreVersion = "0.1.0-dev"
	coreCommit  = "unknown"
)

func main() {
	if len(os.Args) != 2 || os.Args[1] != "--serve-stdio" {
		fmt.Fprintln(os.Stderr, "usage: atlas-core --serve-stdio")
		os.Exit(2)
	}

	server := protocol.Server{Build: protocol.BuildInfo{Version: coreVersion, Commit: coreCommit}}
	if err := server.Serve(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "atlas-core protocol session terminated: %v\n", err)
		os.Exit(1)
	}
}
