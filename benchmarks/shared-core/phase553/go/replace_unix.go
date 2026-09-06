//go:build !windows

package main

import (
	"os"
	"path/filepath"
)

// atomicReplaceDurable replaces an existing state file atomically, then fsyncs
// the containing directory so the rename itself is durably ordered on Unix-like
// filesystems. A false durability result is a hard-gate failure in the state probe.
func atomicReplaceDurable(temp, target string) (bool, error) {
	if err := os.Rename(temp, target); err != nil {
		return false, err
	}
	dir, err := os.Open(filepath.Dir(target))
	if err != nil {
		return false, err
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return false, err
	}
	return true, nil
}

func atomicReplacePrimitive() string {
	return "rename(2)+directory-fsync"
}
