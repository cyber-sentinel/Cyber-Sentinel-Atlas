//go:build !windows

package pack

import (
	"os"
	"path/filepath"
)

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
