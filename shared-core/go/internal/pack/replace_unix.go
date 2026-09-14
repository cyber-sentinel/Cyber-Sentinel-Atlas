//go:build !windows

package pack

import (
	"os"
	"path/filepath"
)

func atomicReplaceDurable(temp, target string) error {
	if err := os.Rename(temp, target); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(target))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
