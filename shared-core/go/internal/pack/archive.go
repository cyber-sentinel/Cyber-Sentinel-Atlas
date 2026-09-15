package pack

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/text/unicode/norm"
)

const copyChunk = 1024 * 1024

var versionedRootRE = regexp.MustCompile(`^[1-9][0-9]*\.root\.json$`)

var topLevelMetadata = map[string]struct{}{
	"root.json": {}, "timestamp.json": {}, "snapshot.json": {}, "targets.json": {},
}

type SafetyLimits struct {
	ProfileVersion           string
	MaxArchiveBytes          int64
	MaxEntries               int
	MaxPathChars             int
	MaxFileUncompressedBytes uint64
	MaxTotalUncompressed     uint64
	MaxCompressionRatio      float64
}

func DefaultSafetyLimits() SafetyLimits {
	return SafetyLimits{
		ProfileVersion:           "1.0.0",
		MaxArchiveBytes:          2 * 1024 * 1024 * 1024,
		MaxEntries:               8192,
		MaxPathChars:             512,
		MaxFileUncompressedBytes: 2 * 1024 * 1024 * 1024,
		MaxTotalUncompressed:     4 * 1024 * 1024 * 1024,
		MaxCompressionRatio:      200.0,
	}
}

type ExtractionReport struct {
	ProfileVersion         string `json:"profile_version"`
	FileCount              int    `json:"file_count"`
	DirectoryCount         int    `json:"directory_count"`
	TotalUncompressedBytes uint64 `json:"total_uncompressed_bytes"`
}

type validatedEntry struct {
	file  *zip.File
	clean string
	parts []string
}

func validateArchiveMemberName(name string, isDirectory bool, limits SafetyLimits) (string, []string, error) {
	if name == "" || strings.ContainsRune(name, '\x00') || strings.Contains(name, "\\") {
		return "", nil, fmt.Errorf("unsafe archive member name: %q", name)
	}
	maxLen := limits.MaxPathChars
	if isDirectory {
		if !strings.HasSuffix(name, "/") {
			return "", nil, fmt.Errorf("directory entry lacks canonical trailing slash: %q", name)
		}
		name = strings.TrimSuffix(name, "/")
	} else if strings.HasSuffix(name, "/") {
		return "", nil, fmt.Errorf("file entry has directory-style path")
	}
	if name == "" || len(name) > maxLen || strings.HasPrefix(name, "/") || driveRE.MatchString(name) {
		return "", nil, fmt.Errorf("archive member path is empty/absolute/too long: %q", name)
	}
	if norm.NFC.String(name) != name || path.Clean(name) != name {
		return "", nil, fmt.Errorf("archive member path is not canonical NFC: %q", name)
	}
	parts := strings.Split(name, "/")
	for _, part := range parts {
		if err := validatePathComponent(part); err != nil {
			return "", nil, err
		}
	}
	if parts[0] != "metadata" && parts[0] != "targets" {
		return "", nil, fmt.Errorf("archive member outside metadata/targets namespaces: %q", name)
	}
	if parts[0] == "metadata" && !isDirectory {
		if len(parts) != 2 {
			return "", nil, fmt.Errorf("v1 metadata files must be direct children of metadata/")
		}
		if _, ok := topLevelMetadata[parts[1]]; !ok && !versionedRootRE.MatchString(parts[1]) {
			return "", nil, fmt.Errorf("unsupported v1 TUF metadata member: %q", parts[1])
		}
	}
	if parts[0] == "targets" {
		if len(parts) < 2 {
			if !isDirectory {
				return "", nil, fmt.Errorf("targets/ cannot itself be a file")
			}
		} else if parts[1] != "atlas" && parts[1] != "content" && parts[1] != "search" {
			return "", nil, fmt.Errorf("target outside Atlas namespaces: %q", name)
		} else if !isDirectory {
			if _, blocked := activeExtensions[strings.ToLower(path.Ext(name))]; blocked {
				return "", nil, fmt.Errorf("active-code extension is forbidden in content packs: %q", name)
			}
		}
	}
	return name, parts, nil
}

func validateZipEntryType(file *zip.File) error {
	if file.Flags&0x1 != 0 {
		return fmt.Errorf("encrypted ZIP member is forbidden: %q", file.Name)
	}
	if file.NonUTF8 {
		return fmt.Errorf("non-UTF8 ZIP member name is forbidden: %q", file.Name)
	}
	if file.Method != zip.Store && file.Method != zip.Deflate {
		return fmt.Errorf("unsupported ZIP compression method %d: %q", file.Method, file.Name)
	}
	// Preserve the Phase 5.5.2 cross-platform reparse-point guard.
	if file.ExternalAttrs&0x0400 != 0 {
		return fmt.Errorf("Windows reparse-point archive member is forbidden: %q", file.Name)
	}
	mode := file.Mode()
	if mode&os.ModeSymlink != 0 || mode&(os.ModeDevice|os.ModeNamedPipe|os.ModeSocket|os.ModeCharDevice) != 0 {
		return fmt.Errorf("non-regular archive member is forbidden: %q", file.Name)
	}
	return nil
}

func preflightArchive(reader *zip.ReadCloser, limits SafetyLimits) ([]validatedEntry, ExtractionReport, error) {
	if len(reader.File) > limits.MaxEntries {
		return nil, ExtractionReport{}, fmt.Errorf("archive has %d entries; limit is %d", len(reader.File), limits.MaxEntries)
	}
	report := ExtractionReport{ProfileVersion: limits.ProfileVersion}
	seen := map[string]struct{}{}
	validated := make([]validatedEntry, 0, len(reader.File))
	for _, file := range reader.File {
		if err := validateZipEntryType(file); err != nil {
			return nil, ExtractionReport{}, err
		}
		isDir := file.FileInfo().IsDir()
		clean, parts, err := validateArchiveMemberName(file.Name, isDir, limits)
		if err != nil {
			return nil, ExtractionReport{}, err
		}
		collisionKey := strings.ToLower(norm.NFC.String(clean))
		if _, exists := seen[collisionKey]; exists {
			return nil, ExtractionReport{}, fmt.Errorf("duplicate/case-colliding archive path: %q", clean)
		}
		seen[collisionKey] = struct{}{}
		if isDir {
			if file.UncompressedSize64 != 0 {
				return nil, ExtractionReport{}, fmt.Errorf("directory entry has non-zero size: %q", clean)
			}
			report.DirectoryCount++
		} else {
			report.FileCount++
			if file.UncompressedSize64 > limits.MaxFileUncompressedBytes {
				return nil, ExtractionReport{}, fmt.Errorf("archive member exceeds per-file bound: %q", clean)
			}
			if ^uint64(0)-report.TotalUncompressedBytes < file.UncompressedSize64 {
				return nil, ExtractionReport{}, fmt.Errorf("archive size accounting overflow")
			}
			report.TotalUncompressedBytes += file.UncompressedSize64
			if report.TotalUncompressedBytes > limits.MaxTotalUncompressed {
				return nil, ExtractionReport{}, fmt.Errorf("archive exceeds aggregate uncompressed-size bound")
			}
			if file.UncompressedSize64 > 0 {
				compressed := file.CompressedSize64
				if compressed == 0 {
					compressed = 1
				}
				ratio := float64(file.UncompressedSize64) / float64(compressed)
				if ratio > limits.MaxCompressionRatio {
					return nil, ExtractionReport{}, fmt.Errorf("archive member exceeds compression-ratio bound: %q", clean)
				}
			}
		}
		validated = append(validated, validatedEntry{file: file, clean: clean, parts: parts})
	}
	return validated, report, nil
}

func ensurePrivateEmptyDirectory(destination string) error {
	info, err := os.Lstat(destination)
	if err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("staging destination is not a normal directory")
		}
		entries, err := os.ReadDir(destination)
		if err != nil {
			return err
		}
		if len(entries) != 0 {
			return fmt.Errorf("staging destination must be empty")
		}
		return os.Chmod(destination, 0o700)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.MkdirAll(destination, 0o700)
}

func mkdirChainWithoutLinks(root string, parts []string) (string, error) {
	current := root
	for _, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return "", fmt.Errorf("staging path component is not a normal directory: %s", current)
			}
			continue
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		if err := os.Mkdir(current, 0o700); err != nil {
			return "", err
		}
	}
	return current, nil
}

func SafeExtractAtlaspack(archivePath, destination string, limits SafetyLimits) (ExtractionReport, error) {
	info, err := os.Stat(archivePath)
	if err != nil || !info.Mode().IsRegular() {
		return ExtractionReport{}, fmt.Errorf("atlaspack does not exist or is not regular")
	}
	if info.Size() > limits.MaxArchiveBytes {
		return ExtractionReport{}, fmt.Errorf("atlaspack exceeds configured compressed-size bound")
	}
	if err := ensurePrivateEmptyDirectory(destination); err != nil {
		return ExtractionReport{}, err
	}
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return ExtractionReport{}, fmt.Errorf("atlaspack open failed: %w", err)
	}
	defer reader.Close()
	validated, report, err := preflightArchive(reader, limits)
	if err != nil {
		return ExtractionReport{}, err
	}
	for _, entry := range validated {
		if entry.file.FileInfo().IsDir() {
			if _, err := mkdirChainWithoutLinks(destination, entry.parts); err != nil {
				return ExtractionReport{}, err
			}
			continue
		}
		parent, err := mkdirChainWithoutLinks(destination, entry.parts[:len(entry.parts)-1])
		if err != nil {
			return ExtractionReport{}, err
		}
		target := filepath.Join(parent, entry.parts[len(entry.parts)-1])
		if _, err := os.Lstat(target); err == nil {
			return ExtractionReport{}, fmt.Errorf("refusing to overwrite staging path: %s", target)
		} else if !errors.Is(err, os.ErrNotExist) {
			return ExtractionReport{}, err
		}
		source, err := entry.file.Open()
		if err != nil {
			return ExtractionReport{}, err
		}
		output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			source.Close()
			return ExtractionReport{}, err
		}
		written, copyErr := io.CopyBuffer(output, io.LimitReader(source, int64(entry.file.UncompressedSize64)+1), make([]byte, copyChunk))
		syncErr := output.Sync()
		closeOutErr := output.Close()
		closeSourceErr := source.Close()
		if copyErr != nil {
			return ExtractionReport{}, copyErr
		}
		if written != int64(entry.file.UncompressedSize64) {
			return ExtractionReport{}, fmt.Errorf("decompressed member size mismatch: %q", entry.clean)
		}
		if syncErr != nil {
			return ExtractionReport{}, syncErr
		}
		if closeOutErr != nil {
			return ExtractionReport{}, closeOutErr
		}
		if closeSourceErr != nil {
			return ExtractionReport{}, closeSourceErr
		}
	}
	return report, nil
}
