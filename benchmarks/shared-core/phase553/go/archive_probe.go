package main

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const (
	maxArchiveEntries      = 8192
	maxArchivePathScalars  = 512
	maxArchiveFileBytes    = uint64(2 * 1024 * 1024 * 1024)
	maxArchiveTotalBytes   = uint64(4 * 1024 * 1024 * 1024)
	maxCompressionRatio    = 200.0
)

var driveQualifiedArchive = regexp.MustCompile(`^[A-Za-z]:`)
var versionedRootArchive = regexp.MustCompile(`^[1-9][0-9]*\.root\.json$`)
var activeArchiveExtensions = map[string]bool{
	".exe": true, ".dll": true, ".sys": true, ".msi": true, ".msp": true,
	".com": true, ".scr": true, ".bat": true, ".cmd": true, ".ps1": true,
	".psm1": true, ".vbs": true, ".vbe": true, ".js": true, ".jse": true,
	".wsf": true, ".wsh": true, ".hta": true, ".lnk": true, ".reg": true,
	".sh": true, ".py": true, ".pl": true, ".rb": true, ".jar": true,
	".class": true, ".so": true, ".dylib": true, ".appx": true, ".msix": true,
	".deb": true, ".rpm": true, ".apk": true,
}
var windowsReservedArchive = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true,
	"COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true,
	"LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

func archiveComponentSafe(part string) bool {
	if part == "" || part == "." || part == ".." || strings.TrimRight(part, " .") != part {
		return false
	}
	stem := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
	return !windowsReservedArchive[stem]
}

func validateArchivePath(name string, directory bool) (string, error) {
	if name == "" || !utf8.ValidString(name) || strings.ContainsRune(name, '\x00') || strings.Contains(name, "\\") {
		return "", fmt.Errorf("unsafe ZIP member name")
	}
	if utf8.RuneCountInString(name) > maxArchivePathScalars+1 || strings.HasPrefix(name, "/") || driveQualifiedArchive.MatchString(name) {
		return "", fmt.Errorf("absolute, drive-qualified, or overlong ZIP member")
	}
	raw := name
	if directory {
		if !strings.HasSuffix(raw, "/") {
			return "", fmt.Errorf("directory entry lacks canonical slash")
		}
		raw = strings.TrimSuffix(raw, "/")
	} else if strings.HasSuffix(raw, "/") {
		return "", fmt.Errorf("file uses directory path form")
	}
	if raw == "" || utf8.RuneCountInString(raw) > maxArchivePathScalars || norm.NFC.String(raw) != raw {
		return "", fmt.Errorf("non-NFC, empty, or overlong ZIP member")
	}
	parts := strings.Split(raw, "/")
	for _, part := range parts {
		if !archiveComponentSafe(part) {
			return "", fmt.Errorf("unsafe ZIP path component")
		}
	}
	if parts[0] != "metadata" && parts[0] != "targets" {
		return "", fmt.Errorf("ZIP member outside Atlas namespaces")
	}
	if parts[0] == "metadata" && !directory {
		if len(parts) != 2 {
			return "", fmt.Errorf("nested TUF metadata is forbidden")
		}
		name := parts[1]
		allowed := name == "root.json" || name == "timestamp.json" || name == "snapshot.json" || name == "targets.json" || versionedRootArchive.MatchString(name)
		if !allowed {
			return "", fmt.Errorf("unsupported top-level TUF metadata")
		}
	}
	if parts[0] == "targets" {
		if len(parts) < 2 {
			if !directory {
				return "", fmt.Errorf("targets root cannot be a file")
			}
		} else if parts[1] != "atlas" && parts[1] != "content" && parts[1] != "search" {
			return "", fmt.Errorf("target outside Atlas target namespaces")
		}
		if !directory && activeArchiveExtensions[strings.ToLower(filepath.Ext(raw))] {
			return "", fmt.Errorf("active-code extension is forbidden")
		}
	}
	return raw, nil
}

func validateAtlasArchive(path string) (map[string]any, error) {
	reader, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	if len(reader.File) > maxArchiveEntries {
		return nil, fmt.Errorf("archive entry bound exceeded")
	}
	seen := map[string]bool{}
	var total uint64
	files := 0
	for _, entry := range reader.File {
		if entry.Flags&0x1 != 0 {
			return nil, fmt.Errorf("encrypted ZIP member is forbidden")
		}
		if entry.Method != zip.Store && entry.Method != zip.Deflate {
			return nil, fmt.Errorf("unsupported ZIP compression")
		}
		mode := entry.Mode()
		directory := mode.IsDir()
		if mode&os.ModeSymlink != 0 || (!directory && !mode.IsRegular()) {
			return nil, fmt.Errorf("non-regular ZIP entry is forbidden")
		}
		raw, err := validateArchivePath(entry.Name, directory)
		if err != nil {
			return nil, err
		}
		collision := fold(norm.NFC.String(raw))
		if seen[collision] {
			return nil, fmt.Errorf("duplicate/case-colliding ZIP path")
		}
		seen[collision] = true
		if directory {
			continue
		}
		files++
		if entry.UncompressedSize64 > maxArchiveFileBytes {
			return nil, fmt.Errorf("ZIP file size bound exceeded")
		}
		total += entry.UncompressedSize64
		if total > maxArchiveTotalBytes {
			return nil, fmt.Errorf("ZIP aggregate size bound exceeded")
		}
		if entry.UncompressedSize64 > 0 {
			ratio := float64(entry.UncompressedSize64) / float64(maxU64(entry.CompressedSize64, 1))
			if ratio > maxCompressionRatio {
				return nil, fmt.Errorf("ZIP compression ratio bound exceeded")
			}
		}
		stream, err := entry.Open()
		if err != nil {
			return nil, err
		}
		read, readErr := io.Copy(io.Discard, io.LimitReader(stream, int64(entry.UncompressedSize64)+1))
		closeErr := stream.Close()
		if readErr != nil || closeErr != nil || uint64(read) != entry.UncompressedSize64 {
			return nil, fmt.Errorf("ZIP member byte count mismatch")
		}
	}
	return map[string]any{
		"file_count": files,
		"total_uncompressed_bytes": total,
		"dynamic_code_execution": false,
		"extraction_performed": false,
		"preflight_only": true,
	}, nil
}

func maxU64(left, right uint64) uint64 {
	if left > right {
		return left
	}
	return right
}

func runArchiveProbe(workspace string, expected Expected) (map[string]any, bool, error) {
	validRelative := expected.ArchiveCases.Valid
	valid, validErr := validateAtlasArchive(filepath.Join(workspace, filepath.FromSlash(validRelative)))
	cases := map[string]bool{"valid": validErr == nil}
	for name, relative := range expected.ArchiveCases.Reject {
		_, err := validateAtlasArchive(filepath.Join(workspace, filepath.FromSlash(relative)))
		cases[name+"_rejected"] = err != nil
	}
	all := true
	for _, passed := range cases {
		all = all && passed
	}
	result := map[string]any{
		"cases": cases,
		"valid_report": valid,
		"no_dynamic_code_execution": true,
		"no_archive_member_execution": true,
		"profile": "Atlas Phase 5.5.2 v1 archive safety parity probe",
	}
	if validErr != nil {
		result["valid_error"] = validErr.Error()
	}
	return result, all, nil
}
