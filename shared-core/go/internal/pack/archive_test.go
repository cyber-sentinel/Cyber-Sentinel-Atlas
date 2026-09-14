package pack

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeZip(t *testing.T, path string, entries map[string][]byte, method uint16) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	for name, data := range entries {
		header := &zip.FileHeader{Name: name, Method: method}
		header.SetMode(0o600)
		out, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := out.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func minimalArchiveEntries() map[string][]byte {
	return map[string][]byte{
		"metadata/root.json":                  []byte("{}"),
		"metadata/timestamp.json":             []byte("{}"),
		"metadata/snapshot.json":              []byte("{}"),
		"metadata/targets.json":               []byte("{}"),
		"targets/atlas/pack-manifest.json":    []byte("{}"),
	}
}

func TestSafeExtractValidAtlaspackLayout(t *testing.T) {
	packPath := filepath.Join(t.TempDir(), "valid.atlaspack")
	writeZip(t, packPath, minimalArchiveEntries(), zip.Store)
	out := filepath.Join(t.TempDir(), "out")
	report, err := SafeExtractAtlaspack(packPath, out, DefaultSafetyLimits())
	if err != nil {
		t.Fatal(err)
	}
	if report.FileCount != 5 {
		t.Fatalf("unexpected file count: %d", report.FileCount)
	}
	if _, err := os.Stat(filepath.Join(out, "targets", "atlas", "pack-manifest.json")); err != nil {
		t.Fatal(err)
	}
}

func TestUnsafeArchiveNamesFailClosed(t *testing.T) {
	unsafe := []string{
		"../targets/content/a.json",
		"targets/content/../evil.json",
		"/targets/content/a.json",
		"C:/targets/content/a.json",
		"targets/content/CON.json",
		"targets/content/name. ",
		"outside/content/a.json",
		"metadata/nested/targets.json",
		"metadata/evil.json",
		"targets/other/a.json",
		"targets/content/run.ps1",
		"targets\\content\\a.json",
	}
	for _, name := range unsafe {
		t.Run(strings.ReplaceAll(name, "/", "_"), func(t *testing.T) {
			entries := minimalArchiveEntries()
			entries[name] = []byte("x")
			packPath := filepath.Join(t.TempDir(), "unsafe.atlaspack")
			writeZip(t, packPath, entries, zip.Store)
			if _, err := SafeExtractAtlaspack(packPath, filepath.Join(t.TempDir(), "out"), DefaultSafetyLimits()); err == nil {
				t.Fatalf("unsafe archive member accepted: %q", name)
			}
		})
	}
}

func TestArchiveCaseCollisionFailsClosed(t *testing.T) {
	entries := minimalArchiveEntries()
	entries["targets/content/Records.json"] = []byte("a")
	entries["targets/content/records.json"] = []byte("b")
	packPath := filepath.Join(t.TempDir(), "collision.atlaspack")
	writeZip(t, packPath, entries, zip.Store)
	if _, err := SafeExtractAtlaspack(packPath, filepath.Join(t.TempDir(), "out"), DefaultSafetyLimits()); err == nil || !strings.Contains(err.Error(), "colliding") {
		t.Fatalf("case collision was not rejected: %v", err)
	}
}

func TestArchiveCompressionRatioAndBoundsFailClosed(t *testing.T) {
	entries := minimalArchiveEntries()
	entries["targets/content/zeros.bin"] = []byte(strings.Repeat("0", 1024*1024))
	packPath := filepath.Join(t.TempDir(), "ratio.atlaspack")
	writeZip(t, packPath, entries, zip.Deflate)
	limits := DefaultSafetyLimits()
	limits.MaxCompressionRatio = 10
	if _, err := SafeExtractAtlaspack(packPath, filepath.Join(t.TempDir(), "ratio"), limits); err == nil || !strings.Contains(err.Error(), "compression-ratio") {
		t.Fatalf("compression-ratio bomb was not rejected: %v", err)
	}

	packPath2 := filepath.Join(t.TempDir(), "bounds.atlaspack")
	writeZip(t, packPath2, minimalArchiveEntries(), zip.Store)
	limits = DefaultSafetyLimits()
	limits.MaxEntries = 2
	if _, err := SafeExtractAtlaspack(packPath2, filepath.Join(t.TempDir(), "entries"), limits); err == nil {
		t.Fatal("archive entry bound was not enforced")
	}
}

func TestNonEmptyExtractionDestinationFailsClosed(t *testing.T) {
	packPath := filepath.Join(t.TempDir(), "valid.atlaspack")
	writeZip(t, packPath, minimalArchiveEntries(), zip.Store)
	out := filepath.Join(t.TempDir(), "out")
	if err := os.MkdirAll(out, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(out, "existing.txt")
	if err := os.WriteFile(marker, []byte("do not overwrite"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := SafeExtractAtlaspack(packPath, out, DefaultSafetyLimits()); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("non-empty destination was not rejected: %v", err)
	}
	data, err := os.ReadFile(marker)
	if err != nil || string(data) != "do not overwrite" {
		t.Fatalf("pre-existing destination content changed: %q %v", data, err)
	}
}
