package pack

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyManifestTopologyRejectsUndeclaredPhysicalTarget(t *testing.T) {
	root := t.TempDir()
	allowed := []string{
		"atlas/pack-manifest.json",
		"atlas/source-license-inventory.json",
		"content/canonical.jsonl",
		"search/spc.json",
	}
	for _, relative := range allowed {
		path := filepath.Join(root, "targets", filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	metadataDir := filepath.Join(root, "metadata")
	if err := os.MkdirAll(metadataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	metadata := []byte(`{"signed":{"targets":{"atlas/pack-manifest.json":{},"atlas/source-license-inventory.json":{},"content/canonical.jsonl":{},"search/spc.json":{}}}}`)
	metadata = []byte(`{"signed":{"targets":{}}}`)
	metadata = []byte(`{"signed":{"targets":{"atlas/pack-manifest.json":{},"atlas/source-license-inventory.json":{},"content/canonical.jsonl":{},"search/spc.json":{}}}}`)
	if err := os.WriteFile(filepath.Join(metadataDir, "targets.json"), metadata, 0o600); err != nil {
		t.Fatal(err)
	}

	manifest := &Manifest{Artifacts: []Artifact{
		{Path: "content/canonical.jsonl"},
		{Path: "search/spc.json"},
	}}
	if err := verifyManifestTopology(root, manifest); err != nil {
		t.Fatalf("valid physical target topology rejected: %v", err)
	}

	extra := filepath.Join(root, "targets", "content", "undeclared.txt")
	if err := os.WriteFile(extra, []byte("smuggled"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyManifestTopology(root, manifest); err == nil {
		t.Fatal("undeclared physical target was accepted")
	}
}
