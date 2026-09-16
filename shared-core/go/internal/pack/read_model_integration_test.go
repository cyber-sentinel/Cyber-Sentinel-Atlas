//go:build phase554c_integration

package pack

import (
	"path/filepath"
	"testing"

	"github.com/cyber-sentinel/Cyber-Sentinel-Atlas/shared-core/go/internal/graph"
)

func TestLoadActiveReadModelFromInstalledGeneration(t *testing.T) {
	fixtures := buildSignedFixtures(t)
	verified := verifyArchive(
		t,
		fixtures.V1Pack,
		fixtures.V1Root,
		filepath.Join(t.TempDir(), "verified-work"),
		filepath.Join(t.TempDir(), "tuf-cache"),
	)

	runtimeRoot := filepath.Join(t.TempDir(), "runtime")
	t.Cleanup(func() { restoreTempTreePermissions(runtimeRoot) })
	generationID, err := InstallVerifiedGeneration(verified, runtimeRoot, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	model, err := LoadActiveReadModel(runtimeRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer model.Close()

	if model.GenerationID != generationID {
		t.Fatalf("active generation mismatch: %s != %s", model.GenerationID, generationID)
	}
	if model.PackID != verified.PackID || model.PackVersion != verified.PackVersion || model.ManifestDigest != verified.ManifestDigest {
		t.Fatalf("active pack identity mismatch: %#v", model)
	}
	if model.Canonical == nil || model.Search == nil || len(model.Bundle.Documents) == 0 {
		t.Fatal("active generation did not produce a complete canonical/search read model")
	}

	var canonicalTargetID, canonicalTitle string
	for _, document := range model.Bundle.Documents {
		if document.Title == "" {
			continue
		}
		if _, ok := model.Canonical.Get(document.TargetID); ok {
			canonicalTargetID = document.TargetID
			canonicalTitle = document.Title
			break
		}
	}
	if canonicalTargetID == "" {
		t.Fatal("active SPC contains no search document backed by a canonical record")
	}

	result, err := model.Search.Resolve(canonicalTitle, 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, match := range result.Matches {
		if match.TargetID == canonicalTargetID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("active immutable search index did not resolve canonical target %s from title %q", canonicalTargetID, canonicalTitle)
	}

	graphRuntime, err := graph.New(&model.Bundle)
	if err != nil {
		t.Fatalf("active SPC could not construct graph runtime: %v", err)
	}
	if graphRuntime == nil {
		t.Fatal("active SPC graph runtime is nil")
	}
}
