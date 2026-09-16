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

	canonicalIDs := model.Canonical.IDs()
	if len(canonicalIDs) == 0 {
		t.Fatal("active generation canonical store is empty")
	}
	if _, ok := model.Canonical.Get(canonicalIDs[0]); !ok {
		t.Fatalf("active canonical record is not retrievable: %s", canonicalIDs[0])
	}

	searchDocument := model.Bundle.Documents[0]
	if searchDocument.TargetID == "" || searchDocument.Title == "" {
		t.Fatalf("active SPC contains an incomplete search document: %#v", searchDocument)
	}
	result, err := model.Search.Resolve(searchDocument.Title, 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, match := range result.Matches {
		if match.TargetID == searchDocument.TargetID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("active immutable search index did not resolve SPC target %s from title %q", searchDocument.TargetID, searchDocument.Title)
	}

	graphRuntime, err := graph.New(&model.Bundle)
	if err != nil {
		t.Fatalf("active SPC could not construct graph runtime: %v", err)
	}
	if graphRuntime == nil {
		t.Fatal("active SPC graph runtime is nil")
	}
	if _, err := graphRuntime.Expand(
		[]string{searchDocument.TargetID},
		1,
		nil,
		"both",
		10,
	); err != nil {
		t.Fatalf("active graph runtime rejected a valid SPC seed: %v", err)
	}
}
