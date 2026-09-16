//go:build phase554c_integration

package pack

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/cyber-sentinel/Cyber-Sentinel-Atlas/shared-core/go/internal/protocol"
)

type gd6ProcessFixtures struct {
	OldPack       string `json:"old_pack"`
	NewPack       string `json:"new_pack"`
	Root          string `json:"root"`
	UntrustedPack string `json:"untrusted_pack"`
}

type gd6WireResponse struct {
	ID     string              `json:"id"`
	OK     bool                `json:"ok"`
	Result json.RawMessage     `json:"result,omitempty"`
	Error  *protocol.ErrorBody `json:"error,omitempty"`
}

type gd6PackStatus struct {
	Ready             bool   `json:"ready"`
	GenerationID      string `json:"generation_id"`
	PackID            string `json:"pack_id"`
	PackVersion       string `json:"pack_version"`
	ManifestDigest    string `json:"manifest_digest"`
	PendingUpdate     bool   `json:"pending_update"`
	RollbackAvailable bool   `json:"rollback_available"`
}

type gd6MutationResult struct {
	GenerationID      string `json:"generation_id"`
	PackID            string `json:"pack_id"`
	PackVersion       string `json:"pack_version"`
	ManifestDigest    string `json:"manifest_digest"`
	RollbackAvailable bool   `json:"rollback_available"`
}

func buildGD6ProcessFixtures(t *testing.T) gd6ProcessFixtures {
	t.Helper()
	python := os.Getenv("ATLAS_PHASE554C_PYTHON")
	if python == "" {
		t.Skip("ATLAS_PHASE554C_PYTHON is required for G-D6 process integration")
	}
	root := repositoryRoot(t)
	work := t.TempDir()
	out := filepath.Join(work, "gd6-fixtures.json")
	const script = `
import json, sys
from pathlib import Path
from tuf.api.metadata import Metadata, TargetFile, Targets, Snapshot, Timestamp
from tuf.api.serialization.json import JSONSerializer

root = Path(sys.argv[1])
work = Path(sys.argv[2])
out = Path(sys.argv[3])
sys.path.insert(0, str(root))

from tests.phase55.phase552_helpers import make_signed_repository, canonical_json_bytes, _metafile
from tools.pack.builder import build_verified_atlaspack
from tools.pack.tuf_runtime import sha256_prefixed

fixture = make_signed_repository(work / "runtime-update", pack_version="1.0.0-test.10")
root_file = work / "runtime-update-root.json"
root_file.write_bytes(fixture.bootstrap_root)
old_pack = work / "runtime-update-old.atlaspack"
build_verified_atlaspack(fixture.root, old_pack, bootstrap_root=fixture.bootstrap_root)

inventory_path = fixture.root / "targets" / "atlas" / "source-license-inventory.json"
manifest_path = fixture.root / "targets" / "atlas" / "pack-manifest.json"
inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
inventory["pack_version"] = "1.0.0-test.11"
inventory_bytes = canonical_json_bytes(inventory)
inventory_path.write_bytes(inventory_bytes)

manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
manifest["pack_version"] = "1.0.0-test.11"
manifest["source_license_inventory"]["digest"] = sha256_prefixed(inventory_bytes)
manifest_bytes = canonical_json_bytes(manifest)
manifest_path.write_bytes(manifest_bytes)

metadata_dir = fixture.root / "metadata"
serializer = JSONSerializer()
md_targets = Metadata.from_bytes((metadata_dir / "targets.json").read_bytes())
md_targets.signed.version += 1
md_targets.signed.targets["atlas/pack-manifest.json"] = TargetFile.from_data(
    "atlas/pack-manifest.json", manifest_bytes, ["sha256"]
)
md_targets.signed.targets["atlas/source-license-inventory.json"] = TargetFile.from_data(
    "atlas/source-license-inventory.json", inventory_bytes, ["sha256"]
)
md_targets.sign(fixture.signers[Targets.type])
targets_metadata = md_targets.to_bytes(serializer)
(metadata_dir / "targets.json").write_bytes(targets_metadata)

md_snapshot = Metadata.from_bytes((metadata_dir / "snapshot.json").read_bytes())
md_snapshot.signed.version += 1
md_snapshot.signed.meta["targets.json"] = _metafile(targets_metadata, md_targets.signed.version)
md_snapshot.sign(fixture.signers[Snapshot.type])
snapshot_metadata = md_snapshot.to_bytes(serializer)
(metadata_dir / "snapshot.json").write_bytes(snapshot_metadata)

md_timestamp = Metadata.from_bytes((metadata_dir / "timestamp.json").read_bytes())
md_timestamp.signed.version += 1
md_timestamp.signed.snapshot_meta = _metafile(snapshot_metadata, md_snapshot.signed.version)
md_timestamp.sign(fixture.signers[Timestamp.type])
(metadata_dir / "timestamp.json").write_bytes(md_timestamp.to_bytes(serializer))

new_pack = work / "runtime-update-new.atlaspack"
build_verified_atlaspack(fixture.root, new_pack, bootstrap_root=fixture.bootstrap_root)

untrusted = make_signed_repository(work / "untrusted", pack_version="1.0.0-test.12")
untrusted_pack = work / "runtime-update-untrusted.atlaspack"
build_verified_atlaspack(untrusted.root, untrusted_pack, bootstrap_root=untrusted.bootstrap_root)

json.dump({
    "old_pack": str(old_pack),
    "new_pack": str(new_pack),
    "root": str(root_file),
    "untrusted_pack": str(untrusted_pack),
}, out.open("w", encoding="utf-8"), sort_keys=True)
`
	cmd := exec.Command(python, "-c", script, root, work, out)
	cmd.Dir = root
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build G-D6 process fixtures: %v\n%s", err, output)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var fixtures gd6ProcessFixtures
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	return fixtures
}

func gd6CopyFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func gd6Request(t *testing.T, stdin io.Writer, stdout io.Reader, id, method string, params any) gd6WireResponse {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"id":     id,
		"method": method,
		"params": params,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.WriteFrame(stdin, payload, protocol.MaxRequestPayload); err != nil {
		t.Fatalf("write %s request: %v", method, err)
	}
	frame, err := protocol.ReadFrame(stdout, protocol.MaxResponsePayload)
	if err != nil {
		t.Fatalf("read %s response: %v", method, err)
	}
	var response gd6WireResponse
	if err := json.Unmarshal(frame, &response); err != nil {
		t.Fatalf("decode %s response: %v", method, err)
	}
	return response
}

func gd6RequireOK(t *testing.T, response gd6WireResponse, method string) {
	t.Helper()
	if !response.OK {
		t.Fatalf("%s failed: %+v", method, response.Error)
	}
}

func gd6Status(t *testing.T, stdin io.Writer, stdout io.Reader, id string) gd6PackStatus {
	t.Helper()
	response := gd6Request(t, stdin, stdout, id, "pack.status", map[string]any{})
	gd6RequireOK(t, response, "pack.status")
	var status gd6PackStatus
	if err := json.Unmarshal(response.Result, &status); err != nil {
		t.Fatal(err)
	}
	return status
}

func gd6Search(t *testing.T, stdin io.Writer, stdout io.Reader, id string) {
	t.Helper()
	response := gd6Request(t, stdin, stdout, id, "search.query", map[string]any{
		"query":       "4688",
		"graph_depth": 1,
		"limit":       5,
	})
	gd6RequireOK(t, response, "search.query")
}

func TestAtlasCoreSignedUpdateRollbackRoundTripSameProcess(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("G-D6 process round-trip is a Windows Desktop integration gate")
	}
	fixtures := buildGD6ProcessFixtures(t)
	localAppData := t.TempDir()
	runtimeRoot := filepath.Join(localAppData, "Cyber-Sentinel", "ATLAS", "runtime")
	t.Cleanup(func() { restoreTempTreePermissions(runtimeRoot) })

	rootBytes, err := os.ReadFile(fixtures.Root)
	if err != nil {
		t.Fatal(err)
	}
	oldGeneration, err := InstallAtlaspack(
		fixtures.OldPack,
		rootBytes,
		runtimeRoot,
		CurrentRuntimeVersion,
		DefaultSafetyLimits(),
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("install old signed pack: %v", err)
	}
	if err := ensureControlRuntimeRoot(runtimeRoot); err != nil {
		t.Fatal(err)
	}
	gd6CopyFile(t, fixtures.NewPack, PendingUpdatePath(runtimeRoot))

	repoRoot := repositoryRoot(t)
	goRoot := filepath.Join(repoRoot, "shared-core", "go")
	exe := filepath.Join(t.TempDir(), "atlas-core.exe")
	build := exec.Command("go", "build", "-o", exe, "./cmd/atlas-core")
	build.Dir = goRoot
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build atlas-core.exe: %v\n%s", err, output)
	}

	cmd := exec.Command(exe, "--serve-stdio")
	cmd.Env = append(os.Environ(), "LOCALAPPDATA="+localAppData)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()

	handshake := gd6Request(t, stdin, stdout, "h", "core.handshake", map[string]any{
		"protocol":       protocol.ProtocolName,
		"version":        protocol.ProtocolVersion,
		"client_name":    "gd6-process-integration",
		"client_version": "1",
		"session_nonce":  "gd6-signed-roundtrip",
	})
	gd6RequireOK(t, handshake, "core.handshake")
	var handshakeBody struct {
		Capabilities []string `json:"capabilities"`
	}
	if err := json.Unmarshal(handshake.Result, &handshakeBody); err != nil {
		t.Fatal(err)
	}
	capabilitySet := map[string]bool{}
	for _, capability := range handshakeBody.Capabilities {
		capabilitySet[capability] = true
	}
	if !capabilitySet["pack.update"] || !capabilitySet["pack.rollback"] {
		t.Fatalf("G-D6 pack capabilities missing: %#v", handshakeBody.Capabilities)
	}

	before := gd6Status(t, stdin, stdout, "s0")
	if !before.Ready || before.GenerationID != oldGeneration || !before.PendingUpdate {
		t.Fatalf("unexpected pre-update status: %#v", before)
	}
	gd6Search(t, stdin, stdout, "q0")

	updateResponse := gd6Request(t, stdin, stdout, "u", "pack.update", map[string]any{})
	gd6RequireOK(t, updateResponse, "pack.update")
	var update gd6MutationResult
	if err := json.Unmarshal(updateResponse.Result, &update); err != nil {
		t.Fatal(err)
	}
	if update.GenerationID == "" || update.GenerationID == oldGeneration {
		t.Fatalf("signed update did not activate a new generation: %#v", update)
	}

	afterUpdate := gd6Status(t, stdin, stdout, "s1")
	if !afterUpdate.Ready || afterUpdate.GenerationID != update.GenerationID || afterUpdate.PendingUpdate || !afterUpdate.RollbackAvailable {
		t.Fatalf("same-process update status is wrong: %#v", afterUpdate)
	}
	gd6Search(t, stdin, stdout, "q1")

	rollbackResponse := gd6Request(t, stdin, stdout, "r", "pack.rollback", map[string]any{})
	gd6RequireOK(t, rollbackResponse, "pack.rollback")
	var rollback gd6MutationResult
	if err := json.Unmarshal(rollbackResponse.Result, &rollback); err != nil {
		t.Fatal(err)
	}
	if rollback.GenerationID != oldGeneration {
		t.Fatalf("manual rollback restored wrong generation: %#v", rollback)
	}

	afterRollback := gd6Status(t, stdin, stdout, "s2")
	if !afterRollback.Ready || afterRollback.GenerationID != oldGeneration || !afterRollback.RollbackAvailable {
		t.Fatalf("same-process rollback status is wrong: %#v", afterRollback)
	}
	gd6Search(t, stdin, stdout, "q2")

	state, err := LoadRuntimeState(runtimeRoot)
	if err != nil {
		t.Fatal(err)
	}
	highest := state.HighestSeenPacks[update.PackID]
	if highest.Version != update.PackVersion || highest.ManifestDigest != update.ManifestDigest {
		t.Fatalf("manual rollback rewound highest-seen trust: %#v", highest)
	}

	gd6CopyFile(t, fixtures.UntrustedPack, PendingUpdatePath(runtimeRoot))
	untrustedResponse := gd6Request(t, stdin, stdout, "bad", "pack.update", map[string]any{})
	if untrustedResponse.OK || untrustedResponse.Error == nil || untrustedResponse.Error.Code != protocol.CodePackTrustFailure {
		t.Fatalf("untrusted update did not fail with pack trust error: %+v", untrustedResponse.Error)
	}
	preserved := gd6Status(t, stdin, stdout, "s3")
	if !preserved.Ready || preserved.GenerationID != oldGeneration || !preserved.PendingUpdate {
		t.Fatalf("failed untrusted update changed active state: %#v", preserved)
	}
	gd6Search(t, stdin, stdout, "q3")

	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("atlas-core process exit: %v\nstderr:\n%s", err, stderr.String())
	}
}
