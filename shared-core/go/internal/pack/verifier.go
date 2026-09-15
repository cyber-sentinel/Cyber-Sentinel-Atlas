package pack

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cyber-sentinel/Cyber-Sentinel-Atlas/shared-core/go/internal/canonical"
	"github.com/cyber-sentinel/Cyber-Sentinel-Atlas/shared-core/go/internal/search"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
)

const CurrentRuntimeVersion = "0.1.0-foundation.1"

var (
	versionedMetadataRE = regexp.MustCompile(`^([1-9][0-9]*)\.(root|snapshot|targets)\.json$`)
	hashTargetRE        = regexp.MustCompile(`^([0-9a-f]{64})\.(.+)$`)
)

type VerifiedPack struct {
	PackID                 string
	PackVersion            string
	Manifest               *Manifest
	ManifestBytes          []byte
	ManifestDigest         string
	Inventory              *SourceLicenseInventory
	InventoryBytes         []byte
	VerifiedTargetsDir     string
	RuntimeSearchIndex     string
	UsedRebuiltSearchIndex bool
	SPC                    search.Bundle
}

type localFetcher struct {
	root string
}

func downloadHTTPError(path string, status int) error {
	return &metadata.ErrDownloadHTTP{StatusCode: status, URL: path}
}

func safeRelative(value string) ([]string, error) {
	if value == "" || strings.Contains(value, "\\") || strings.ContainsRune(value, '\x00') || strings.HasPrefix(value, "/") || driveRE.MatchString(value) {
		return nil, fmt.Errorf("unsafe relative path %q", value)
	}
	parts := strings.Split(value, "/")
	for _, part := range parts {
		if err := validatePathComponent(part); err != nil {
			return nil, err
		}
	}
	return parts, nil
}

func metadataVersion(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var envelope struct {
		Signed struct {
			Version int `json:"version"`
		} `json:"signed"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return 0, err
	}
	return envelope.Signed.Version, nil
}

func safeRegularFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("not a regular non-symlink file")
	}
	return os.ReadFile(path)
}

func (f *localFetcher) resolveMetadata(relative string) (string, error) {
	parts, err := safeRelative(relative)
	if err != nil || len(parts) != 1 {
		return "", downloadHTTPError(relative, 404)
	}
	direct := filepath.Join(f.root, "metadata", parts[0])
	if info, err := os.Lstat(direct); err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
		return direct, nil
	}
	match := versionedMetadataRE.FindStringSubmatch(parts[0])
	if match == nil {
		return "", downloadHTTPError(relative, 404)
	}
	requested, _ := strconv.Atoi(match[1])
	fallback := filepath.Join(f.root, "metadata", match[2]+".json")
	version, err := metadataVersion(fallback)
	if err == nil && version == requested {
		return fallback, nil
	}
	return "", downloadHTTPError(relative, 404)
}

func (f *localFetcher) resolveTarget(relative string) (string, error) {
	parts, err := safeRelative(relative)
	if err != nil {
		return "", downloadHTTPError(relative, 404)
	}
	direct := filepath.Join(append([]string{f.root, "targets"}, parts...)...)
	if info, err := os.Lstat(direct); err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
		return direct, nil
	}
	match := hashTargetRE.FindStringSubmatch(parts[len(parts)-1])
	if match == nil {
		return "", downloadHTTPError(relative, 404)
	}
	fallbackParts := append([]string{}, parts[:len(parts)-1]...)
	fallbackParts = append(fallbackParts, match[2])
	fallback := filepath.Join(append([]string{f.root, "targets"}, fallbackParts...)...)
	if info, err := os.Lstat(fallback); err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
		return fallback, nil
	}
	return "", downloadHTTPError(relative, 404)
}

func (f *localFetcher) DownloadFile(urlPath string, maxLength int64, _ time.Duration) ([]byte, error) {
	parsed, err := url.Parse(urlPath)
	if err != nil || parsed.Scheme != "https" || parsed.Host != "atlas.invalid" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, downloadHTTPError(urlPath, 403)
	}
	decoded, err := url.PathUnescape(parsed.EscapedPath())
	if err != nil {
		return nil, downloadHTTPError(urlPath, 404)
	}
	var source string
	switch {
	case strings.HasPrefix(decoded, "/metadata/"):
		source, err = f.resolveMetadata(strings.TrimPrefix(decoded, "/metadata/"))
	case strings.HasPrefix(decoded, "/targets/"):
		source, err = f.resolveTarget(strings.TrimPrefix(decoded, "/targets/"))
	default:
		return nil, downloadHTTPError(urlPath, 404)
	}
	if err != nil {
		return nil, err
	}
	data, err := safeRegularFile(source)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxLength {
		return nil, fmt.Errorf("local fetch exceeds TUF maxLength")
	}
	return data, nil
}

func newUpdater(repoRoot string, bootstrap []byte, cache string) (*updater.Updater, error) {
	cfg, err := config.New("https://atlas.invalid/metadata/", bootstrap)
	if err != nil {
		return nil, err
	}
	cfg.Fetcher = &localFetcher{root: repoRoot}
	cfg.LocalMetadataDir = filepath.Join(cache, "metadata")
	cfg.LocalTargetsDir = filepath.Join(cache, "downloads")
	cfg.RemoteTargetsURL = "https://atlas.invalid/targets/"
	cfg.PrefixTargetsWithHash = true
	cfg.MaxRootRotations = 32
	cfg.MaxDelegations = 1
	cfg.RootMaxLength = 1024 * 1024
	cfg.TimestampMaxLength = 2 * 1024 * 1024
	cfg.SnapshotMaxLength = 8 * 1024 * 1024
	cfg.TargetsMaxLength = 32 * 1024 * 1024
	return updater.New(cfg)
}

func downloadTarget(up *updater.Updater, name string) ([]byte, error) {
	info, err := up.GetTargetInfo(name)
	if err != nil {
		return nil, err
	}
	if info == nil {
		return nil, fmt.Errorf("TUF target missing: %s", name)
	}
	_, data, err := up.DownloadTarget(info, "", "")
	return data, err
}

func signedTargetNames(repoRoot string) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(repoRoot, "metadata", "targets.json"))
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Signed struct {
			Targets map[string]json.RawMessage `json:"targets"`
		} `json:"signed"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(envelope.Signed.Targets))
	for name := range envelope.Signed.Targets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func verifyManifestTopology(repoRoot string, manifest *Manifest) error {
	allowed := map[string]bool{
		"atlas/pack-manifest.json":            true,
		"atlas/source-license-inventory.json": true,
	}
	for _, artifact := range manifest.Artifacts {
		allowed[artifact.Path] = true
	}
	names, err := signedTargetNames(repoRoot)
	if err != nil {
		return err
	}
	if len(names) != len(allowed) {
		return fmt.Errorf("signed target topology mismatch")
	}
	for _, name := range names {
		if !allowed[name] {
			return fmt.Errorf("signed but undeclared target: %s", name)
		}
	}
	return nil
}

func writeVerifiedTarget(root, relative string, data []byte) (string, error) {
	parts, err := safeRelative(relative)
	if err != nil {
		return "", err
	}
	path := filepath.Join(append([]string{root}, parts...)...)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func canonicalDigest(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256-" + hex.EncodeToString(sum[:]), nil
}

func validateSPC(data []byte) (search.Bundle, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var raw map[string]any
	if err := decoder.Decode(&raw); err != nil {
		return search.Bundle{}, err
	}
	claimed, ok := raw["bundle_digest"].(string)
	if !ok || !digestRE.MatchString(claimed) {
		return search.Bundle{}, fmt.Errorf("SPC bundle digest is missing")
	}
	delete(raw, "bundle_digest")
	actual, err := canonicalDigest(raw)
	if err != nil || actual != claimed {
		return search.Bundle{}, fmt.Errorf("SPC bundle digest mismatch")
	}
	if docs, ok := raw["documents"].([]any); ok {
		for _, item := range docs {
			doc, ok := item.(map[string]any)
			if !ok {
				return search.Bundle{}, fmt.Errorf("SPC document is malformed")
			}
			projection, ok := doc["projection_digest"].(string)
			if !ok {
				return search.Bundle{}, fmt.Errorf("SPC document projection digest is missing")
			}
			delete(doc, "projection_digest")
			digest, err := canonicalDigest(doc)
			if err != nil || digest != projection {
				return search.Bundle{}, fmt.Errorf("SPC document projection digest mismatch")
			}
		}
	}
	var bundle search.Bundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return search.Bundle{}, err
	}
	if err := search.ValidateBundle(&bundle); err != nil {
		return search.Bundle{}, err
	}
	return bundle, nil
}

func VerifyPackDirectory(packRoot string, bootstrapRoot []byte, metadataCacheDir, verifiedTargetsDir, currentRuntimeVersion string) (*VerifiedPack, error) {
	if len(bootstrapRoot) == 0 {
		return nil, fmt.Errorf("a non-empty trusted bootstrap root is mandatory")
	}
	if currentRuntimeVersion == "" {
		currentRuntimeVersion = CurrentRuntimeVersion
	}
	for _, name := range []string{"metadata", "targets"} {
		info, err := os.Lstat(filepath.Join(packRoot, name))
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("pack lacks safe %s directory", name)
		}
	}
	if info, err := os.Lstat(verifiedTargetsDir); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("verified target output directory is unsafe")
		}
		entries, err := os.ReadDir(verifiedTargetsDir)
		if err != nil || len(entries) != 0 {
			return nil, fmt.Errorf("verified target output directory must be empty")
		}
	} else if err := os.MkdirAll(verifiedTargetsDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(metadataCacheDir, 0o700); err != nil {
		return nil, err
	}
	up, err := newUpdater(packRoot, bootstrapRoot, metadataCacheDir)
	if err != nil {
		return nil, err
	}
	if err := up.Refresh(); err != nil {
		return nil, fmt.Errorf("TUF verification failed: %w", err)
	}
	manifestBytes, err := downloadTarget(up, "atlas/pack-manifest.json")
	if err != nil {
		return nil, fmt.Errorf("TUF manifest verification failed: %w", err)
	}
	inventoryBytes, err := downloadTarget(up, "atlas/source-license-inventory.json")
	if err != nil {
		return nil, fmt.Errorf("TUF inventory verification failed: %w", err)
	}
	manifest, inventory, err := validateContractPair(manifestBytes, inventoryBytes, true)
	if err != nil {
		return nil, fmt.Errorf("Atlas pack control contract failed: %w", err)
	}
	order, err := compareSemver(currentRuntimeVersion, manifest.MinimumRuntimeVersion)
	if err != nil || order < 0 {
		return nil, fmt.Errorf("pack requires newer Atlas runtime")
	}
	if err := verifyManifestTopology(packRoot, manifest); err != nil {
		return nil, err
	}
	if _, err := writeVerifiedTarget(verifiedTargetsDir, "atlas/pack-manifest.json", manifestBytes); err != nil {
		return nil, err
	}
	if _, err := writeVerifiedTarget(verifiedTargetsDir, "atlas/source-license-inventory.json", inventoryBytes); err != nil {
		return nil, err
	}

	var canonicalData, spcData []byte
	var signedIndexPath string
	for _, artifact := range manifest.Artifacts {
		data, err := downloadTarget(up, artifact.Path)
		if err != nil {
			return nil, fmt.Errorf("TUF artifact verification failed for %s: %w", artifact.Path, err)
		}
		if int64(len(data)) != artifact.Length || sha256Prefixed(data) != artifact.Digest {
			return nil, fmt.Errorf("artifact binding mismatch: %s", artifact.Path)
		}
		path, err := writeVerifiedTarget(verifiedTargetsDir, artifact.Path, data)
		if err != nil {
			return nil, err
		}
		switch artifact.Kind {
		case "canonical-records":
			canonicalData = data
		case "spc":
			spcData = data
		case "search-index":
			signedIndexPath = path
		}
	}
	if len(canonicalData) == 0 || len(spcData) == 0 {
		return nil, fmt.Errorf("verified pack is missing canonical/SPC artifacts")
	}
	if _, err := canonical.DecodeJSONL(bytes.NewReader(canonicalData)); err != nil {
		return nil, fmt.Errorf("canonical AtlasRecord validation failed: %w", err)
	}
	bundle, err := validateSPC(spcData)
	if err != nil {
		return nil, fmt.Errorf("verified SPC is invalid: %w", err)
	}
	runtimeIndex := signedIndexPath
	rebuilt := false
	if runtimeIndex != "" {
		core, err := search.Open(runtimeIndex, &bundle)
		if err == nil {
			_ = core.Close()
		} else {
			runtimeIndex = ""
		}
	}
	if runtimeIndex == "" {
		runtimeIndex = filepath.Join(verifiedTargetsDir, "_runtime-derived", "search", "atlas-search.sqlite3")
		if err := search.BuildIndex(&bundle, runtimeIndex); err != nil {
			return nil, fmt.Errorf("failed to rebuild derived search index: %w", err)
		}
		core, err := search.Open(runtimeIndex, &bundle)
		if err != nil {
			return nil, fmt.Errorf("rebuilt derived search index failed validation: %w", err)
		}
		_ = core.Close()
		rebuilt = true
	}
	return &VerifiedPack{
		PackID:                 manifest.PackID,
		PackVersion:            manifest.PackVersion,
		Manifest:               manifest,
		ManifestBytes:          manifestBytes,
		ManifestDigest:         sha256Prefixed(manifestBytes),
		Inventory:              inventory,
		InventoryBytes:         inventoryBytes,
		VerifiedTargetsDir:     verifiedTargetsDir,
		RuntimeSearchIndex:     runtimeIndex,
		UsedRebuiltSearchIndex: rebuilt,
		SPC:                    bundle,
	}, nil
}
