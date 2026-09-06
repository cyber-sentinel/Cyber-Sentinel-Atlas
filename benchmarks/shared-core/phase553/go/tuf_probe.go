package main

import (
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

	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
)

var (
	versionedMetadataRE = regexp.MustCompile(`^([1-9][0-9]*)\.(root|snapshot|targets)\.json$`)
	hashTargetRE        = regexp.MustCompile(`^([0-9a-f]{64})\.(.+)$`)
)

type localFetcher struct {
	root          string
	sawHashTarget bool
	requests      []string
}

func downloadHTTPError(path string, status int) error {
	return &metadata.ErrDownloadHTTP{StatusCode: status, URL: path}
}

func safeRelative(value string) ([]string, error) {
	if value == "" || strings.Contains(value, "\\") || strings.ContainsRune(value, '\x00') || strings.HasPrefix(value, "/") {
		return nil, fmt.Errorf("unsafe relative path %q", value)
	}
	parts := strings.Split(value, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, fmt.Errorf("unsafe path component in %q", value)
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
		return nil, fmt.Errorf("not a regular non-symlink file: %s", path)
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
		f.sawHashTarget = true
		return fallback, nil
	}
	return "", downloadHTTPError(relative, 404)
}

func (f *localFetcher) DownloadFile(urlPath string, maxLength int64, _ time.Duration) ([]byte, error) {
	f.requests = append(f.requests, urlPath)
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
		return nil, fmt.Errorf("local fetch exceeds TUF maxLength: %d > %d", len(data), maxLength)
	}
	return data, nil
}

type manifestArtifact struct {
	Path    string `json:"path"`
	Kind    string `json:"kind"`
	Digest  string `json:"digest"`
	Length  int    `json:"length"`
	Derived bool   `json:"derived"`
}

type packManifest struct {
	PackID                 string `json:"pack_id"`
	PackVersion            string `json:"pack_version"`
	CanonicalRecordsDigest string `json:"canonical_records_digest"`
	SPCDigest              string `json:"spc_digest"`
	SourceLicenseInventory struct {
		Path   string `json:"path"`
		Digest string `json:"digest"`
	} `json:"source_license_inventory"`
	Artifacts []manifestArtifact `json:"artifacts"`
}

type verifiedGoPack struct {
	ManifestDigest string
	PackID         string
	PackVersion    string
	HashTargetSeen bool
	Requests       int
}

func newUpdater(repoRoot string, bootstrap []byte, cache string) (*updater.Updater, *localFetcher, error) {
	fetcher := &localFetcher{root: repoRoot}
	cfg, err := config.New("https://atlas.invalid/metadata/", bootstrap)
	if err != nil {
		return nil, nil, err
	}
	cfg.Fetcher = fetcher
	cfg.LocalMetadataDir = filepath.Join(cache, "metadata")
	cfg.LocalTargetsDir = filepath.Join(cache, "targets")
	cfg.RemoteTargetsURL = "https://atlas.invalid/targets/"
	cfg.PrefixTargetsWithHash = true
	cfg.MaxRootRotations = 32
	cfg.MaxDelegations = 1
	cfg.RootMaxLength = 1024 * 1024
	cfg.TimestampMaxLength = 2 * 1024 * 1024
	cfg.SnapshotMaxLength = 8 * 1024 * 1024
	cfg.TargetsMaxLength = 32 * 1024 * 1024
	up, err := updater.New(cfg)
	return up, fetcher, err
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

func verifyManifestTopology(repoRoot string, manifest packManifest) error {
	allowed := map[string]bool{
		"atlas/pack-manifest.json":           true,
		"atlas/source-license-inventory.json": true,
	}
	for _, artifact := range manifest.Artifacts {
		if _, err := safeRelative(artifact.Path); err != nil {
			return fmt.Errorf("unsafe manifest artifact: %w", err)
		}
		allowed[artifact.Path] = true
	}
	names, err := signedTargetNames(repoRoot)
	if err != nil {
		return err
	}
	if len(names) != len(allowed) {
		return fmt.Errorf("signed target topology mismatch: signed=%d declared=%d", len(names), len(allowed))
	}
	for _, name := range names {
		if !allowed[name] {
			return fmt.Errorf("signed but undeclared target: %s", name)
		}
	}
	return nil
}

func verifyRepo(repoRoot string, bootstrap []byte, cache string) (verifiedGoPack, error) {
	up, fetcher, err := newUpdater(repoRoot, bootstrap, cache)
	if err != nil {
		return verifiedGoPack{}, err
	}
	if err := up.Refresh(); err != nil {
		return verifiedGoPack{}, err
	}
	manifestBytes, err := downloadTarget(up, "atlas/pack-manifest.json")
	if err != nil {
		return verifiedGoPack{}, err
	}
	inventoryBytes, err := downloadTarget(up, "atlas/source-license-inventory.json")
	if err != nil {
		return verifiedGoPack{}, err
	}
	var manifest packManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return verifiedGoPack{}, err
	}
	if manifest.PackID == "" || manifest.PackVersion == "" {
		return verifiedGoPack{}, fmt.Errorf("manifest identity missing")
	}
	if manifest.SourceLicenseInventory.Path != "atlas/source-license-inventory.json" || sha256Prefixed(inventoryBytes) != manifest.SourceLicenseInventory.Digest {
		return verifiedGoPack{}, fmt.Errorf("source-license inventory binding mismatch")
	}
	if err := verifyManifestTopology(repoRoot, manifest); err != nil {
		return verifiedGoPack{}, err
	}
	canonicalCount, spcCount := 0, 0
	for _, artifact := range manifest.Artifacts {
		data, err := downloadTarget(up, artifact.Path)
		if err != nil {
			return verifiedGoPack{}, err
		}
		if len(data) != artifact.Length || sha256Prefixed(data) != artifact.Digest {
			return verifiedGoPack{}, fmt.Errorf("artifact binding mismatch: %s", artifact.Path)
		}
		if artifact.Kind == "canonical-records" {
			canonicalCount++
			if artifact.Digest != manifest.CanonicalRecordsDigest {
				return verifiedGoPack{}, fmt.Errorf("canonical digest binding mismatch")
			}
		}
		if artifact.Kind == "spc" {
			spcCount++
			if artifact.Digest != manifest.SPCDigest {
				return verifiedGoPack{}, fmt.Errorf("SPC digest binding mismatch")
			}
		}
	}
	if canonicalCount != 1 || spcCount != 1 {
		return verifiedGoPack{}, fmt.Errorf("manifest must contain exactly one canonical and one SPC artifact")
	}
	return verifiedGoPack{
		ManifestDigest: sha256Prefixed(manifestBytes),
		PackID: manifest.PackID,
		PackVersion: manifest.PackVersion,
		HashTargetSeen: fetcher.sawHashTarget,
		Requests: len(fetcher.requests),
	}, nil
}

func expectReject(repo string, bootstrap []byte, cache string) bool {
	_, err := verifyRepo(repo, bootstrap, cache)
	return err != nil
}

func rollbackRejected(workspace string, bootstrap []byte) bool {
	cache, err := os.MkdirTemp("", "atlas-go-tuf-rollback-")
	if err != nil {
		return false
	}
	defer os.RemoveAll(cache)
	if _, err := verifyRepo(filepath.Join(workspace, "rollback-v2"), bootstrap, cache); err != nil {
		return false
	}
	_, err = verifyRepo(filepath.Join(workspace, "rollback-v1"), bootstrap, cache)
	return err != nil
}

func runTUFProbe(workspace string, expected Expected) (map[string]any, bool, error) {
	bootstrap, err := os.ReadFile(filepath.Join(workspace, "bootstrap-root.json"))
	if err != nil {
		return nil, false, err
	}
	wrongBootstrap, err := os.ReadFile(filepath.Join(workspace, "wrong-bootstrap-root.json"))
	if err != nil {
		return nil, false, err
	}
	rollbackBootstrap, err := os.ReadFile(filepath.Join(workspace, "rollback-bootstrap-root.json"))
	if err != nil {
		return nil, false, err
	}
	validCache, err := os.MkdirTemp("", "atlas-go-tuf-valid-")
	if err != nil {
		return nil, false, err
	}
	defer os.RemoveAll(validCache)
	valid, validErr := verifyRepo(filepath.Join(workspace, "valid"), bootstrap, validCache)
	validOK := validErr == nil && valid.ManifestDigest == expected.ValidManifestSHA256 && valid.HashTargetSeen

	caseReject := func(name string, root []byte) bool {
		cache, err := os.MkdirTemp("", "atlas-go-tuf-case-")
		if err != nil {
			return false
		}
		defer os.RemoveAll(cache)
		return expectReject(filepath.Join(workspace, name), root, cache)
	}
	cases := map[string]bool{
		"valid":                    validOK,
		"wrong_root":               caseReject("valid", wrongBootstrap),
		"target_byte_tamper":       caseReject("tampered-target", bootstrap),
		"signature_tamper":         caseReject("tampered-signature", bootstrap),
		"expired_metadata":         caseReject("expired", bootstrap),
		"undeclared_signed_target": caseReject("undeclared", bootstrap),
		"metadata_rollback":        rollbackRejected(workspace, rollbackBootstrap),
		"consistent_snapshot":      validErr == nil && valid.HashTargetSeen,
		"offline_local_fetch_only": validErr == nil,
		"manifest_inventory_binding": validErr == nil && valid.ManifestDigest == expected.ValidManifestSHA256,
	}
	all := true
	for _, ok := range cases {
		all = all && ok
	}
	result := map[string]any{
		"library": "github.com/theupdateframework/go-tuf/v2@v2.4.2",
		"cases": cases,
		"valid_manifest_digest": valid.ManifestDigest,
		"local_fetch_requests": valid.Requests,
		"network_transport": "none-custom-local-fetcher",
	}
	if validErr != nil {
		result["valid_error"] = validErr.Error()
	}
	return result, all, nil
}

func rawSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
