package pack

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"golang.org/x/text/unicode/norm"
)

const (
	PackFormatVersion = "1.0.0"
	InventoryVersion  = "1.0.0"
)

var (
	digestRE   = regexp.MustCompile(`^sha256-[0-9a-f]{64}$`)
	hex64RE    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	packIDRE   = regexp.MustCompile(`^atlas:pack:[a-z0-9][a-z0-9._-]{0,127}$`)
	sourceIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)
	driveRE    = regexp.MustCompile(`^[A-Za-z]:`)
)

var windowsReserved = func() map[string]struct{} {
	values := map[string]struct{}{"CON": {}, "PRN": {}, "AUX": {}, "NUL": {}}
	for i := 1; i <= 9; i++ {
		values[fmt.Sprintf("COM%d", i)] = struct{}{}
		values[fmt.Sprintf("LPT%d", i)] = struct{}{}
	}
	return values
}()

var activeExtensions = map[string]struct{}{
	".exe": {}, ".dll": {}, ".sys": {}, ".msi": {}, ".msp": {}, ".com": {}, ".scr": {},
	".bat": {}, ".cmd": {}, ".ps1": {}, ".psm1": {}, ".vbs": {}, ".vbe": {}, ".js": {},
	".jse": {}, ".wsf": {}, ".wsh": {}, ".hta": {}, ".lnk": {}, ".reg": {}, ".sh": {},
	".py": {}, ".pl": {}, ".rb": {}, ".jar": {}, ".class": {}, ".so": {}, ".dylib": {},
	".appx": {}, ".msix": {}, ".deb": {}, ".rpm": {}, ".apk": {},
}

type Artifact struct {
	Path    string `json:"path"`
	Kind    string `json:"kind"`
	Digest  string `json:"digest"`
	Length  int64  `json:"length"`
	Derived bool   `json:"derived"`
}

type InventoryBinding struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}

type Manifest struct {
	PackFormatVersion        string           `json:"pack_format_version"`
	PackID                   string           `json:"pack_id"`
	PackVersion              string           `json:"pack_version"`
	CreatedAt                string           `json:"created_at"`
	CanonicalSchemaVersion   string           `json:"canonical_schema_version"`
	IngestionContractVersion string           `json:"ingestion_contract_version"`
	SearchContractVersion    string           `json:"search_contract_version"`
	MinimumRuntimeVersion    string           `json:"minimum_runtime_version"`
	CanonicalRecordsDigest   string           `json:"canonical_records_digest"`
	SPCDigest                string           `json:"spc_digest"`
	SourceLicenseInventory   InventoryBinding `json:"source_license_inventory"`
	Artifacts                []Artifact       `json:"artifacts"`
}

type SourceLicenseEntry struct {
	SourceID              string `json:"source_id"`
	SourceName            string `json:"source_name"`
	UpstreamURL           string `json:"upstream_url"`
	SourceVersionOrCommit string `json:"source_version_or_commit"`
	ContentDigest         string `json:"content_digest"`
	RedistributionScope   string `json:"redistribution_scope"`
	LicenseStatus         string `json:"license_status"`
	LicenseIdentifier     string `json:"license_identifier"`
	NoticeRequired        bool   `json:"notice_required"`
	Attribution           string `json:"attribution"`
	EvidenceURL           string `json:"evidence_url"`
	ReviewedAt            string `json:"reviewed_at"`
}

type SourceLicenseInventory struct {
	InventoryVersion string               `json:"inventory_version"`
	PackID           string               `json:"pack_id"`
	PackVersion      string               `json:"pack_version"`
	Entries          []SourceLicenseEntry `json:"entries"`
}

func decodeStrictJSON(data []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON value")
		}
		return fmt.Errorf("trailing JSON data: %w", err)
	}
	return nil
}

func sha256Prefixed(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256-" + hex.EncodeToString(sum[:])
}

func validateCanonicalUTC(value, field string) error {
	if len(value) != len("2006-01-02T15:04:05Z") || !strings.HasSuffix(value, "Z") {
		return fmt.Errorf("%s must use canonical UTC YYYY-MM-DDTHH:MM:SSZ form", field)
	}
	parsed, err := time.Parse("2006-01-02T15:04:05Z", value)
	if err != nil || parsed.Format("2006-01-02T15:04:05Z") != value {
		return fmt.Errorf("%s is not a valid canonical UTC timestamp", field)
	}
	return nil
}

func validateHTTPSURL(value, field string) error {
	parsed, err := url.Parse(value)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.Host == "" {
		return fmt.Errorf("%s must be an absolute HTTPS URL", field)
	}
	if parsed.User != nil {
		return fmt.Errorf("%s must not contain URL credentials", field)
	}
	if parsed.Fragment != "" {
		return fmt.Errorf("%s must not contain a fragment", field)
	}
	return nil
}

func validatePathComponent(part string) error {
	if part == "" || part == "." || part == ".." {
		return fmt.Errorf("non-canonical path component: %q", part)
	}
	stripped := strings.TrimRight(part, " .")
	if stripped != part || stripped == "" {
		return fmt.Errorf("Windows-ambiguous path component: %q", part)
	}
	stem := strings.ToUpper(strings.SplitN(stripped, ".", 2)[0])
	if _, blocked := windowsReserved[stem]; blocked {
		return fmt.Errorf("Windows-reserved path component: %q", part)
	}
	return nil
}

func validateSafeTargetPath(value string, expectedPrefixes ...string) error {
	if value == "" || len(value) > 512 || strings.Contains(value, "\\") || strings.ContainsRune(value, '\x00') {
		return fmt.Errorf("unsafe target path: %q", value)
	}
	if strings.HasPrefix(value, "/") || driveRE.MatchString(value) || path.Clean(value) != value {
		return fmt.Errorf("non-canonical target path: %q", value)
	}
	if norm.NFC.String(value) != value {
		return fmt.Errorf("target path is not NFC canonical: %q", value)
	}
	allowed := false
	for _, prefix := range expectedPrefixes {
		if strings.HasPrefix(value, prefix) {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("target path outside permitted namespace: %q", value)
	}
	parts := strings.Split(value, "/")
	for _, part := range parts {
		if err := validatePathComponent(part); err != nil {
			return err
		}
	}
	ext := strings.ToLower(path.Ext(value))
	if _, blocked := activeExtensions[ext]; blocked {
		return fmt.Errorf("active-code extension is forbidden in content packs: %q", value)
	}
	return nil
}

func validateManifest(manifest *Manifest) error {
	if manifest == nil {
		return fmt.Errorf("pack manifest is required")
	}
	if manifest.PackFormatVersion != PackFormatVersion {
		return fmt.Errorf("unsupported pack_format_version")
	}
	if !packIDRE.MatchString(manifest.PackID) {
		return fmt.Errorf("invalid pack_id")
	}
	if _, err := parseSemver(manifest.PackVersion); err != nil {
		return err
	}
	if err := validateCanonicalUTC(manifest.CreatedAt, "created_at"); err != nil {
		return err
	}
	for field, value := range map[string]string{
		"canonical_schema_version":   manifest.CanonicalSchemaVersion,
		"ingestion_contract_version": manifest.IngestionContractVersion,
		"search_contract_version":    manifest.SearchContractVersion,
	} {
		if value == "" || len(value) > 64 {
			return fmt.Errorf("%s is required and must be <=64 characters", field)
		}
	}
	if _, err := parseSemver(manifest.MinimumRuntimeVersion); err != nil {
		return fmt.Errorf("invalid minimum_runtime_version: %w", err)
	}
	if !digestRE.MatchString(manifest.CanonicalRecordsDigest) || !digestRE.MatchString(manifest.SPCDigest) {
		return fmt.Errorf("invalid manifest control digest")
	}
	if manifest.SourceLicenseInventory.Path != "atlas/source-license-inventory.json" || !digestRE.MatchString(manifest.SourceLicenseInventory.Digest) {
		return fmt.Errorf("invalid source-license inventory binding")
	}
	if len(manifest.Artifacts) < 1 || len(manifest.Artifacts) > 4096 {
		return fmt.Errorf("manifest artifacts count is outside permitted bounds")
	}
	seen := map[string]struct{}{}
	canonicalCount, spcCount, searchCount := 0, 0, 0
	for _, artifact := range manifest.Artifacts {
		if err := validateSafeTargetPath(artifact.Path, "content/", "search/"); err != nil {
			return err
		}
		folded := strings.ToLower(norm.NFC.String(artifact.Path))
		if _, exists := seen[folded]; exists {
			return fmt.Errorf("duplicate/case-colliding artifact path: %q", artifact.Path)
		}
		seen[folded] = struct{}{}
		if !digestRE.MatchString(artifact.Digest) || artifact.Length < 0 || artifact.Length > 2147483648 {
			return fmt.Errorf("invalid artifact binding: %s", artifact.Path)
		}
		switch artifact.Kind {
		case "canonical-records":
			canonicalCount++
			if artifact.Derived || artifact.Digest != manifest.CanonicalRecordsDigest {
				return fmt.Errorf("canonical-records binding is invalid")
			}
		case "spc":
			spcCount++
			if !artifact.Derived || artifact.Digest != manifest.SPCDigest {
				return fmt.Errorf("SPC binding is invalid")
			}
		case "search-index":
			searchCount++
			if !artifact.Derived {
				return fmt.Errorf("search-index must declare derived=true")
			}
		case "coverage", "provenance", "auxiliary-data":
		default:
			return fmt.Errorf("unsupported artifact kind: %q", artifact.Kind)
		}
	}
	if canonicalCount != 1 || spcCount != 1 || searchCount > 1 {
		return fmt.Errorf("pack requires exactly one canonical-records and SPC artifact and at most one search-index")
	}
	return nil
}

func validateSourceLicenseInventory(inventory *SourceLicenseInventory, publication bool) error {
	if inventory == nil || inventory.InventoryVersion != InventoryVersion || !packIDRE.MatchString(inventory.PackID) {
		return fmt.Errorf("invalid source-license inventory identity")
	}
	if _, err := parseSemver(inventory.PackVersion); err != nil {
		return err
	}
	if len(inventory.Entries) < 1 || len(inventory.Entries) > 4096 {
		return fmt.Errorf("source-license entries count is outside permitted bounds")
	}
	seen := map[string]struct{}{}
	for _, entry := range inventory.Entries {
		if !sourceIDRE.MatchString(entry.SourceID) {
			return fmt.Errorf("invalid source_id: %q", entry.SourceID)
		}
		if _, exists := seen[entry.SourceID]; exists {
			return fmt.Errorf("duplicate source_id: %q", entry.SourceID)
		}
		seen[entry.SourceID] = struct{}{}
		if entry.SourceName == "" || len(entry.SourceName) > 256 || entry.SourceVersionOrCommit == "" || len(entry.SourceVersionOrCommit) > 256 {
			return fmt.Errorf("source identity fields are invalid: %s", entry.SourceID)
		}
		if !digestRE.MatchString(entry.ContentDigest) {
			return fmt.Errorf("invalid source content digest: %s", entry.SourceID)
		}
		if err := validateHTTPSURL(entry.UpstreamURL, entry.SourceID+".upstream_url"); err != nil {
			return err
		}
		if err := validateHTTPSURL(entry.EvidenceURL, entry.SourceID+".evidence_url"); err != nil {
			return err
		}
		if err := validateCanonicalUTC(entry.ReviewedAt, entry.SourceID+".reviewed_at"); err != nil {
			return err
		}
		if entry.LicenseIdentifier == "" || len(entry.LicenseIdentifier) > 256 || entry.Attribution == "" || len(entry.Attribution) > 4096 {
			return fmt.Errorf("license attribution fields are invalid: %s", entry.SourceID)
		}
		switch entry.RedistributionScope {
		case "included", "reference-only":
		default:
			return fmt.Errorf("invalid redistribution_scope: %s", entry.SourceID)
		}
		switch entry.LicenseStatus {
		case "verified-redistributable", "verified-reference-only", "unknown", "incompatible":
		default:
			return fmt.Errorf("invalid license_status: %s", entry.SourceID)
		}
		if entry.RedistributionScope == "included" && entry.LicenseStatus != "verified-redistributable" {
			return fmt.Errorf("included source is not verified redistributable: %s", entry.SourceID)
		}
		if publication && (entry.LicenseStatus == "unknown" || entry.LicenseStatus == "incompatible") {
			return fmt.Errorf("publication inventory contains blocked license state: %s", entry.SourceID)
		}
	}
	return nil
}

func validateContractPair(manifestBytes, inventoryBytes []byte, publication bool) (*Manifest, *SourceLicenseInventory, error) {
	var manifest Manifest
	if err := decodeStrictJSON(manifestBytes, &manifest); err != nil {
		return nil, nil, fmt.Errorf("decode pack manifest: %w", err)
	}
	if err := validateManifest(&manifest); err != nil {
		return nil, nil, err
	}
	var inventory SourceLicenseInventory
	if err := decodeStrictJSON(inventoryBytes, &inventory); err != nil {
		return nil, nil, fmt.Errorf("decode source-license inventory: %w", err)
	}
	if err := validateSourceLicenseInventory(&inventory, publication); err != nil {
		return nil, nil, err
	}
	if manifest.PackID != inventory.PackID || manifest.PackVersion != inventory.PackVersion {
		return nil, nil, fmt.Errorf("manifest/inventory pack identity mismatch")
	}
	if manifest.SourceLicenseInventory.Digest != sha256Prefixed(inventoryBytes) {
		return nil, nil, fmt.Errorf("source-license inventory byte digest mismatch")
	}
	return &manifest, &inventory, nil
}
