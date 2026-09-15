package search

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

const (
	ContractVersion = "1.0.0"
	DefaultTopK     = 20
	MaxTopK         = 100
	MaxQueryScalars = 512
	MaxTerms        = 32
	MaxFilters      = 16
	MaxGraphDepth   = 2
)

var (
	caseFolder     = cases.Fold()
	lexicalTokenRE = regexp.MustCompile(`[\p{L}\p{N}_]+`)
	filterKeys     = map[string]struct{}{
		"platform": {}, "product": {}, "provider": {}, "channel": {},
		"namespace": {}, "type": {}, "lifecycle": {}, "version": {},
	}
	scopeWords = map[string]map[string]string{
		"sysmon":  {"namespace": "microsoft.sysmon", "product": "sysmon"},
		"windows": {"namespace": "microsoft.windows.security", "platform": "windows"},
	}
)

type Error struct{ Message string }

func (e *Error) Error() string                 { return e.Message }
func invalid(format string, args ...any) error { return &Error{Message: fmt.Sprintf(format, args...)} }

type Scope struct {
	Namespace *string `json:"namespace"`
	Platform  *string `json:"platform"`
	Product   *string `json:"product"`
	Provider  *string `json:"provider"`
	Channel   *string `json:"channel"`
}

type Document struct {
	SearchContractVersion string        `json:"search_contract_version,omitempty"`
	TargetID              string        `json:"target_id"`
	EntityType            string        `json:"entity_type"`
	Title                 string        `json:"title"`
	Scope                 Scope         `json:"scope"`
	Lifecycle             *string       `json:"lifecycle"`
	LexicalFields         LexicalFields `json:"lexical_fields,omitempty"`
	ProjectionDigest      string        `json:"projection_digest,omitempty"`
}

type Edge struct {
	SourceID         string `json:"source_id"`
	RelationshipType string `json:"relationship_type"`
	TargetID         string `json:"target_id"`
}

type Bundle struct {
	SearchContractVersion string             `json:"search_contract_version"`
	BuildBinding          BuildBinding       `json:"build_binding"`
	Documents             []Document         `json:"documents"`
	Identifiers           []Identifier       `json:"identifiers"`
	Aliases               []Alias            `json:"aliases"`
	Filters               []FilterProjection `json:"filters"`
	Edges                 []Edge             `json:"edges"`
	BundleDigest          string             `json:"bundle_digest"`
}

type Match struct {
	TargetID     string  `json:"target_id"`
	Title        string  `json:"title"`
	EntityType   string  `json:"entity_type"`
	Scope        Scope   `json:"scope"`
	Lifecycle    *string `json:"lifecycle"`
	MatchedValue string  `json:"matched_value"`
	MatchReason  string  `json:"match_reason"`
}

type Result struct {
	SearchContractVersion string  `json:"search_contract_version"`
	Query                 string  `json:"query"`
	Status                string  `json:"status"`
	MatchStage            string  `json:"match_stage"`
	Matches               []Match `json:"matches"`
}

type CatalogItem struct {
	TargetID   string  `json:"target_id"`
	Title      string  `json:"title"`
	EntityType string  `json:"entity_type"`
	Scope      Scope   `json:"scope"`
	Lifecycle  *string `json:"lifecycle"`
}

type FacetValue struct {
	Value     string `json:"value"`
	ItemCount int64  `json:"item_count"`
}

type NumericIdentifier struct {
	TargetID            string `json:"target_id"`
	Value               string `json:"value"`
	DerivedNumericValue int64  `json:"derived_numeric_value"`
}

type parsedQuery struct {
	normalized string
	terms      []string
	scope      map[string]string
	idType     string
	idValue    string
	hasID      bool
}

func ValidateBundle(bundle *Bundle) error {
	if bundle == nil {
		return errors.New("expected SPC binding is required")
	}
	if bundle.SearchContractVersion != ContractVersion {
		return fmt.Errorf("unsupported search contract version: %q", bundle.SearchContractVersion)
	}
	if bundle.BundleDigest == "" || len(bundle.Documents) == 0 {
		return errors.New("SPC bundle binding is incomplete")
	}
	seen := map[string]struct{}{}
	for _, doc := range bundle.Documents {
		if !strings.HasPrefix(doc.TargetID, "atlas:") {
			return fmt.Errorf("invalid projected target_id: %q", doc.TargetID)
		}
		if _, exists := seen[doc.TargetID]; exists {
			return fmt.Errorf("duplicate projected target_id: %s", doc.TargetID)
		}
		seen[doc.TargetID] = struct{}{}
	}
	for _, row := range bundle.Identifiers {
		if _, ok := seen[row.TargetID]; !ok {
			return fmt.Errorf("identifier references missing target: %s", row.TargetID)
		}
	}
	for _, row := range bundle.Aliases {
		if _, ok := seen[row.TargetID]; !ok {
			return fmt.Errorf("alias references missing target: %s", row.TargetID)
		}
	}
	for _, row := range bundle.Filters {
		if _, ok := seen[row.TargetID]; !ok {
			return fmt.Errorf("filter references missing target: %s", row.TargetID)
		}
	}
	return nil
}

func fold(value string) string { return caseFolder.String(norm.NFKC.String(value)) }
