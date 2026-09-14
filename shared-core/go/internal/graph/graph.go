package graph

import (
	"errors"
	"fmt"
	"sort"

	"github.com/cyber-sentinel/Cyber-Sentinel-Atlas/shared-core/go/internal/search"
)

const (
	MaxSeeds             = 20
	MaxResults           = 100
	MaxEdges             = 100000
	MaxRelationshipTypes = 32
)

var registeredRelationshipTypes = map[string]struct{}{
	"RUNS_ON": {}, "EMITS": {}, "HAS_FIELD": {}, "INDICATES": {}, "RELATED_TO": {}, "EQUIVALENT_SIGNAL": {},
	"PRECEDES": {}, "FOLLOWS": {}, "MAPS_TO_ATTACK": {}, "COUNTERED_BY": {}, "DETECTED_BY": {}, "HUNTED_BY": {},
	"INVESTIGATED_BY": {}, "RESPONDED_BY": {}, "REQUIRES_TELEMETRY": {}, "DERIVED_FROM": {}, "SUPPORTED_BY": {},
	"SUPERSEDES": {}, "SUPERSEDED_BY": {}, "VERSION_OF": {}, "VALIDATED_BY": {}, "HAS_TELEMETRY_PROVIDER": {}, "HAS_TELEMETRY_SOURCE": {},
}

var defaultRelationshipTypes = map[string]struct{}{
	"RELATED_TO": {}, "EQUIVALENT_SIGNAL": {}, "SUPERSEDES": {}, "SUPERSEDED_BY": {}, "VERSION_OF": {},
	"MAPS_TO_ATTACK": {}, "COUNTERED_BY": {}, "DETECTED_BY": {}, "HUNTED_BY": {}, "INVESTIGATED_BY": {},
	"RESPONDED_BY": {}, "REQUIRES_TELEMETRY": {}, "HAS_TELEMETRY_PROVIDER": {}, "HAS_TELEMETRY_SOURCE": {},
}

type Pivot struct {
	TargetID         string `json:"target_id"`
	Title            string `json:"title"`
	EntityType       string `json:"entity_type"`
	Depth            int    `json:"depth"`
	ViaID            string `json:"via_id"`
	RelationshipType string `json:"relationship_type"`
	Direction        string `json:"direction"`
}

type Runtime struct {
	documents map[string]search.Document
	outgoing  map[string][]search.Edge
	incoming  map[string][]search.Edge
}

func New(bundle *search.Bundle) (*Runtime, error) {
	if bundle == nil {
		return nil, errors.New("graph runtime requires an SPC bundle")
	}
	if len(bundle.Edges) > MaxEdges {
		return nil, fmt.Errorf("edge projection exceeds %d rows", MaxEdges)
	}
	runtime := &Runtime{
		documents: make(map[string]search.Document, len(bundle.Documents)),
		outgoing:  map[string][]search.Edge{},
		incoming:  map[string][]search.Edge{},
	}
	for _, doc := range bundle.Documents {
		runtime.documents[doc.TargetID] = doc
	}
	seen := map[[3]string]struct{}{}
	previous := [3]string{}
	for index, edge := range bundle.Edges {
		if _, ok := runtime.documents[edge.SourceID]; !ok {
			return nil, errors.New("EdgeProjection references a missing SearchDocument")
		}
		if _, ok := runtime.documents[edge.TargetID]; !ok {
			return nil, errors.New("EdgeProjection references a missing SearchDocument")
		}
		if _, ok := registeredRelationshipTypes[edge.RelationshipType]; !ok {
			return nil, fmt.Errorf("unregistered relationship type: %s", edge.RelationshipType)
		}
		identity := [3]string{edge.SourceID, edge.RelationshipType, edge.TargetID}
		if _, ok := seen[identity]; ok {
			return nil, errors.New("duplicate EdgeProjection")
		}
		if index > 0 && !lessTriple(previous, identity) {
			return nil, errors.New("EdgeProjection rows must be deterministically sorted")
		}
		seen[identity] = struct{}{}
		previous = identity
		runtime.outgoing[edge.SourceID] = append(runtime.outgoing[edge.SourceID], edge)
		runtime.incoming[edge.TargetID] = append(runtime.incoming[edge.TargetID], edge)
	}
	for _, adjacency := range []map[string][]search.Edge{runtime.outgoing, runtime.incoming} {
		for id := range adjacency {
			sort.Slice(adjacency[id], func(i, j int) bool {
				left, right := adjacency[id][i], adjacency[id][j]
				if left.RelationshipType != right.RelationshipType {
					return left.RelationshipType < right.RelationshipType
				}
				if left.SourceID != right.SourceID {
					return left.SourceID < right.SourceID
				}
				return left.TargetID < right.TargetID
			})
		}
	}
	return runtime, nil
}

func (r *Runtime) Expand(seedIDs []string, depth int, allowedRelationshipTypes []string, direction string, limit int) ([]Pivot, error) {
	if len(seedIDs) < 1 || len(seedIDs) > MaxSeeds {
		return nil, fmt.Errorf("graph seed count must be between 1 and %d", MaxSeeds)
	}
	if depth < 0 || depth > search.MaxGraphDepth {
		return nil, fmt.Errorf("graph depth must be between 0 and %d", search.MaxGraphDepth)
	}
	if limit < 1 || limit > MaxResults {
		return nil, fmt.Errorf("graph limit must be between 1 and %d", MaxResults)
	}
	if direction != "outgoing" && direction != "incoming" && direction != "both" {
		return nil, errors.New("graph direction must be outgoing, incoming, or both")
	}
	seeds := uniqueSorted(seedIDs)
	for _, seed := range seeds {
		if _, ok := r.documents[seed]; !ok {
			return nil, errors.New("graph seed is not present in the active SPC")
		}
	}
	allowed := map[string]struct{}{}
	if allowedRelationshipTypes == nil {
		for relationshipType := range defaultRelationshipTypes {
			allowed[relationshipType] = struct{}{}
		}
	} else {
		if len(allowedRelationshipTypes) == 0 || len(allowedRelationshipTypes) > MaxRelationshipTypes {
			return nil, errors.New("invalid allowed relationship-type set")
		}
		for _, relationshipType := range allowedRelationshipTypes {
			if _, ok := registeredRelationshipTypes[relationshipType]; !ok {
				return nil, fmt.Errorf("unregistered graph relationship type: %s", relationshipType)
			}
			allowed[relationshipType] = struct{}{}
		}
	}
	if len(allowed) == 0 {
		return nil, errors.New("invalid allowed relationship-type set")
	}
	if depth == 0 {
		return []Pivot{}, nil
	}

	type queueItem struct {
		id    string
		depth int
	}
	type candidate struct {
		neighbor  string
		edge      search.Edge
		direction string
	}
	visited := map[string]struct{}{}
	queue := make([]queueItem, 0, len(seeds))
	for _, seed := range seeds {
		visited[seed] = struct{}{}
		queue = append(queue, queueItem{id: seed})
	}
	out := make([]Pivot, 0)
	for len(queue) > 0 && len(out) < limit {
		current := queue[0]
		queue = queue[1:]
		if current.depth >= depth {
			continue
		}
		candidates := make([]candidate, 0)
		if direction == "outgoing" || direction == "both" {
			for _, edge := range r.outgoing[current.id] {
				candidates = append(candidates, candidate{neighbor: edge.TargetID, edge: edge, direction: "outgoing"})
			}
		}
		if direction == "incoming" || direction == "both" {
			for _, edge := range r.incoming[current.id] {
				candidates = append(candidates, candidate{neighbor: edge.SourceID, edge: edge, direction: "incoming"})
			}
		}
		sort.Slice(candidates, func(i, j int) bool {
			left, right := candidates[i], candidates[j]
			if left.edge.RelationshipType != right.edge.RelationshipType {
				return left.edge.RelationshipType < right.edge.RelationshipType
			}
			if left.direction != right.direction {
				return left.direction < right.direction
			}
			if left.neighbor != right.neighbor {
				return left.neighbor < right.neighbor
			}
			if left.edge.SourceID != right.edge.SourceID {
				return left.edge.SourceID < right.edge.SourceID
			}
			return left.edge.TargetID < right.edge.TargetID
		})
		for _, candidate := range candidates {
			if _, ok := allowed[candidate.edge.RelationshipType]; !ok {
				continue
			}
			if _, ok := visited[candidate.neighbor]; ok {
				continue
			}
			visited[candidate.neighbor] = struct{}{}
			nextDepth := current.depth + 1
			doc := r.documents[candidate.neighbor]
			out = append(out, Pivot{
				TargetID: candidate.neighbor, Title: doc.Title, EntityType: doc.EntityType,
				Depth: nextDepth, ViaID: current.id, RelationshipType: candidate.edge.RelationshipType, Direction: candidate.direction,
			})
			if len(out) >= limit {
				break
			}
			queue = append(queue, queueItem{id: candidate.neighbor, depth: nextDepth})
		}
	}
	return out, nil
}

func uniqueSorted(values []string) []string {
	set := map[string]struct{}{}
	for _, value := range values {
		set[value] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func lessTriple(left, right [3]string) bool {
	for i := range left {
		if left[i] != right[i] {
			return left[i] < right[i]
		}
	}
	return false
}
