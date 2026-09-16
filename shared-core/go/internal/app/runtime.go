package app

import (
	"encoding/json"
	"errors"

	"github.com/cyber-sentinel/Cyber-Sentinel-Atlas/shared-core/go/internal/canonical"
	"github.com/cyber-sentinel/Cyber-Sentinel-Atlas/shared-core/go/internal/graph"
	"github.com/cyber-sentinel/Cyber-Sentinel-Atlas/shared-core/go/internal/pack"
	"github.com/cyber-sentinel/Cyber-Sentinel-Atlas/shared-core/go/internal/protocol"
	"github.com/cyber-sentinel/Cyber-Sentinel-Atlas/shared-core/go/internal/search"
)

type Runtime struct {
	Canonical      *canonical.Store
	Search         *search.Core
	Graph          *graph.Runtime
	GenerationID   string
	PackID         string
	PackVersion    string
	ManifestDigest string
	RuntimeRoot    string
}

func NewUnconfigured() *Runtime { return &Runtime{} }

func NewUnconfiguredAt(runtimeRoot string) *Runtime { return &Runtime{RuntimeRoot: runtimeRoot} }

func New(store *canonical.Store, searchCore *search.Core, graphRuntime *graph.Runtime) *Runtime {
	return &Runtime{Canonical: store, Search: searchCore, Graph: graphRuntime}
}

// NewFromRuntimeRoot binds the process to the single active verified pack
// generation selected by durable runtime state. It never selects another
// generation when the active pointer is corrupt or unhealthy.
func NewFromRuntimeRoot(runtimeRoot string) (*Runtime, error) {
	model, err := pack.LoadActiveReadModel(runtimeRoot)
	if err != nil {
		return nil, err
	}
	graphRuntime, err := graph.New(&model.Bundle)
	if err != nil {
		_ = model.Close()
		return nil, err
	}
	return &Runtime{
		Canonical:      model.Canonical,
		Search:         model.Search,
		Graph:          graphRuntime,
		GenerationID:   model.GenerationID,
		PackID:         model.PackID,
		PackVersion:    model.PackVersion,
		ManifestDigest: model.ManifestDigest,
		RuntimeRoot:    runtimeRoot,
	}, nil
}

func (r *Runtime) Close() error {
	if r == nil || r.Search == nil {
		return nil
	}
	err := r.Search.Close()
	r.Search = nil
	return err
}

func (r *Runtime) invalidateReadModel() {
	if r == nil {
		return
	}
	if r.Search != nil {
		_ = r.Search.Close()
	}
	r.Canonical = nil
	r.Search = nil
	r.Graph = nil
	r.GenerationID = ""
	r.PackID = ""
	r.PackVersion = ""
	r.ManifestDigest = ""
}

func (r *Runtime) replaceReadModel(next *Runtime) {
	if r == nil || next == nil {
		return
	}
	oldSearch := r.Search
	r.Canonical = next.Canonical
	r.Search = next.Search
	r.Graph = next.Graph
	r.GenerationID = next.GenerationID
	r.PackID = next.PackID
	r.PackVersion = next.PackVersion
	r.ManifestDigest = next.ManifestDigest
	if next.RuntimeRoot != "" {
		r.RuntimeRoot = next.RuntimeRoot
	}
	next.Search = nil
	if oldSearch != nil {
		_ = oldSearch.Close()
	}
}

func (r *Runtime) reloadActive() error {
	if r == nil || r.RuntimeRoot == "" {
		return errors.New("pack control runtime is unavailable")
	}
	next, err := NewFromRuntimeRoot(r.RuntimeRoot)
	if err != nil {
		return err
	}
	r.replaceReadModel(next)
	return nil
}

type searchParams struct {
	Query      string `json:"query"`
	GraphDepth *int   `json:"graph_depth,omitempty"`
	Limit      *int   `json:"limit,omitempty"`
}

type recordParams struct {
	ID string `json:"id"`
}

type catalogParams struct {
	Filters map[string]string `json:"filters,omitempty"`
	Facet   string            `json:"facet,omitempty"`
	Limit   *int              `json:"limit,omitempty"`
}

type graphParams struct {
	SeedIDs                  []string `json:"seed_ids"`
	Depth                    *int     `json:"depth,omitempty"`
	AllowedRelationshipTypes []string `json:"allowed_relationship_types,omitempty"`
	Direction                string   `json:"direction,omitempty"`
	Limit                    *int     `json:"limit,omitempty"`
}

type emptyParams struct{}

func (r *Runtime) Handle(method string, raw json.RawMessage) (any, *protocol.OperationError) {
	switch method {
	case "pack.status":
		var params emptyParams
		if err := protocol.DecodeStrictParams(raw, &params); err != nil {
			return nil, invalidRequest("pack.status params must be an empty object")
		}
		ready := r != nil && r.Canonical != nil && r.Search != nil && r.Graph != nil
		state := "pack_runtime_not_activated"
		if ready {
			state = "read_model_ready"
		}
		result := map[string]any{"ready": ready, "state": state, "phase": "5.6.2"}
		if ready && r.GenerationID != "" {
			result["generation_id"] = r.GenerationID
			result["pack_id"] = r.PackID
			result["pack_version"] = r.PackVersion
			result["manifest_digest"] = r.ManifestDigest
		}
		if r != nil && r.RuntimeRoot != "" {
			control, err := pack.ControlState(r.RuntimeRoot)
			if err != nil {
				return nil, &protocol.OperationError{Code: protocol.CodeStateFailure, Message: "pack control state is unavailable"}
			}
			result["pending_update"] = control.PendingUpdate
			result["rollback_available"] = control.RollbackAvailable
			if control.RollbackTarget != nil {
				result["rollback_target"] = control.RollbackTarget
			}
		}
		return result, nil
	case "pack.update":
		var params emptyParams
		if err := protocol.DecodeStrictParams(raw, &params); err != nil {
			return nil, invalidRequest("pack.update params must be an empty object")
		}
		if r == nil || r.RuntimeRoot == "" {
			return nil, packControlUnavailable()
		}
		result, err := pack.ApplyPendingUpdate(r.RuntimeRoot)
		if err != nil {
			return nil, classifyPackControl(err)
		}
		if err := r.reloadActive(); err != nil {
			if _, rollbackErr := pack.RollbackPrevious(r.RuntimeRoot); rollbackErr == nil {
				if restoreErr := r.reloadActive(); restoreErr == nil {
					return nil, &protocol.OperationError{Code: protocol.CodeStateFailure, Message: "verified update could not be activated in-process; previous read model restored"}
				}
			}
			r.invalidateReadModel()
			return nil, &protocol.OperationError{Code: protocol.CodeStateFailure, Message: "verified update activated durably but in-process read model recovery failed"}
		}
		return result, nil
	case "pack.rollback":
		var params emptyParams
		if err := protocol.DecodeStrictParams(raw, &params); err != nil {
			return nil, invalidRequest("pack.rollback params must be an empty object")
		}
		if r == nil || r.RuntimeRoot == "" {
			return nil, packControlUnavailable()
		}
		result, err := pack.RollbackPrevious(r.RuntimeRoot)
		if err != nil {
			return nil, classifyPackControl(err)
		}
		if err := r.reloadActive(); err != nil {
			if _, restoreErr := pack.RollbackPrevious(r.RuntimeRoot); restoreErr == nil {
				if reloadErr := r.reloadActive(); reloadErr == nil {
					return nil, &protocol.OperationError{Code: protocol.CodeStateFailure, Message: "rollback target could not be activated in-process; previous read model restored"}
				}
			}
			r.invalidateReadModel()
			return nil, &protocol.OperationError{Code: protocol.CodeStateFailure, Message: "rollback changed durable state but in-process read model recovery failed"}
		}
		return result, nil
	case "search.query":
		if r == nil || r.Search == nil {
			return nil, packNotReady()
		}
		var params searchParams
		if err := protocol.DecodeStrictParams(raw, &params); err != nil || params.Query == "" {
			return nil, invalidRequest("invalid search.query params")
		}
		depth, limit := 1, search.DefaultTopK
		if params.GraphDepth != nil {
			depth = *params.GraphDepth
		}
		if params.Limit != nil {
			limit = *params.Limit
		}
		result, err := r.Search.Resolve(params.Query, depth, limit)
		if err != nil {
			return nil, classifyQuery(err)
		}
		return result, nil
	case "record.get":
		if r == nil || r.Canonical == nil {
			return nil, packNotReady()
		}
		var params recordParams
		if err := protocol.DecodeStrictParams(raw, &params); err != nil || params.ID == "" {
			return nil, invalidRequest("invalid record.get params")
		}
		record, ok := r.Canonical.Get(params.ID)
		if !ok {
			return nil, &protocol.OperationError{Code: protocol.CodeRecordNotFound, Message: "canonical record not found"}
		}
		return record, nil
	case "catalog.list":
		if r == nil || r.Search == nil {
			return nil, packNotReady()
		}
		var params catalogParams
		if err := protocol.DecodeStrictParams(raw, &params); err != nil {
			return nil, invalidRequest("invalid catalog.list params")
		}
		limit := search.DefaultTopK
		if params.Limit != nil {
			limit = *params.Limit
		}
		if params.Facet != "" {
			values, err := r.Search.FacetValues(params.Facet, params.Filters, limit)
			if err != nil {
				return nil, classifyQuery(err)
			}
			return map[string]any{"facet": params.Facet, "values": values}, nil
		}
		items, err := r.Search.Browse(params.Filters, limit)
		if err != nil {
			return nil, classifyQuery(err)
		}
		return map[string]any{"items": items}, nil
	case "graph.expand":
		if r == nil || r.Graph == nil {
			return nil, packNotReady()
		}
		var params graphParams
		if err := protocol.DecodeStrictParams(raw, &params); err != nil {
			return nil, invalidRequest("invalid graph.expand params")
		}
		depth, limit, direction := 1, graph.MaxResults, "both"
		if params.Depth != nil {
			depth = *params.Depth
		}
		if params.Limit != nil {
			limit = *params.Limit
		}
		if params.Direction != "" {
			direction = params.Direction
		}
		pivots, err := r.Graph.Expand(params.SeedIDs, depth, params.AllowedRelationshipTypes, direction, limit)
		if err != nil {
			return nil, &protocol.OperationError{Code: protocol.CodeQueryInvalid, Message: "invalid bounded graph request"}
		}
		return map[string]any{"pivots": pivots}, nil
	default:
		return nil, &protocol.OperationError{Code: protocol.CodeMethodNotFound, Message: "method is not available in this core build"}
	}
}

func invalidRequest(message string) *protocol.OperationError {
	return &protocol.OperationError{Code: protocol.CodeInvalidRequest, Message: message}
}

func packNotReady() *protocol.OperationError {
	return &protocol.OperationError{Code: protocol.CodePackNotReady, Message: "verified pack read model is not activated"}
}

func packControlUnavailable() *protocol.OperationError {
	return &protocol.OperationError{Code: protocol.CodeStateFailure, Message: "pack control runtime is unavailable"}
}

func classifyPackControl(err error) *protocol.OperationError {
	if errors.Is(err, pack.ErrPackControlTrust) {
		return &protocol.OperationError{Code: protocol.CodePackTrustFailure, Message: "pack update failed trust verification"}
	}
	if errors.Is(err, pack.ErrNoPendingUpdate) {
		return &protocol.OperationError{Code: protocol.CodeStateFailure, Message: "no verified pack update is pending"}
	}
	if errors.Is(err, pack.ErrNoRollbackTarget) {
		return &protocol.OperationError{Code: protocol.CodeStateFailure, Message: "no safe manual rollback target is available"}
	}
	return &protocol.OperationError{Code: protocol.CodeStateFailure, Message: "pack control operation failed"}
}

func classifyQuery(err error) *protocol.OperationError {
	var queryError *search.Error
	if errors.As(err, &queryError) {
		return &protocol.OperationError{Code: protocol.CodeQueryInvalid, Message: "invalid bounded query"}
	}
	return &protocol.OperationError{Code: protocol.CodeInternalError, Message: "shared core read operation failed"}
}
