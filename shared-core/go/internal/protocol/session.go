package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

const (
	MaxClientFieldRunes = 128
	MaxNonceRunes       = 256
)

var coreCapabilities = []string{"core.handshake", "core.status"}
var operationalCapabilities = []string{"search.query", "record.get", "catalog.list", "graph.expand", "pack.status", "pack.update", "pack.rollback"}
var operationalAllowlist = map[string]struct{}{
	"search.query": {}, "record.get": {}, "catalog.list": {}, "graph.expand": {}, "pack.status": {},
	"pack.update": {}, "pack.rollback": {},
}

type BuildInfo struct {
	Version string
	Commit  string
}

type OperationHandler interface {
	Handle(method string, params json.RawMessage) (any, *OperationError)
}

type Server struct {
	Build      BuildInfo
	Operations OperationHandler
}

type sessionState struct {
	handshakeComplete bool
	sessionNonce      string
}

type handshakeParams struct {
	Protocol      string `json:"protocol"`
	Version       string `json:"version"`
	ClientName    string `json:"client_name"`
	ClientVersion string `json:"client_version"`
	SessionNonce  string `json:"session_nonce"`
}

type handshakeResult struct {
	Protocol     string   `json:"protocol"`
	Version      string   `json:"version"`
	CoreVersion  string   `json:"core_version"`
	CoreCommit   string   `json:"core_commit"`
	SessionNonce string   `json:"session_nonce"`
	Capabilities []string `json:"capabilities"`
}

type statusResult struct {
	Protocol        string   `json:"protocol"`
	Version         string   `json:"version"`
	CoreVersion     string   `json:"core_version"`
	CoreCommit      string   `json:"core_commit"`
	Capabilities    []string `json:"capabilities"`
	OfflineCapable  bool     `json:"offline_capable"`
	NetworkListener bool     `json:"network_listener"`
}

type emptyParams struct{}

func (s Server) capabilities() []string {
	out := append([]string(nil), coreCapabilities...)
	if s.Operations != nil {
		out = append(out, operationalCapabilities...)
	}
	return out
}

func (s Server) Serve(in io.Reader, out io.Writer) error {
	state := &sessionState{}
	for {
		payload, err := ReadFrame(in, MaxRequestPayload)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("fatal protocol framing error: %w", err)
		}

		resp := s.handle(payload, state)
		encoded, err := json.Marshal(resp)
		if err != nil {
			return fmt.Errorf("encode protocol response: %w", err)
		}
		if err := WriteFrame(out, encoded, MaxResponsePayload); err != nil {
			return fmt.Errorf("write protocol response: %w", err)
		}
	}
}

func (s Server) handle(payload []byte, state *sessionState) Response {
	req, err := DecodeRequest(payload)
	if err != nil {
		return failure("", CodeInvalidRequest, "request failed strict protocol validation")
	}

	if !state.handshakeComplete {
		if req.Method != "core.handshake" {
			return failure(req.ID, CodeHandshakeRequired, "core.handshake must complete before operational methods")
		}
		return s.handleHandshake(req, state)
	}

	switch req.Method {
	case "core.handshake":
		return failure(req.ID, CodeInvalidRequest, "core.handshake may only occur once per child process")
	case "core.status":
		var params emptyParams
		if err := DecodeStrictParams(req.Params, &params); err != nil {
			return failure(req.ID, CodeInvalidRequest, "core.status params must be an empty object")
		}
		return success(req.ID, statusResult{
			Protocol:        ProtocolName,
			Version:         ProtocolVersion,
			CoreVersion:     safeBuildField(s.Build.Version, "dev"),
			CoreCommit:      safeBuildField(s.Build.Commit, "unknown"),
			Capabilities:    s.capabilities(),
			OfflineCapable:  true,
			NetworkListener: false,
		})
	default:
		if _, ok := operationalAllowlist[req.Method]; !ok || s.Operations == nil {
			return failure(req.ID, CodeMethodNotFound, "method is not available in this core build")
		}
		result, operationError := s.Operations.Handle(req.Method, req.Params)
		if operationError != nil {
			return failureWithRetry(req.ID, operationError.Code, operationError.Message, operationError.Retryable)
		}
		return success(req.ID, result)
	}
}

func (s Server) handleHandshake(req Request, state *sessionState) Response {
	var params handshakeParams
	if err := DecodeStrictParams(req.Params, &params); err != nil {
		return failure(req.ID, CodeInvalidRequest, "invalid core.handshake params")
	}
	if params.Protocol != ProtocolName || params.Version != ProtocolVersion {
		return failure(req.ID, CodeUnsupportedVersion, "exact atlas-core protocol 1.0.0 is required")
	}
	if !boundedNonEmpty(params.ClientName, MaxClientFieldRunes) ||
		!boundedNonEmpty(params.ClientVersion, MaxClientFieldRunes) ||
		!boundedNonEmpty(params.SessionNonce, MaxNonceRunes) {
		return failure(req.ID, CodeInvalidRequest, "handshake string field violates protocol bounds")
	}

	state.handshakeComplete = true
	state.sessionNonce = params.SessionNonce
	return success(req.ID, handshakeResult{
		Protocol:     ProtocolName,
		Version:      ProtocolVersion,
		CoreVersion:  safeBuildField(s.Build.Version, "dev"),
		CoreCommit:   safeBuildField(s.Build.Commit, "unknown"),
		SessionNonce: params.SessionNonce,
		Capabilities: s.capabilities(),
	})
}

func boundedNonEmpty(s string, max int) bool {
	return s != "" && utf8.ValidString(s) && utf8.RuneCountInString(s) <= max
}

func safeBuildField(value, fallback string) string {
	if value == "" || !utf8.ValidString(value) || utf8.RuneCountInString(value) > MaxClientFieldRunes {
		return fallback
	}
	return value
}
