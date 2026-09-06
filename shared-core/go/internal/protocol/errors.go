package protocol

const (
	ProtocolName    = "atlas-core"
	ProtocolVersion = "1.0.0"

	CodeInvalidFrame       = "ATLAS_PROTOCOL_INVALID_FRAME"
	CodeUnsupportedVersion = "ATLAS_PROTOCOL_UNSUPPORTED_VERSION"
	CodeHandshakeRequired  = "ATLAS_PROTOCOL_HANDSHAKE_REQUIRED"
	CodeInvalidRequest     = "ATLAS_PROTOCOL_INVALID_REQUEST"
	CodeMethodNotFound     = "ATLAS_METHOD_NOT_FOUND"
	CodeInternalError      = "ATLAS_INTERNAL_FAILURE"
)

type ErrorBody struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

type Response struct {
	ID     string     `json:"id"`
	OK     bool       `json:"ok"`
	Result any        `json:"result,omitempty"`
	Error  *ErrorBody `json:"error,omitempty"`
}

func success(id string, result any) Response {
	return Response{ID: id, OK: true, Result: result}
}

func failure(id, code, message string) Response {
	return Response{ID: id, OK: false, Error: &ErrorBody{Code: code, Message: message, Retryable: false}}
}
