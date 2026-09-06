package protocol

const (
	ProtocolName    = "atlas-core"
	ProtocolVersion = "1.0.0"

	CodeInvalidRequest     = "INVALID_REQUEST"
	CodeHandshakeRequired  = "HANDSHAKE_REQUIRED"
	CodeUnsupportedVersion = "UNSUPPORTED_VERSION"
	CodeMethodNotFound     = "METHOD_NOT_FOUND"
	CodeInternalError      = "INTERNAL_ERROR"
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
