package protocol

import (
	"bytes"
	"encoding/json"
	"testing"
)

type testOperations struct{}

func (testOperations) Handle(method string, params json.RawMessage) (any, *OperationError) {
	if method == "pack.status" {
		return map[string]any{"ready": false}, nil
	}
	return nil, &OperationError{Code: CodePackNotReady, Message: "not ready"}
}

func TestOperationalAllowlistAfterHandshake(t *testing.T) {
	input := &bytes.Buffer{}
	writeRequest(t, input, `{"id":"h","method":"core.handshake","params":{"protocol":"atlas-core","version":"1.0.0","client_name":"test","client_version":"1","session_nonce":"n"}}`)
	writeRequest(t, input, `{"id":"p","method":"pack.status","params":{}}`)
	writeRequest(t, input, `{"id":"u","method":"pack.update","params":{}}`)
	writeRequest(t, input, `{"id":"r","method":"pack.rollback","params":{}}`)
	writeRequest(t, input, `{"id":"x","method":"shell.exec","params":{}}`)
	output := &bytes.Buffer{}
	server := Server{Build: BuildInfo{Version: "v", Commit: "c"}, Operations: testOperations{}}
	if err := server.Serve(input, output); err != nil {
		t.Fatal(err)
	}
	handshake := readResponse(t, output)
	if !handshake.OK {
		t.Fatalf("handshake failed: %+v", handshake)
	}
	body := handshake.Result.(map[string]any)
	capabilities := body["capabilities"].([]any)
	if len(capabilities) != 9 {
		t.Fatalf("expected nine compiled capabilities, got %#v", capabilities)
	}
	pack := readResponse(t, output)
	if !pack.OK {
		t.Fatalf("pack.status failed: %+v", pack)
	}
	for _, method := range []string{"pack.update", "pack.rollback"} {
		response := readResponse(t, output)
		if response.OK || response.Error == nil || response.Error.Code != CodePackNotReady {
			t.Fatalf("%s was not forwarded through the operational allowlist: %+v", method, response)
		}
	}
	unknown := readResponse(t, output)
	if unknown.OK || unknown.Error == nil || unknown.Error.Code != CodeMethodNotFound {
		t.Fatalf("non-allowlisted method must fail: %+v", unknown)
	}
}
