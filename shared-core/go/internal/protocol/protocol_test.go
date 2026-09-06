package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestFrameBoundsAndTruncation(t *testing.T) {
	var header [4]byte

	binary.BigEndian.PutUint32(header[:], 0)
	if _, err := ReadFrame(bytes.NewReader(header[:]), MaxRequestPayload); !errors.Is(err, ErrZeroLengthFrame) {
		t.Fatalf("zero-length frame: got %v", err)
	}

	binary.BigEndian.PutUint32(header[:], MaxRequestPayload+1)
	if _, err := ReadFrame(bytes.NewReader(header[:]), MaxRequestPayload); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("oversized frame: got %v", err)
	}

	if _, err := ReadFrame(bytes.NewReader([]byte{0, 0}), MaxRequestPayload); err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("partial header must be fatal, got %v", err)
	}

	binary.BigEndian.PutUint32(header[:], 5)
	truncated := append(header[:], []byte("ab")...)
	if _, err := ReadFrame(bytes.NewReader(truncated), MaxRequestPayload); err == nil {
		t.Fatal("partial payload must be fatal")
	}

	if _, err := ReadFrame(bytes.NewReader(nil), MaxRequestPayload); !errors.Is(err, io.EOF) {
		t.Fatalf("clean EOF: got %v", err)
	}
}

func TestStrictJSONProfile(t *testing.T) {
	valid32 := strings.Repeat("[", 32) + "0" + strings.Repeat("]", 32)
	if err := ValidateJSON([]byte(valid32)); err != nil {
		t.Fatalf("depth 32 should pass: %v", err)
	}
	invalid33 := strings.Repeat("[", 33) + "0" + strings.Repeat("]", 33)
	if err := ValidateJSON([]byte(invalid33)); !errors.Is(err, ErrJSONDepth) {
		t.Fatalf("depth 33 should fail with ErrJSONDepth, got %v", err)
	}

	cases := []struct {
		name string
		data []byte
		want error
	}{
		{"duplicate envelope", []byte(`{"id":"1"}`), ErrDuplicateKey},
		{"duplicate nested", []byte(`{"id":"1"}`), ErrDuplicateKey},
		{"bom", append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{"x":1}`)...), ErrUTF8BOM},
		{"invalid utf8", []byte{0xff, 0xfe}, ErrInvalidUTF8},
		{"trailing value", []byte(`{"x":1} {"y":2}`), ErrTrailingJSON},
	}
	// Replace escaped literals above with byte strings to make the intended duplicate
	// fixtures visually unambiguous to gofmt and reviewers.
	cases[0].data = []byte("{\"id\":\"1\",\"id\":\"2\",\"method\":\"x\",\"params\":{}}")
	cases[1].data = []byte("{\"id\":\"1\",\"method\":\"x\",\"params\":{\"a\":{\"k\":1,\"k\":2}}}")
	cases[2].data = append([]byte{0xEF, 0xBB, 0xBF}, []byte("{\"x\":1}")...)
	cases[4].data = []byte("{\"x\":1} {\"y\":2}")

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateJSON(tc.data); !errors.Is(err, tc.want) {
				t.Fatalf("wanted %v, got %v", tc.want, err)
			}
		})
	}
}

func TestDecodeRequestEnvelopeBounds(t *testing.T) {
	if _, err := DecodeRequest([]byte("{\"id\":\"1\",\"method\":\"core.status\",\"params\":{},\"extra\":true}")); err == nil {
		t.Fatal("unknown envelope field must fail")
	}
	if _, err := DecodeRequest([]byte("{\"id\":\"1\",\"method\":\"core.status\",\"params\":null}")); err == nil {
		t.Fatal("params must be an object")
	}
	longID := strings.Repeat("x", MaxIDRunes+1)
	raw, _ := json.Marshal(map[string]any{"id": longID, "method": "core.status", "params": map[string]any{}})
	if _, err := DecodeRequest(raw); err == nil {
		t.Fatal("overlong request id must fail")
	}
}

func TestSessionHandshakeAndStatus(t *testing.T) {
	input := &bytes.Buffer{}
	writeRequest(t, input, "{\"id\":\"h1\",\"method\":\"core.handshake\",\"params\":{\"protocol\":\"atlas-core\",\"version\":\"1.0.0\",\"client_name\":\"test\",\"client_version\":\"1\",\"session_nonce\":\"nonce-1\"}}")
	writeRequest(t, input, "{\"id\":\"s1\",\"method\":\"core.status\",\"params\":{}}")

	output := &bytes.Buffer{}
	server := Server{Build: BuildInfo{Version: "test-version", Commit: "abc123"}}
	if err := server.Serve(input, output); err != nil {
		t.Fatalf("serve: %v", err)
	}

	handshake := readResponse(t, output)
	if !handshake.OK || handshake.ID != "h1" {
		t.Fatalf("unexpected handshake response: %+v", handshake)
	}
	result, ok := handshake.Result.(map[string]any)
	if !ok || result["session_nonce"] != "nonce-1" || result["protocol"] != ProtocolName {
		t.Fatalf("unexpected handshake result: %#v", handshake.Result)
	}

	status := readResponse(t, output)
	if !status.OK || status.ID != "s1" {
		t.Fatalf("unexpected status response: %+v", status)
	}
	statusResult, ok := status.Result.(map[string]any)
	if !ok || statusResult["network_listener"] != false || statusResult["offline_capable"] != true {
		t.Fatalf("unexpected status result: %#v", status.Result)
	}
	if output.Len() != 0 {
		t.Fatal("unexpected bytes after framed responses")
	}
}

func TestSessionEnforcesHandshakeAndMethodAllowlist(t *testing.T) {
	server := Server{Build: BuildInfo{Version: "v", Commit: "c"}}

	before := runSingleRequest(t, server, "{\"id\":\"1\",\"method\":\"core.status\",\"params\":{}}")
	if before.OK || before.Error == nil || before.Error.Code != CodeHandshakeRequired {
		t.Fatalf("expected handshake requirement, got %+v", before)
	}

	badVersion := runSingleRequest(t, server, "{\"id\":\"1\",\"method\":\"core.handshake\",\"params\":{\"protocol\":\"atlas-core\",\"version\":\"0.9.0\",\"client_name\":\"test\",\"client_version\":\"1\",\"session_nonce\":\"n\"}}")
	if badVersion.OK || badVersion.Error == nil || badVersion.Error.Code != CodeUnsupportedVersion {
		t.Fatalf("expected unsupported version, got %+v", badVersion)
	}

	input := &bytes.Buffer{}
	writeRequest(t, input, "{\"id\":\"h\",\"method\":\"core.handshake\",\"params\":{\"protocol\":\"atlas-core\",\"version\":\"1.0.0\",\"client_name\":\"test\",\"client_version\":\"1\",\"session_nonce\":\"n\"}}")
	writeRequest(t, input, "{\"id\":\"x\",\"method\":\"shell.exec\",\"params\":{\"command\":\"whoami\"}}")
	writeRequest(t, input, "{\"id\":\"h2\",\"method\":\"core.handshake\",\"params\":{\"protocol\":\"atlas-core\",\"version\":\"1.0.0\",\"client_name\":\"test\",\"client_version\":\"1\",\"session_nonce\":\"n2\"}}")
	output := &bytes.Buffer{}
	if err := server.Serve(input, output); err != nil {
		t.Fatalf("serve: %v", err)
	}
	_ = readResponse(t, output)
	unknown := readResponse(t, output)
	if unknown.OK || unknown.Error == nil || unknown.Error.Code != CodeMethodNotFound {
		t.Fatalf("expected method-not-found, got %+v", unknown)
	}
	repeat := readResponse(t, output)
	if repeat.OK || repeat.Error == nil || repeat.Error.Code != CodeInvalidRequest {
		t.Fatalf("repeated handshake must fail, got %+v", repeat)
	}
}

func TestSessionRejectsMalformedRequestWithoutPanicking(t *testing.T) {
	server := Server{}
	input := &bytes.Buffer{}
	writeRequest(t, input, "{\"id\":\"1\",\"method\":\"core.handshake\",\"params\":{\"protocol\":\"atlas-core\",\"version\":\"1.0.0\",\"client_name\":\"a\",\"client_name\":\"b\",\"client_version\":\"1\",\"session_nonce\":\"n\"}}")
	output := &bytes.Buffer{}
	if err := server.Serve(input, output); err != nil {
		t.Fatalf("valid frame with invalid JSON should receive a protocol error, not kill session: %v", err)
	}
	resp := readResponse(t, output)
	if resp.OK || resp.Error == nil || resp.Error.Code != CodeInvalidRequest {
		t.Fatalf("expected invalid-request response, got %+v", resp)
	}
}

func TestStatusRejectsUnknownParams(t *testing.T) {
	input := &bytes.Buffer{}
	writeRequest(t, input, "{\"id\":\"h\",\"method\":\"core.handshake\",\"params\":{\"protocol\":\"atlas-core\",\"version\":\"1.0.0\",\"client_name\":\"test\",\"client_version\":\"1\",\"session_nonce\":\"n\"}}")
	writeRequest(t, input, "{\"id\":\"s\",\"method\":\"core.status\",\"params\":{\"unexpected\":true}}")
	output := &bytes.Buffer{}
	if err := (Server{}).Serve(input, output); err != nil {
		t.Fatalf("serve: %v", err)
	}
	_ = readResponse(t, output)
	resp := readResponse(t, output)
	if resp.OK || resp.Error == nil || resp.Error.Code != CodeInvalidRequest {
		t.Fatalf("unknown status param must fail, got %+v", resp)
	}
}

func writeRequest(t *testing.T, buf *bytes.Buffer, raw string) {
	t.Helper()
	if err := WriteFrame(buf, []byte(raw), MaxRequestPayload); err != nil {
		t.Fatalf("write test frame: %v", err)
	}
}

func readResponse(t *testing.T, buf *bytes.Buffer) Response {
	t.Helper()
	payload, err := ReadFrame(buf, MaxResponsePayload)
	if err != nil {
		t.Fatalf("read response frame: %v", err)
	}
	var resp Response
	if err := json.Unmarshal(payload, &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp
}

func runSingleRequest(t *testing.T, server Server, raw string) Response {
	t.Helper()
	input := &bytes.Buffer{}
	writeRequest(t, input, raw)
	output := &bytes.Buffer{}
	if err := server.Serve(input, output); err != nil {
		t.Fatalf("serve: %v", err)
	}
	return readResponse(t, output)
}
