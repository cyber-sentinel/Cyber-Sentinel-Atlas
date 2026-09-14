package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

const (
	MaxJSONDepth = 32
	MaxIDRunes   = 128
)

var (
	ErrInvalidUTF8     = errors.New("payload is not valid UTF-8")
	ErrUTF8BOM         = errors.New("UTF-8 BOM is not permitted")
	ErrDuplicateKey    = errors.New("duplicate JSON object member")
	ErrJSONDepth       = errors.New("JSON nesting depth exceeds limit")
	ErrTrailingJSON    = errors.New("trailing data after JSON value")
	ErrInvalidEnvelope = errors.New("invalid request envelope")
)

type Request struct {
	ID     string          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

// ValidateJSON applies the protocol's strict JSON profile before typed decode.
// Container nesting is bounded to MaxJSONDepth, with a root object/array at depth 1.
func ValidateJSON(data []byte) error {
	if !utf8.Valid(data) {
		return ErrInvalidUTF8
	}
	if bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}) {
		return ErrUTF8BOM
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := scanValue(dec, 0); err != nil {
		return err
	}
	if _, err := dec.Token(); err == nil {
		return ErrTrailingJSON
	} else if !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing JSON validation: %w", err)
	}
	return nil
}

func scanValue(dec *json.Decoder, containerDepth int) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("decode JSON token: %w", err)
	}

	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}

	switch delim {
	case '{':
		depth := containerDepth + 1
		if depth > MaxJSONDepth {
			return ErrJSONDepth
		}
		seen := make(map[string]struct{})
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return fmt.Errorf("decode JSON object key: %w", err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("%w: %s", ErrDuplicateKey, key)
			}
			seen[key] = struct{}{}
			if err := scanValue(dec, depth); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil {
			return fmt.Errorf("close JSON object: %w", err)
		}
		if d, ok := end.(json.Delim); !ok || d != '}' {
			return errors.New("JSON object did not terminate correctly")
		}
		return nil

	case '[':
		depth := containerDepth + 1
		if depth > MaxJSONDepth {
			return ErrJSONDepth
		}
		for dec.More() {
			if err := scanValue(dec, depth); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil {
			return fmt.Errorf("close JSON array: %w", err)
		}
		if d, ok := end.(json.Delim); !ok || d != ']' {
			return errors.New("JSON array did not terminate correctly")
		}
		return nil
	default:
		return errors.New("unexpected closing JSON delimiter")
	}
}

func DecodeRequest(data []byte) (Request, error) {
	var req Request
	if err := ValidateJSON(data); err != nil {
		return req, err
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return req, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	if req.ID == "" || utf8.RuneCountInString(req.ID) > MaxIDRunes {
		return req, fmt.Errorf("%w: invalid id", ErrInvalidEnvelope)
	}
	if req.Method == "" {
		return req, fmt.Errorf("%w: method is required", ErrInvalidEnvelope)
	}
	if len(req.Params) == 0 || !jsonObject(req.Params) {
		return req, fmt.Errorf("%w: params must be a JSON object", ErrInvalidEnvelope)
	}
	return req, nil
}

func DecodeStrictParams[T any](raw json.RawMessage, out *T) error {
	if !jsonObject(raw) {
		return errors.New("params must be a JSON object")
	}
	if err := ValidateJSON(raw); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	return nil
}

func jsonObject(raw []byte) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) >= 2 && trimmed[0] == '{' && trimmed[len(trimmed)-1] == '}'
}
