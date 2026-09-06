package main

import (
	"bytes"
	"encoding/json"
)

// canonicalJSON reproduces the current Atlas compact deterministic JSON profile
// for the bounded JSON value domain used by frozen protocol artifacts. This is
// evidence for compatibility, not a new canonicalization standard.
func canonicalJSON(value any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
