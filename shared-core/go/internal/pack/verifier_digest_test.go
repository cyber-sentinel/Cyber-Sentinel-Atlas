package pack

import "testing"

func TestCanonicalDigestMatchesPythonReferenceEncoding(t *testing.T) {
	value := map[string]any{
		"label":    "ATT&CK",
		"lt":       "<x>",
		"nonascii": "é",
		"para":     "\u2029",
		"sep":      "\u2028",
	}

	got, err := canonicalDigest(value)
	if err != nil {
		t.Fatal(err)
	}

	const want = "sha256-6ecf8291093d9130634ae5d58a00163cd315c5f0812dfdb37c6680249390ef93"
	if got != want {
		t.Fatalf("canonical digest parity mismatch: got %s want %s", got, want)
	}
}
