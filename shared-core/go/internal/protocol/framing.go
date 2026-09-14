package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	MaxRequestPayload  uint32 = 1 << 20
	MaxResponsePayload uint32 = 8 << 20
)

var (
	ErrZeroLengthFrame = errors.New("zero-length frame")
	ErrFrameTooLarge   = errors.New("frame exceeds configured payload bound")
)

// ReadFrame reads one Atlas length-prefixed frame. A clean EOF before any header
// byte terminates the session. Any partial header/payload is a fatal framing error.
func ReadFrame(r io.Reader, max uint32) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("read frame header: %w", err)
	}

	n := binary.BigEndian.Uint32(header[:])
	if n == 0 {
		return nil, ErrZeroLengthFrame
	}
	if n > max {
		return nil, ErrFrameTooLarge
	}

	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("read frame payload: %w", err)
	}
	return payload, nil
}

// WriteFrame writes one complete Atlas frame and refuses oversized output.
func WriteFrame(w io.Writer, payload []byte, max uint32) error {
	if len(payload) == 0 {
		return ErrZeroLengthFrame
	}
	if uint64(len(payload)) > uint64(max) {
		return ErrFrameTooLarge
	}

	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if err := writeAll(w, header[:]); err != nil {
		return fmt.Errorf("write frame header: %w", err)
	}
	if err := writeAll(w, payload); err != nil {
		return fmt.Errorf("write frame payload: %w", err)
	}
	return nil
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}
