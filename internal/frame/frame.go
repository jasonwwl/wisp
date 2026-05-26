// Package frame implements the wisp wire framing carried inside the
// WebSocket binary message. See docs/design.md §3.3.
//
// Frame layout (big-endian):
//
//	+--------+----------------+---------+----------------+----------+
//	| type:1 | length:2       | pad_n:1 | payload:length | pad:pad_n|
//	+--------+----------------+---------+----------------+----------+
//
// Padding is opaque random bytes; receivers must discard it. The header
// is always exactly 4 bytes.
package frame

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Type identifies a wisp control or data frame.
type Type uint8

// Frame types. Values are wire-stable.
const (
	TypeHello    Type = 0x01 // client → server: session establishment
	TypeHelloAck Type = 0x02 // server → client: assigned port, granted TTL
	TypePing     Type = 0x03 // either side: liveness probe
	TypePong     Type = 0x04 // either side: liveness reply
	TypeYamux    Type = 0x05 // either side: opaque carrier for a yamux frame
	TypeBye      Type = 0x06 // either side: orderly shutdown with reason
)

// String returns the canonical lowercase name of t.
func (t Type) String() string {
	switch t {
	case TypeHello:
		return "hello"
	case TypeHelloAck:
		return "hello_ack"
	case TypePing:
		return "ping"
	case TypePong:
		return "pong"
	case TypeYamux:
		return "yamux"
	case TypeBye:
		return "bye"
	default:
		return fmt.Sprintf("unknown(0x%02x)", uint8(t))
	}
}

// Wire-format constants.
const (
	HeaderSize = 4
	MaxPayload = 1 << 16 // 64 KiB
	MaxPad     = 255
)

// Errors returned by Encode and Decode.
var (
	ErrPayloadTooLarge = errors.New("frame: payload exceeds 64 KiB")
	ErrPadTooLarge     = errors.New("frame: pad exceeds 255 bytes")
	ErrUnknownType     = errors.New("frame: unknown type")
)

// Frame is a single wisp frame in memory. Padding is not part of the
// in-memory representation — Encode adds random padding and Decode
// discards any bytes after the payload.
type Frame struct {
	Type    Type
	Payload []byte
}

// Encode writes f to w. If padTarget > 0, Encode appends a random number
// of pad bytes drawn uniformly from [0, min(padTarget, MaxPad)].
func (f Frame) Encode(w io.Writer, padTarget int) error {
	if len(f.Payload) > MaxPayload {
		return ErrPayloadTooLarge
	}
	if padTarget < 0 {
		padTarget = 0
	}
	if padTarget > MaxPad {
		padTarget = MaxPad
	}

	padN := 0
	if padTarget > 0 {
		var b [1]byte
		if _, err := rand.Read(b[:]); err != nil {
			return err
		}
		padN = int(b[0]) % (padTarget + 1)
	}

	var hdr [HeaderSize]byte
	hdr[0] = byte(f.Type)
	binary.BigEndian.PutUint16(hdr[1:3], uint16(len(f.Payload)))
	hdr[3] = byte(padN)
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(f.Payload) > 0 {
		if _, err := w.Write(f.Payload); err != nil {
			return err
		}
	}
	if padN > 0 {
		pad := make([]byte, padN)
		if _, err := rand.Read(pad); err != nil {
			return err
		}
		if _, err := w.Write(pad); err != nil {
			return err
		}
	}
	return nil
}

// Decode reads exactly one frame from r. Pad bytes are read and discarded.
func Decode(r io.Reader) (Frame, error) {
	var hdr [HeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}
	t := Type(hdr[0])
	if !t.valid() {
		return Frame{}, ErrUnknownType
	}
	length := int(binary.BigEndian.Uint16(hdr[1:3]))
	padN := int(hdr[3])
	if length > MaxPayload {
		return Frame{}, ErrPayloadTooLarge
	}

	f := Frame{Type: t}
	if length > 0 {
		f.Payload = make([]byte, length)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return Frame{}, err
		}
	}
	if padN > 0 {
		if _, err := io.CopyN(io.Discard, r, int64(padN)); err != nil {
			return Frame{}, err
		}
	}
	return f, nil
}

func (t Type) valid() bool {
	switch t {
	case TypeHello, TypeHelloAck, TypePing, TypePong, TypeYamux, TypeBye:
		return true
	}
	return false
}
