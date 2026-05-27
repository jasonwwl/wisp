// Package protocol defines the wisp control messages carried inside
// wisp.Frame envelopes: HELLO, HELLO_ACK, BYE.
//
// All multi-byte integers are big-endian. The format is deliberately
// flat (no varints, no TLV) to keep the parser auditable and the
// fingerprint of the encoded bytes uniform across releases.
//
// Wire layouts (all sizes in bytes):
//
//	Hello (>= 55 bytes):
//	  0..31    session_id        [32]
//	  32..47   nonce             [16]
//	  48..51   requested_ttl_sec uint32
//	  52..53   target_len        uint16
//	  54..     target            target_len bytes (ASCII)
//	  54+tl    mode              uint8 (HelloModeFresh = 0,
//	                                    HelloModeResume = 1)
//
// The trailing mode byte is an append-only v0.2 extension: a v0.1
// peer that produced a 54+tl-byte HELLO is decoded as mode=fresh; a
// v0.1 peer that receives a 55+tl-byte HELLO ignores the trailing
// byte (its decoder did not validate trailing-byte presence).
//
//	HelloAck (>= 26 bytes):
//	  0..1     port              uint16
//	  2..5     granted_ttl_sec   uint32
//	  6..21    server_nonce      [16]
//	  22..23   code              uint16   (0 = ok)
//	  24..25   msg_len           uint16
//	  26..     msg               msg_len bytes (ASCII; empty when ok)
//
//	Bye (>= 4 bytes):
//	  0..1     code              uint16
//	  2..3     msg_len           uint16
//	  4..      msg               msg_len bytes (ASCII)
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// AckCode classifies HELLO_ACK outcomes. Zero is success; non-zero is
// a structured rejection the client can show the user.
type AckCode uint16

const (
	AckOK             AckCode = 0
	AckPortsExhausted AckCode = 1
	AckBadHello       AckCode = 2
	AckInternalError  AckCode = 3
	AckResumeNotFound AckCode = 4
	AckTTLOutOfRange  AckCode = 5 // reserved
)

// HelloMode is the trailing flag byte on HELLO. It tells the server
// whether the client is starting a brand-new session or trying to
// re-attach to an existing one within its resume window.
type HelloMode uint8

const (
	HelloModeFresh  HelloMode = 0
	HelloModeResume HelloMode = 1
)

// ByeCode classifies orderly shutdown reasons.
type ByeCode uint16

const (
	ByeNormal         ByeCode = 0
	ByeTTLExpired     ByeCode = 1
	ByeServerShutdown ByeCode = 2
	ByeClientShutdown ByeCode = 3
)

// Maximum string lengths (paranoia against malformed peer).
const (
	MaxTargetLen = 4096
	MaxMsgLen    = 4096
)

// Errors.
var (
	ErrShortBuffer = errors.New("protocol: short buffer")
	ErrLengthCap   = errors.New("protocol: length exceeds cap")
)

// Hello is sent by the client immediately after the WebSocket upgrade.
type Hello struct {
	SessionID    [32]byte
	Nonce        [16]byte
	RequestedTTL uint32 // seconds
	Target       string // free-form, ASCII (e.g. "127.0.0.1:22"); informational
	Mode         HelloMode
}

// Encode returns the wire bytes for h.
func (h *Hello) Encode() ([]byte, error) {
	if len(h.Target) > MaxTargetLen {
		return nil, fmt.Errorf("%w: target %d > %d", ErrLengthCap, len(h.Target), MaxTargetLen)
	}
	buf := make([]byte, 55+len(h.Target))
	copy(buf[0:32], h.SessionID[:])
	copy(buf[32:48], h.Nonce[:])
	binary.BigEndian.PutUint32(buf[48:52], h.RequestedTTL)
	binary.BigEndian.PutUint16(buf[52:54], uint16(len(h.Target)))
	copy(buf[54:54+len(h.Target)], h.Target)
	buf[54+len(h.Target)] = byte(h.Mode)
	return buf, nil
}

// DecodeHello parses h from wire bytes. A v0.1 peer's 54+tl-byte HELLO
// (no trailing mode byte) decodes with Mode = HelloModeFresh.
func DecodeHello(b []byte) (*Hello, error) {
	if len(b) < 54 {
		return nil, fmt.Errorf("%w: hello %d < 54", ErrShortBuffer, len(b))
	}
	tl := int(binary.BigEndian.Uint16(b[52:54]))
	if tl > MaxTargetLen {
		return nil, fmt.Errorf("%w: target_len %d > %d", ErrLengthCap, tl, MaxTargetLen)
	}
	if len(b) < 54+tl {
		return nil, fmt.Errorf("%w: hello body %d < %d", ErrShortBuffer, len(b), 54+tl)
	}
	h := &Hello{RequestedTTL: binary.BigEndian.Uint32(b[48:52])}
	copy(h.SessionID[:], b[0:32])
	copy(h.Nonce[:], b[32:48])
	h.Target = string(b[54 : 54+tl])
	if len(b) >= 54+tl+1 {
		h.Mode = HelloMode(b[54+tl])
	}
	return h, nil
}

// HelloAck is the server's response to HELLO.
type HelloAck struct {
	Port        uint16
	GrantedTTL  uint32 // seconds; may be less than the client requested
	ServerNonce [16]byte
	Code        AckCode
	Message     string
}

// Encode returns the wire bytes for a.
func (a *HelloAck) Encode() ([]byte, error) {
	if len(a.Message) > MaxMsgLen {
		return nil, fmt.Errorf("%w: msg %d > %d", ErrLengthCap, len(a.Message), MaxMsgLen)
	}
	buf := make([]byte, 26+len(a.Message))
	binary.BigEndian.PutUint16(buf[0:2], a.Port)
	binary.BigEndian.PutUint32(buf[2:6], a.GrantedTTL)
	copy(buf[6:22], a.ServerNonce[:])
	binary.BigEndian.PutUint16(buf[22:24], uint16(a.Code))
	binary.BigEndian.PutUint16(buf[24:26], uint16(len(a.Message)))
	copy(buf[26:], a.Message)
	return buf, nil
}

// DecodeHelloAck parses a from wire bytes.
func DecodeHelloAck(b []byte) (*HelloAck, error) {
	if len(b) < 26 {
		return nil, fmt.Errorf("%w: ack %d < 26", ErrShortBuffer, len(b))
	}
	ml := int(binary.BigEndian.Uint16(b[24:26]))
	if ml > MaxMsgLen {
		return nil, fmt.Errorf("%w: msg_len %d > %d", ErrLengthCap, ml, MaxMsgLen)
	}
	if len(b) < 26+ml {
		return nil, fmt.Errorf("%w: ack body %d < %d", ErrShortBuffer, len(b), 26+ml)
	}
	a := &HelloAck{
		Port:       binary.BigEndian.Uint16(b[0:2]),
		GrantedTTL: binary.BigEndian.Uint32(b[2:6]),
		Code:       AckCode(binary.BigEndian.Uint16(b[22:24])),
		Message:    string(b[26 : 26+ml]),
	}
	copy(a.ServerNonce[:], b[6:22])
	return a, nil
}

// Bye is exchanged for orderly tunnel teardown.
type Bye struct {
	Code    ByeCode
	Message string
}

// Encode returns the wire bytes for b.
func (b *Bye) Encode() ([]byte, error) {
	if len(b.Message) > MaxMsgLen {
		return nil, fmt.Errorf("%w: msg %d > %d", ErrLengthCap, len(b.Message), MaxMsgLen)
	}
	buf := make([]byte, 4+len(b.Message))
	binary.BigEndian.PutUint16(buf[0:2], uint16(b.Code))
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(b.Message)))
	copy(buf[4:], b.Message)
	return buf, nil
}

// DecodeBye parses b from wire bytes.
func DecodeBye(b []byte) (*Bye, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("%w: bye %d < 4", ErrShortBuffer, len(b))
	}
	ml := int(binary.BigEndian.Uint16(b[2:4]))
	if ml > MaxMsgLen {
		return nil, fmt.Errorf("%w: msg_len %d > %d", ErrLengthCap, ml, MaxMsgLen)
	}
	if len(b) < 4+ml {
		return nil, fmt.Errorf("%w: bye body %d < %d", ErrShortBuffer, len(b), 4+ml)
	}
	return &Bye{
		Code:    ByeCode(binary.BigEndian.Uint16(b[0:2])),
		Message: string(b[4 : 4+ml]),
	}, nil
}
