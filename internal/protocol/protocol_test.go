package protocol

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

func TestHello_RoundTrip(t *testing.T) {
	var sid [32]byte
	var nonce [16]byte
	_, _ = rand.Read(sid[:])
	_, _ = rand.Read(nonce[:])

	in := &Hello{
		SessionID:    sid,
		Nonce:        nonce,
		RequestedTTL: 3600,
		Target:       "127.0.0.1:22",
		Mode:         HelloModeResume,
	}
	b, err := in.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	out, err := DecodeHello(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.SessionID != in.SessionID {
		t.Error("session id mismatch")
	}
	if out.Nonce != in.Nonce {
		t.Error("nonce mismatch")
	}
	if out.RequestedTTL != in.RequestedTTL {
		t.Errorf("ttl: got %d, want %d", out.RequestedTTL, in.RequestedTTL)
	}
	if out.Target != in.Target {
		t.Errorf("target: got %q, want %q", out.Target, in.Target)
	}
	if out.Mode != in.Mode {
		t.Errorf("mode: got %d, want %d", out.Mode, in.Mode)
	}
}

func TestHello_EmptyTarget(t *testing.T) {
	in := &Hello{RequestedTTL: 60}
	b, err := in.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 55 {
		t.Errorf("len: got %d, want 55", len(b))
	}
	out, err := DecodeHello(b)
	if err != nil {
		t.Fatal(err)
	}
	if out.Target != "" {
		t.Errorf("target: got %q, want empty", out.Target)
	}
	if out.Mode != HelloModeFresh {
		t.Errorf("mode: got %d, want fresh (0)", out.Mode)
	}
}

// TestHello_V01WireDecodesAsFresh covers v0.1 ↔ v0.2 forward compatibility:
// a peer that emits a 54+tl-byte HELLO (no trailing mode byte) must decode
// as HelloModeFresh, with no protocol error.
func TestHello_V01WireDecodesAsFresh(t *testing.T) {
	const target = "127.0.0.1:22"
	v01 := make([]byte, 54+len(target))
	// Skip session_id, nonce (zero is fine for the test).
	// RequestedTTL.
	v01[48], v01[49], v01[50], v01[51] = 0, 0, 0x0E, 0x10 // 3600
	v01[52], v01[53] = 0, byte(len(target))               // target_len
	copy(v01[54:], target)

	out, err := DecodeHello(v01)
	if err != nil {
		t.Fatalf("decode v0.1 wire: %v", err)
	}
	if out.Target != target {
		t.Errorf("target: got %q, want %q", out.Target, target)
	}
	if out.RequestedTTL != 3600 {
		t.Errorf("ttl: got %d, want 3600", out.RequestedTTL)
	}
	if out.Mode != HelloModeFresh {
		t.Errorf("mode: got %d, want fresh", out.Mode)
	}
}

func TestHello_RejectsOversizedTarget(t *testing.T) {
	in := &Hello{Target: string(bytes.Repeat([]byte("A"), MaxTargetLen+1))}
	_, err := in.Encode()
	if !errors.Is(err, ErrLengthCap) {
		t.Errorf("got %v, want ErrLengthCap", err)
	}
}

func TestHello_RejectsTruncated(t *testing.T) {
	in := &Hello{Target: "127.0.0.1:22"}
	b, _ := in.Encode()
	for _, cut := range []int{0, 1, 53, 54 + len(in.Target) - 1} {
		if _, err := DecodeHello(b[:cut]); err == nil {
			t.Errorf("cut=%d: expected error, got nil", cut)
		}
	}
}

func TestHelloAck_RoundTrip(t *testing.T) {
	var nonce [16]byte
	_, _ = rand.Read(nonce[:])
	in := &HelloAck{
		Port:        22017,
		GrantedTTL:  1800,
		ServerNonce: nonce,
		Code:        AckOK,
	}
	b, err := in.Encode()
	if err != nil {
		t.Fatal(err)
	}
	out, err := DecodeHelloAck(b)
	if err != nil {
		t.Fatal(err)
	}
	if out.Port != in.Port || out.GrantedTTL != in.GrantedTTL || out.Code != in.Code {
		t.Errorf("mismatch: got %+v want %+v", out, in)
	}
	if out.ServerNonce != nonce {
		t.Error("nonce mismatch")
	}
}

func TestHelloAck_Error(t *testing.T) {
	in := &HelloAck{Code: AckPortsExhausted, Message: "no free ports in range"}
	b, _ := in.Encode()
	out, err := DecodeHelloAck(b)
	if err != nil {
		t.Fatal(err)
	}
	if out.Code != AckPortsExhausted {
		t.Errorf("code: got %d, want %d", out.Code, AckPortsExhausted)
	}
	if out.Message != in.Message {
		t.Errorf("msg: got %q, want %q", out.Message, in.Message)
	}
}

func TestBye_RoundTrip(t *testing.T) {
	in := &Bye{Code: ByeTTLExpired, Message: "ttl reached"}
	b, _ := in.Encode()
	out, err := DecodeBye(b)
	if err != nil {
		t.Fatal(err)
	}
	if out.Code != in.Code || out.Message != in.Message {
		t.Errorf("mismatch: got %+v want %+v", out, in)
	}
}
