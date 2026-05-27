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
}

func TestHello_EmptyTarget(t *testing.T) {
	in := &Hello{RequestedTTL: 60}
	b, err := in.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 54 {
		t.Errorf("len: got %d, want 54", len(b))
	}
	out, err := DecodeHello(b)
	if err != nil {
		t.Fatal(err)
	}
	if out.Target != "" {
		t.Errorf("target: got %q, want empty", out.Target)
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
	for _, cut := range []int{0, 1, 53, len(b) - 1} {
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
