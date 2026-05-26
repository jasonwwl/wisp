package frame

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestRoundTrip_NoPad(t *testing.T) {
	cases := []Frame{
		{Type: TypeHello, Payload: []byte("hello")},
		{Type: TypeHelloAck, Payload: []byte{0x00, 0xff, 0xaa}},
		{Type: TypePing, Payload: nil},
		{Type: TypeBye, Payload: []byte("ttl_expired")},
		{Type: TypeYamux, Payload: bytes.Repeat([]byte("A"), 4096)},
	}
	for _, want := range cases {
		t.Run(want.Type.String(), func(t *testing.T) {
			var buf bytes.Buffer
			if err := want.Encode(&buf, 0); err != nil {
				t.Fatalf("encode: %v", err)
			}
			got, err := Decode(&buf)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got.Type != want.Type {
				t.Errorf("type: got %v, want %v", got.Type, want.Type)
			}
			if !bytes.Equal(got.Payload, want.Payload) {
				t.Errorf("payload mismatch: got %q want %q", got.Payload, want.Payload)
			}
			if buf.Len() != 0 {
				t.Errorf("trailing bytes after decode: %d", buf.Len())
			}
		})
	}
}

func TestRoundTrip_WithPad(t *testing.T) {
	// Run many iterations because padding is random; want stable behavior
	// across runs.
	want := Frame{Type: TypePing, Payload: []byte("pingdata")}
	for i := 0; i < 100; i++ {
		var buf bytes.Buffer
		if err := want.Encode(&buf, 255); err != nil {
			t.Fatalf("encode: %v", err)
		}
		got, err := Decode(&buf)
		if err != nil {
			t.Fatalf("decode iter=%d: %v", i, err)
		}
		if got.Type != want.Type || !bytes.Equal(got.Payload, want.Payload) {
			t.Fatalf("mismatch iter=%d: got %+v want %+v", i, got, want)
		}
		if buf.Len() != 0 {
			t.Fatalf("trailing bytes iter=%d: %d", i, buf.Len())
		}
	}
}

func TestType_String(t *testing.T) {
	if got := TypeHello.String(); got != "hello" {
		t.Errorf("TypeHello.String() = %q, want %q", got, "hello")
	}
	if got := Type(0x99).String(); !strings.HasPrefix(got, "unknown") {
		t.Errorf("unknown type stringer = %q, want unknown(...)", got)
	}
}

func TestDecode_UnknownType(t *testing.T) {
	buf := bytes.NewBuffer([]byte{0xFF, 0, 0, 0})
	if _, err := Decode(buf); err != ErrUnknownType {
		t.Errorf("got %v, want ErrUnknownType", err)
	}
}

func TestDecode_TruncatedHeader(t *testing.T) {
	buf := bytes.NewBuffer([]byte{0x01, 0x00}) // 2 bytes, header needs 4
	if _, err := Decode(buf); err == nil || err == ErrUnknownType {
		t.Errorf("got %v, want a short-read error", err)
	}
}

func TestDecode_TruncatedPayload(t *testing.T) {
	// header says payload length = 10, but we only provide 4
	buf := bytes.NewBuffer([]byte{0x01, 0x00, 0x0a, 0x00, 1, 2, 3, 4})
	if _, err := Decode(buf); err == nil {
		t.Error("got nil error, want short-read")
	} else if err == io.EOF {
		t.Error("got io.EOF, want io.ErrUnexpectedEOF")
	}
}

func TestEncode_PayloadTooLarge(t *testing.T) {
	huge := Frame{Type: TypeYamux, Payload: make([]byte, MaxPayload+1)}
	var buf bytes.Buffer
	if err := huge.Encode(&buf, 0); err != ErrPayloadTooLarge {
		t.Errorf("got %v, want ErrPayloadTooLarge", err)
	}
}

func TestEncode_PadTargetClamped(t *testing.T) {
	f := Frame{Type: TypePing, Payload: []byte("x")}
	for _, target := range []int{-10, 0, 100, 999, 1 << 20} {
		var buf bytes.Buffer
		if err := f.Encode(&buf, target); err != nil {
			t.Fatalf("target=%d encode: %v", target, err)
		}
		got, err := Decode(&buf)
		if err != nil {
			t.Fatalf("target=%d decode: %v", target, err)
		}
		if got.Type != f.Type || !bytes.Equal(got.Payload, f.Payload) {
			t.Errorf("target=%d mismatch", target)
		}
	}
}

func BenchmarkEncodeDecode(b *testing.B) {
	f := Frame{Type: TypeYamux, Payload: bytes.Repeat([]byte("A"), 1024)}
	var buf bytes.Buffer
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		if err := f.Encode(&buf, 64); err != nil {
			b.Fatal(err)
		}
		if _, err := Decode(&buf); err != nil {
			b.Fatal(err)
		}
	}
}
