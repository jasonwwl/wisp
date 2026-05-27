package wsraw

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAccept_RFCExample(t *testing.T) {
	// From RFC 6455 §1.3: client key "dGhlIHNhbXBsZSBub25jZQ==" must
	// produce accept "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=".
	got := Accept("dGhlIHNhbXBsZSBub25jZQ==")
	want := "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
	if got != want {
		t.Errorf("Accept() = %q, want %q", got, want)
	}
}

func TestFrame_RoundTrip_Unmasked(t *testing.T) {
	cases := [][]byte{
		nil,
		[]byte("hi"),
		bytes.Repeat([]byte("A"), 125),
		bytes.Repeat([]byte("A"), 126),
		bytes.Repeat([]byte("A"), 0xFFFF),
		bytes.Repeat([]byte("A"), 0x10000),
	}
	for _, payload := range cases {
		var buf bytes.Buffer
		if err := writeFrame(&buf, OpBinary, payload, false); err != nil {
			t.Fatalf("len=%d write: %v", len(payload), err)
		}
		op, got, err := readFrame(&buf)
		if err != nil {
			t.Fatalf("len=%d read: %v", len(payload), err)
		}
		if op != OpBinary {
			t.Errorf("len=%d op: got %v want %v", len(payload), op, OpBinary)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("len=%d payload mismatch", len(payload))
		}
	}
}

func TestFrame_RoundTrip_Masked(t *testing.T) {
	payload := []byte("client-to-server frame")
	var buf bytes.Buffer
	if err := writeFrame(&buf, OpBinary, payload, true); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Sanity: a masked frame should have the mask bit set
	if buf.Bytes()[1]&0x80 == 0 {
		t.Fatal("expected mask bit set in second header byte")
	}
	op, got, err := readFrame(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if op != OpBinary || !bytes.Equal(got, payload) {
		t.Errorf("mismatch: op=%v got=%q want=%q", op, got, payload)
	}
}

func TestFrame_ReadRejectsFragmented(t *testing.T) {
	// FIN=0, opcode=binary, no mask, len=0
	buf := bytes.NewBuffer([]byte{0x02, 0x00})
	_, _, err := readFrame(buf)
	if !errors.Is(err, ErrFragmented) {
		t.Errorf("got %v, want ErrFragmented", err)
	}
}

func TestFrame_ReadRejectsHugePayload(t *testing.T) {
	// FIN=1, opcode=binary, no mask, len=127 (extended 64-bit), payload size = MaxPayload+1
	var hdr [10]byte
	hdr[0] = 0x82
	hdr[1] = 127
	// big-endian uint64
	size := uint64(MaxPayload + 1)
	for i := 0; i < 8; i++ {
		hdr[2+i] = byte(size >> (8 * (7 - i)))
	}
	buf := bytes.NewBuffer(hdr[:])
	_, _, err := readFrame(buf)
	if !errors.Is(err, ErrPayloadTooBig) {
		t.Errorf("got %v, want ErrPayloadTooBig", err)
	}
}

// End-to-end handshake + message exchange over a TLS in-memory server.
func TestE2E_HandshakeAndMessage(t *testing.T) {
	cert, err := selfSignedCert("localhost")
	if err != nil {
		t.Fatalf("self-sign: %v", err)
	}

	handlerCh := make(chan error, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := AcceptUpgrade(w, r)
		if err != nil {
			handlerCh <- err
			return
		}
		defer conn.Close()
		msg, err := conn.ReadMessage()
		if err != nil {
			handlerCh <- err
			return
		}
		if err := conn.WriteMessage(append([]byte("echo:"), msg...)); err != nil {
			handlerCh <- err
			return
		}
		handlerCh <- nil
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	server.StartTLS()
	defer server.Close()

	wsURL := "https" + server.URL[len("https"):] + "/ws"

	conn, err := Dial(DialOptions{
		URL:       wsURL,
		TLSConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := conn.WriteMessage([]byte("hello wisp")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if want := "echo:hello wisp"; string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}

	if err := <-handlerCh; err != nil {
		t.Errorf("handler: %v", err)
	}
}

// Auto-pong on ping
func TestE2E_PingPong(t *testing.T) {
	cert, err := selfSignedCert("localhost")
	if err != nil {
		t.Fatalf("self-sign: %v", err)
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := AcceptUpgrade(w, r)
		if err != nil {
			return
		}
		defer conn.Close()
		// Send a ping; client should auto-pong (we don't observe it here,
		// but we then send a binary and expect echo).
		// We need access to writeFrame from server-side, which is unexported.
		_ = conn.writeFrame(OpPing, []byte("p1"))
		_ = conn.WriteMessage([]byte("after-ping"))
		_, _ = conn.ReadMessage()
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	server.StartTLS()
	defer server.Close()

	wsURL := "https" + server.URL[len("https"):] + "/ws"
	conn, err := Dial(DialOptions{
		URL:       wsURL,
		TLSConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	msg, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(msg) != "after-ping" {
		t.Errorf("got %q, want %q", msg, "after-ping")
	}
	_ = conn.WriteMessage([]byte("done"))
}

// helper: minimal in-memory self-signed cert. Lives in the test file so the
// production package has no cert-generation code path.
func selfSignedCert(host string) (tls.Certificate, error) {
	return tlsHelperGenerate(host)
}

// Defined in helper_test.go to share with other tests in the file.
var _ = io.EOF // keep io import valid if helper is later moved

var _ net.Conn = (*tls.Conn)(nil)
