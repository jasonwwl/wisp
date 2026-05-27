package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// nonHijackerWriter is an http.ResponseWriter that does NOT implement
// http.Hijacker. This is the situation a request that arrived over
// HTTP/2 produces: the wsraw handshake will fail at hijack-detection
// time, and the wisp server must still produce a decoy-shaped response
// instead of letting Go's default 200 leak through.
type nonHijackerWriter struct {
	*httptest.ResponseRecorder
}

func newRecorder() *nonHijackerWriter {
	return &nonHijackerWriter{ResponseRecorder: httptest.NewRecorder()}
}

// TestTunnel_NonHijackerLooksLike404 simulates an HTTP/2 (or any other
// transport where Hijack is unavailable) request hitting the tunnel
// endpoint with a valid token. The server must NOT return a default 200
// or a generic Go error; it must mimic the decoy site's 404.
func TestTunnel_NonHijackerLooksLike404(t *testing.T) {
	const token = "secret"
	srv, err := New(Config{
		Domain:            "localhost",
		Token:             token,
		Endpoint:          "abcdefghij0123456789ABCDEFGHIJ0123456789xyz",
		TLSAutoSelfSigned: true,
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "/"+srv.Endpoint()+"/ws", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")

	w := newRecorder()
	srv.tunnelHandler(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status: got %d, want 404", w.Code)
	}
	if got := w.Header().Get("Server"); got != "nginx/1.24.0" {
		t.Errorf("Server header: got %q, want %q", got, "nginx/1.24.0")
	}
	if !strings.Contains(w.Body.String(), "404 Not Found") {
		t.Errorf("body should mimic the decoy 404, got: %q", w.Body.String())
	}
}

// TestTunnel_BadTokenLooksLike404 verifies the same indistinguishable-404
// behavior on bad-token paths, on a plain non-Hijacker recorder for unit
// isolation (the e2e behavior is also covered in client.TestHandshake_BadToken).
func TestTunnel_BadTokenLooksLike404(t *testing.T) {
	srv, err := New(Config{
		Domain:            "localhost",
		Token:             "the-real-token",
		Endpoint:          "abcdefghij0123456789ABCDEFGHIJ0123456789xyz",
		TLSAutoSelfSigned: true,
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "/"+srv.Endpoint()+"/ws", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")

	w := newRecorder()
	srv.tunnelHandler(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status: got %d, want 404", w.Code)
	}
	if got := w.Header().Get("Server"); got != "nginx/1.24.0" {
		t.Errorf("Server header: got %q, want %q", got, "nginx/1.24.0")
	}
}
