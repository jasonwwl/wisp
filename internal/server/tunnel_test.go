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
	if !strings.Contains(w.Body.String(), "404 Not Found") {
		t.Errorf("body should mimic the decoy 404, got %q", w.Body.String())
	}
}

// TestTunnel_404BytesMatchDecoy is the load-bearing fingerprint
// regression: every 404 path on this server — decoy fall-through,
// tunnel endpoint without a token, tunnel endpoint with WS headers
// but no token — must produce byte-for-byte identical responses.
// A passive NGFW that observes one signature and probes the other
// must not be able to distinguish them.
func TestTunnel_404BytesMatchDecoy(t *testing.T) {
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

	// 1. decoy 404: a random URL handed to decoyHandler.
	decoyReq := httptest.NewRequest("GET", "/random-not-found", nil)
	decoyW := httptest.NewRecorder()
	srv.decoyHandler(decoyW, decoyReq)

	// 2. tunnel auth-fail: valid endpoint path, missing/wrong token.
	authReq := httptest.NewRequest("GET", "/"+srv.Endpoint()+"/ws", nil)
	authReq.Header.Set("Authorization", "Bearer wrong-token")
	authW := newRecorder()
	srv.tunnelHandler(authW, authReq)

	// 3. tunnel WS-upgrade-fail: valid endpoint + valid token but the
	//    response writer doesn't implement http.Hijacker (i.e. an
	//    HTTP/2 path or any other non-hijackable transport).
	hijackReq := httptest.NewRequest("GET", "/"+srv.Endpoint()+"/ws", nil)
	hijackReq.Header.Set("Authorization", "Bearer the-real-token")
	hijackReq.Header.Set("Connection", "Upgrade")
	hijackReq.Header.Set("Upgrade", "websocket")
	hijackReq.Header.Set("Sec-WebSocket-Version", "13")
	hijackReq.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	hijackW := newRecorder()
	srv.tunnelHandler(hijackW, hijackReq)

	cases := []struct {
		name string
		w    interface {
			Result() *http.Response
		}
		code int
		body string
	}{
		{"decoy 404", decoyW, decoyW.Code, decoyW.Body.String()},
		{"tunnel auth-fail", authW, authW.Code, authW.Body.String()},
		{"tunnel hijack-fail", hijackW, hijackW.Code, hijackW.Body.String()},
	}

	for _, c := range cases {
		t.Logf("%-22s code=%d  body_len=%d  body=%q", c.name, c.code, len(c.body), c.body)
	}

	want := cases[0]
	for _, c := range cases[1:] {
		if c.code != want.code {
			t.Errorf("%s: status %d != decoy %d", c.name, c.code, want.code)
		}
		if c.body != want.body {
			t.Errorf("%s: body differs from decoy\n  decoy: %q\n  got:   %q", c.name, want.body, c.body)
		}
		// Header equality on the bits an NGFW reads.
		dh := decoyW.Header()
		ch := c.w.Result().Header
		for _, h := range []string{"Server", "Content-Type"} {
			if dh.Get(h) != ch.Get(h) {
				t.Errorf("%s: header %s differs: decoy=%q got=%q", c.name, h, dh.Get(h), ch.Get(h))
			}
		}
	}
}
