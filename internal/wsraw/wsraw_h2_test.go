package wsraw

import (
	"bytes"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/net/http2"
)

// TestE2E_H2_ExtendedConnect spins up a TLS server that advertises h2,
// configures x/net/http2 to handle h2 streams, then drives a wsraw
// dial that — by default — negotiates h2 and rides RFC 8441 Extended
// CONNECT. We send a couple of binary messages each way and verify
// bytes round-trip.
func TestE2E_H2_ExtendedConnect(t *testing.T) {
	cert, err := selfSignedCert("localhost")
	if err != nil {
		t.Fatalf("self-sign: %v", err)
	}

	handlerCh := make(chan error, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, ok, err := AcceptH2Upgrade(w, r)
		if !ok && err == nil {
			// Not an h2 extended connect request — fail loudly.
			handlerCh <- nil // tests assert no h1 used.
			http.Error(w, "wanted h2 extended connect", http.StatusBadRequest)
			return
		}
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
		if err := conn.WriteMessage(append([]byte("h2:"), msg...)); err != nil {
			handlerCh <- err
			return
		}
		handlerCh <- nil
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}
	if err := http2.ConfigureServer(srv.Config, &http2.Server{}); err != nil {
		t.Fatalf("ConfigureServer: %v", err)
	}
	srv.StartTLS()
	defer srv.Close()

	wsURL := "https" + srv.URL[len("https"):] + "/ws"

	conn, err := Dial(DialOptions{
		URL: wsURL,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "localhost",
		},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := conn.WriteMessage([]byte("hello h2")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "h2:hello h2" {
		t.Errorf("got %q, want %q", got, "h2:hello h2")
	}

	if err := <-handlerCh; err != nil {
		t.Errorf("handler: %v", err)
	}
}

// TestDial_H1Fallback_ServerOffersH1Only: a server that only advertises
// http/1.1 in ALPN forces the negotiation to land on h1 even though the
// client offers ["h2", "http/1.1"]. The legacy Upgrade path must still
// work — this is how wisp survives intermediaries that strip h2.
func TestDial_H1Fallback_ServerOffersH1Only(t *testing.T) {
	cert, err := selfSignedCert("localhost")
	if err != nil {
		t.Fatalf("self-sign: %v", err)
	}

	handlerCh := make(chan string, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 {
			handlerCh <- "got h2 (negotiation should have landed on h1)"
			http.Error(w, "expected h1", http.StatusBadRequest)
			return
		}
		conn, _, err := AcceptUpgrade(w, r)
		if err != nil {
			handlerCh <- err.Error()
			return
		}
		defer conn.Close()
		msg, err := conn.ReadMessage()
		if err != nil {
			handlerCh <- err.Error()
			return
		}
		_ = conn.WriteMessage(append([]byte("h1:"), msg...))
		handlerCh <- ""
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
	}
	srv.StartTLS()
	defer srv.Close()

	wsURL := "https" + srv.URL[len("https"):] + "/ws"

	conn, err := Dial(DialOptions{
		URL: wsURL,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "localhost",
		},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := conn.WriteMessage([]byte("hi")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "h1:hi" {
		t.Errorf("got %q, want %q", got, "h1:hi")
	}
	if msg := <-handlerCh; msg != "" {
		t.Errorf("handler: %s", msg)
	}
}

// TestE2E_H2_LargeMessage: 1 MiB binary message both ways over h2.
// Catches frame-boundary surprises (e.g. flow-control stalls) that
// the short messages above miss.
func TestE2E_H2_LargeMessage(t *testing.T) {
	cert, err := selfSignedCert("localhost")
	if err != nil {
		t.Fatalf("self-sign: %v", err)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, ok, err := AcceptH2Upgrade(w, r)
		if !ok || err != nil {
			return
		}
		defer conn.Close()
		for {
			msg, rerr := conn.ReadMessage()
			if rerr != nil {
				return
			}
			if werr := conn.WriteMessage(msg); werr != nil {
				return
			}
		}
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}
	if err := http2.ConfigureServer(srv.Config, &http2.Server{}); err != nil {
		t.Fatalf("ConfigureServer: %v", err)
	}
	srv.StartTLS()
	defer srv.Close()

	wsURL := "https" + srv.URL[len("https"):] + "/ws"

	conn, err := Dial(DialOptions{
		URL: wsURL,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "localhost",
		},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	payload := bytes.Repeat([]byte{'A'}, 1<<20)
	if err := conn.WriteMessage(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload round-trip mismatch (lens got=%d want=%d)", len(got), len(payload))
	}
}

// TestAcceptH2Upgrade_RejectsH1: the h2 accept helper must refuse an
// HTTP/1.1 request so callers reliably fall back to the h1 path.
func TestAcceptH2Upgrade_RejectsH1(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.Proto = "HTTP/1.1"
	req.ProtoMajor = 1
	req.ProtoMinor = 1
	rw := httptest.NewRecorder()

	conn, ok, err := AcceptH2Upgrade(rw, req)
	if conn != nil || ok || err != nil {
		t.Errorf("expected (nil, false, nil); got (%v, %v, %v)", conn, ok, err)
	}
}

// Sanity check that the linkname-flipped h2 extended-connect setting
// stays enabled across the test binary lifetime — a future runtime
// change could quietly break it.
func TestH2_ExtendedConnect_FlagIsOn(t *testing.T) {
	if x_net_http2_disableExtendedConnectProtocol {
		t.Error("extended CONNECT must be enabled (linkname flip failed?)")
	}
}
