package client_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jasonwwl/wisp/internal/client"
	"github.com/jasonwwl/wisp/internal/server"
)

// TestHandshake_E2E spins up a real wisp server (TLS + obscured endpoint +
// token auth + HELLO/HELLO_ACK handler) on localhost and runs the client
// against it. This is the milestone 1+2+3 smoke test.
func TestHandshake_E2E(t *testing.T) {
	srv, host, ep, token := mustStartServer(t)
	defer srv.Stop()

	res, err := client.Run(context.Background(), client.Config{
		Server:             host,
		Endpoint:           ep,
		Token:              token,
		LocalTarget:        "127.0.0.1:22",
		TTL:                10 * time.Minute,
		InsecureSkipVerify: true,
		Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("client.Run: %v", err)
	}

	if res.SessionID == "" {
		t.Error("empty session id")
	}
	if !strings.HasPrefix(string(res.AckRaw), "port=") {
		t.Errorf("unexpected ack payload: %q", res.AckRaw)
	}
}

// TestHandshake_BadToken ensures a wrong token gets the indistinguishable
// 404 (not 401), so a probe can't tell the tunnel exists.
func TestHandshake_BadToken(t *testing.T) {
	srv, host, ep, _ := mustStartServer(t)
	defer srv.Stop()

	_, err := client.Run(context.Background(), client.Config{
		Server:             host,
		Endpoint:           ep,
		Token:              "wrong-token",
		LocalTarget:        "127.0.0.1:22",
		InsecureSkipVerify: true,
		Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err == nil {
		t.Fatal("expected error on bad token, got nil")
	}
	// The server returns 404 (not 401) by design.
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("expected 404 in error, got %v", err)
	}
}

// TestDecoy_Site verifies that GET / serves a plausible HTML page, and
// random paths get a plausible 404 — both with Server: nginx headers.
func TestDecoy_Site(t *testing.T) {
	srv, host, _, _ := mustStartServer(t)
	defer srv.Stop()

	hc := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 5 * time.Second,
	}

	t.Run("root", func(t *testing.T) {
		resp, err := hc.Get("https://" + host + "/")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status: got %d want 200", resp.StatusCode)
		}
		if resp.Header.Get("Server") != "nginx/1.24.0" {
			t.Errorf("server header: %q", resp.Header.Get("Server"))
		}
		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "Welcome to nginx") {
			t.Error("decoy page missing expected text")
		}
	})

	t.Run("random_path_404", func(t *testing.T) {
		resp, err := hc.Get("https://" + host + "/some/random/path")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("status: got %d want 404", resp.StatusCode)
		}
		if resp.Header.Get("Server") != "nginx/1.24.0" {
			t.Errorf("server header: %q", resp.Header.Get("Server"))
		}
	})

	t.Run("robots", func(t *testing.T) {
		resp, err := hc.Get("https://" + host + "/robots.txt")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status: got %d want 200", resp.StatusCode)
		}
	})
}

// --- test fixture ---

type runningServer struct {
	cancel context.CancelFunc
	done   chan error
}

func (r *runningServer) Stop() {
	r.cancel()
	<-r.done
}

// mustStartServer brings up a wisp server bound to 127.0.0.1 on a random
// free port, with a self-signed cert. Returns the address as "host:port"
// suitable for client.Config.Server.
func mustStartServer(t *testing.T) (*runningServer, string, string, string) {
	t.Helper()

	// Find a free port up front so we know the address before starting.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	const token = "test-token-very-secret"

	srv, err := server.New(server.Config{
		Listen:            addr,
		Domain:            "localhost",
		Token:             token,
		TLSAutoSelfSigned: true,
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	rs := &runningServer{cancel: cancel, done: make(chan error, 1)}

	go func() {
		err := srv.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			rs.done <- err
			return
		}
		rs.done <- nil
	}()

	// Poll until the server starts accepting TLS connections.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"})
		if err == nil {
			_ = c.Close()
			return rs, addr, srv.Endpoint(), token
		}
		time.Sleep(25 * time.Millisecond)
	}
	rs.Stop()
	t.Fatal("server did not start accepting in time")
	return nil, "", "", ""
}
