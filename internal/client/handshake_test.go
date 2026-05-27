package client_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jasonwwl/wisp/internal/client"
	"github.com/jasonwwl/wisp/internal/server"
)

// TestForward_E2E starts a wisp server, dials a wisp client at it, runs
// a local echo server as the tunnel target, then opens an outside TCP
// connection to the server's public port and verifies the payload
// round-trips through the entire stack:
//
//	external → server public port → yamux stream → wisp frame → wsraw →
//	TLS → wsraw → wisp frame → yamux stream → client → echo server
func TestForward_E2E(t *testing.T) {
	echo := startEchoServer(t)
	defer echo.Close()

	srv, host, ep, token := mustStartServer(t)
	defer srv.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sess, err := client.Dial(ctx, client.Config{
		Server:             host,
		Endpoint:           ep,
		Token:              token,
		LocalTarget:        echo.Addr().String(),
		TTL:                10 * time.Minute,
		InsecureSkipVerify: true,
		Logger:             quietLogger(),
	})
	if err != nil {
		t.Fatalf("client.Dial: %v", err)
	}
	t.Logf("tunnel up: public_port=%d session=%s", sess.PublicPort, sess.SessionID)

	forwardDone := make(chan error, 1)
	go func() { forwardDone <- sess.Forward(ctx) }()

	// External connection to server's public port.
	publicAddr := hostnameOf(host) + ":" + strconv.Itoa(int(sess.PublicPort))
	ext, err := dialWithRetry("tcp", publicAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial public port: %v", err)
	}
	defer ext.Close()

	want := []byte("hello over wisp")
	if _, err := ext.Write(want); err != nil {
		t.Fatalf("ext.Write: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(ext, got); err != nil {
		t.Fatalf("ext.Read: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("echo mismatch: got %q, want %q", got, want)
	}

	cancel()
	select {
	case err := <-forwardDone:
		if err != nil {
			t.Errorf("Forward returned: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("Forward did not stop after ctx cancel")
	}
}

// TestForward_MultipleStreams runs two independent external connections
// concurrently through the same tunnel; both should round-trip.
func TestForward_MultipleStreams(t *testing.T) {
	echo := startEchoServer(t)
	defer echo.Close()

	srv, host, ep, token := mustStartServer(t)
	defer srv.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sess, err := client.Dial(ctx, client.Config{
		Server:             host,
		Endpoint:           ep,
		Token:              token,
		LocalTarget:        echo.Addr().String(),
		InsecureSkipVerify: true,
		Logger:             quietLogger(),
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	go func() { _ = sess.Forward(ctx) }()

	publicAddr := hostnameOf(host) + ":" + strconv.Itoa(int(sess.PublicPort))

	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			c, err := dialWithRetry("tcp", publicAddr, 2*time.Second)
			if err != nil {
				t.Errorf("stream %d dial: %v", n, err)
				return
			}
			defer c.Close()
			payload := []byte("stream-" + strconv.Itoa(n))
			if _, err := c.Write(payload); err != nil {
				t.Errorf("stream %d write: %v", n, err)
				return
			}
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(c, got); err != nil {
				t.Errorf("stream %d read: %v", n, err)
				return
			}
			if string(got) != string(payload) {
				t.Errorf("stream %d: got %q want %q", n, got, payload)
			}
		}(i)
	}
	wg.Wait()
}

// TestDial_BadToken: indistinguishable 404 on the wire side.
func TestDial_BadToken(t *testing.T) {
	srv, host, ep, _ := mustStartServer(t)
	defer srv.Stop()

	_, err := client.Dial(context.Background(), client.Config{
		Server:             host,
		Endpoint:           ep,
		Token:              "wrong-token",
		LocalTarget:        "127.0.0.1:22",
		InsecureSkipVerify: true,
		Logger:             quietLogger(),
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("expected 404 in error, got %v", err)
	}
}

// TestDecoy_Site is unchanged from milestone 1+2+3: GET / serves the
// nginx-style decoy, random paths get 404, robots.txt is plausible.
func TestDecoy_Site(t *testing.T) {
	srv, host, _, _ := mustStartServer(t)
	defer srv.Stop()

	hc := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := hc.Get("https://" + host + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("root: got %d want 200", resp.StatusCode)
	}
	if resp.Header.Get("Server") != "nginx/1.24.0" {
		t.Errorf("server header: %q", resp.Header.Get("Server"))
	}

	resp2, err := hc.Get("https://" + host + "/some/random/path")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != 404 {
		t.Errorf("random path: got %d want 404", resp2.StatusCode)
	}
	if resp2.Header.Get("Server") != "nginx/1.24.0" {
		t.Errorf("random path Server header: %q", resp2.Header.Get("Server"))
	}
}

// --- fixtures ---

type runningServer struct {
	cancel context.CancelFunc
	done   chan error
}

func (r *runningServer) Stop() {
	r.cancel()
	<-r.done
}

func mustStartServer(t *testing.T) (*runningServer, string, string, string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	const token = "test-token-very-secret"

	// Use a high port range that's almost certainly free; bind to
	// localhost so we don't open ports on the listening interface.
	srv, err := server.New(server.Config{
		Listen:            addr,
		Domain:            "localhost",
		Token:             token,
		PortRange:         randomPortRange(),
		TunnelBindHost:    "127.0.0.1",
		TLSAutoSelfSigned: true,
		Logger:            quietLogger(),
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

// randomPortRange picks a 100-port slice in the high range to reduce
// collision chances during parallel test runs.
var portRangeCounter int

func randomPortRange() string {
	// Stagger ranges per call to avoid intra-test-run collisions.
	portRangeCounter++
	lo := 50000 + (portRangeCounter*200)%10000
	hi := lo + 99
	return strconv.Itoa(lo) + "-" + strconv.Itoa(hi)
}

func hostnameOf(hostPort string) string {
	if i := strings.LastIndex(hostPort, ":"); i >= 0 {
		return hostPort[:i]
	}
	return hostPort
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// echoServer is a tiny TCP echo used as the tunnel target.
type echoServer struct {
	l net.Listener
}

func startEchoServer(t *testing.T) *echoServer {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return &echoServer{l: l}
}

func (e *echoServer) Addr() net.Addr { return e.l.Addr() }
func (e *echoServer) Close() error   { return e.l.Close() }

func dialWithRetry(network, addr string, timeout time.Duration) (net.Conn, error) {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout(network, addr, 200*time.Millisecond)
		if err == nil {
			return c, nil
		}
		last = err
		time.Sleep(50 * time.Millisecond)
	}
	return nil, last
}
