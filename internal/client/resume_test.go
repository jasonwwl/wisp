package client_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/jasonwwl/wisp/internal/client"
	"github.com/jasonwwl/wisp/internal/protocol"
	"github.com/jasonwwl/wisp/internal/server"
)

// startServerWithResumeWindow is mustStartServer with a knob for the
// per-session resume window. Resume tests need a short window to keep
// total runtime tractable.
func startServerWithResumeWindow(t *testing.T, resumeWindow time.Duration) (*runningServer, string, string, string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	const token = "test-token-resume"

	srv, err := server.New(server.Config{
		Listen:            addr,
		Domain:            "localhost",
		Token:             token,
		PortRange:         "auto",
		TunnelBindHost:    "127.0.0.1",
		TLSAutoSelfSigned: true,
		ResumeWindow:      resumeWindow,
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

// TestResume_HappyPath: fresh dial, kill underlying WS, redial with
// mode=resume and same SessionID; the server must return the same
// public port and the tunnel must round-trip traffic again.
func TestResume_HappyPath(t *testing.T) {
	echo := startEchoServer(t)
	defer echo.Close()

	srv, host, ep, token := startServerWithResumeWindow(t, 30*time.Second)
	defer srv.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sess1, err := client.Dial(ctx, client.Config{
		Server:             host,
		Endpoint:           ep,
		Token:              token,
		LocalTarget:        echo.Addr().String(),
		TTL:                10 * time.Minute,
		InsecureSkipVerify: true,
		Logger:             quietLogger(),
	})
	if err != nil {
		t.Fatalf("first Dial: %v", err)
	}
	port1 := sess1.PublicPort
	sessionID := sess1.SessionID
	t.Logf("first tunnel: port=%d session=%s", port1, sessionID)

	fwd1Done := make(chan error, 1)
	fwdCtx1, fwdCancel1 := context.WithCancel(ctx)
	go func() { fwd1Done <- sess1.Forward(fwdCtx1) }()

	publicAddr := hostnameOf(host) + ":" + strconv.Itoa(int(port1))
	roundTrip(t, publicAddr, "before-resume")

	// Simulate a network drop. Closing the session forces Forward to
	// return; on the server side, the WS read errors and tunnelHandler
	// flows through ysess.CloseChan → Unbind (entry enters resume window).
	sess1.Close()
	fwdCancel1()
	select {
	case <-fwd1Done:
	case <-time.After(3 * time.Second):
		t.Fatal("Forward did not return after Close")
	}

	// Server needs a moment to observe ws close, run Unbind, free the
	// listener so we can rebind on resume.
	time.Sleep(200 * time.Millisecond)

	sess2, err := client.Dial(ctx, client.Config{
		Server:             host,
		Endpoint:           ep,
		Token:              token,
		LocalTarget:        echo.Addr().String(),
		TTL:                10 * time.Minute, // requested ttl is ignored on resume
		SessionID:          sessionID,
		InitialMode:        protocol.HelloModeResume,
		InsecureSkipVerify: true,
		Logger:             quietLogger(),
	})
	if err != nil {
		t.Fatalf("resume Dial: %v", err)
	}
	defer sess2.Close()

	if sess2.PublicPort != port1 {
		t.Errorf("resume port: got %d, want %d (same)", sess2.PublicPort, port1)
	}
	if sess2.SessionID != sessionID {
		t.Errorf("session id changed across resume: got %q, want %q", sess2.SessionID, sessionID)
	}

	go func() { _ = sess2.Forward(ctx) }()
	roundTrip(t, publicAddr, "after-resume")
}

// TestResume_WindowExpired_Rejects: when the disconnected session has
// fallen out of the resume window, a resume Dial must get AckResumeNotFound.
func TestResume_WindowExpired_Rejects(t *testing.T) {
	srv, host, ep, token := startServerWithResumeWindow(t, 100*time.Millisecond)
	defer srv.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sess1, err := client.Dial(ctx, client.Config{
		Server:             host,
		Endpoint:           ep,
		Token:              token,
		LocalTarget:        "127.0.0.1:1", // unused; this test never opens a stream
		TTL:                10 * time.Minute,
		InsecureSkipVerify: true,
		Logger:             quietLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	sessionID := sess1.SessionID
	sess1.Close()

	// Wait out the resume window plus slack.
	time.Sleep(400 * time.Millisecond)

	_, err = client.Dial(ctx, client.Config{
		Server:             host,
		Endpoint:           ep,
		Token:              token,
		LocalTarget:        "127.0.0.1:1",
		SessionID:          sessionID,
		InitialMode:        protocol.HelloModeResume,
		InsecureSkipVerify: true,
		Logger:             quietLogger(),
	})
	var ackErr *client.AckError
	if !errors.As(err, &ackErr) {
		t.Fatalf("want *AckError, got %v", err)
	}
	if ackErr.Code != protocol.AckResumeNotFound {
		t.Errorf("code: got %d, want %d", ackErr.Code, protocol.AckResumeNotFound)
	}
}

// TestResume_StillBound_Rejects: while a session is actively bound to a
// live WS, a second client cannot hijack it via mode=resume.
func TestResume_StillBound_Rejects(t *testing.T) {
	echo := startEchoServer(t)
	defer echo.Close()

	srv, host, ep, token := startServerWithResumeWindow(t, 30*time.Second)
	defer srv.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sess1, err := client.Dial(ctx, client.Config{
		Server:             host,
		Endpoint:           ep,
		Token:              token,
		LocalTarget:        echo.Addr().String(),
		TTL:                10 * time.Minute,
		InsecureSkipVerify: true,
		Logger:             quietLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sess1.Close()
	go func() { _ = sess1.Forward(ctx) }()

	// Don't close sess1. Attempt to resume with the same id.
	_, err = client.Dial(ctx, client.Config{
		Server:             host,
		Endpoint:           ep,
		Token:              token,
		LocalTarget:        echo.Addr().String(),
		SessionID:          sess1.SessionID,
		InitialMode:        protocol.HelloModeResume,
		InsecureSkipVerify: true,
		Logger:             quietLogger(),
	})
	var ackErr *client.AckError
	if !errors.As(err, &ackErr) {
		t.Fatalf("want *AckError, got %v", err)
	}
	if ackErr.Code != protocol.AckResumeNotFound {
		t.Errorf("code: got %d, want %d", ackErr.Code, protocol.AckResumeNotFound)
	}
}

// TestResume_TTLExpired_Rejects: once the original grant has elapsed,
// no resume can succeed — TTL is absolute and does not extend.
func TestResume_TTLExpired_Rejects(t *testing.T) {
	srv, host, ep, token := startServerWithResumeWindow(t, 10*time.Second)
	defer srv.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sess1, err := client.Dial(ctx, client.Config{
		Server:             host,
		Endpoint:           ep,
		Token:              token,
		LocalTarget:        "127.0.0.1:1",
		TTL:                1 * time.Second,
		InsecureSkipVerify: true,
		Logger:             quietLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	sessionID := sess1.SessionID
	sess1.Close()

	time.Sleep(2 * time.Second)

	_, err = client.Dial(ctx, client.Config{
		Server:             host,
		Endpoint:           ep,
		Token:              token,
		LocalTarget:        "127.0.0.1:1",
		SessionID:          sessionID,
		InitialMode:        protocol.HelloModeResume,
		InsecureSkipVerify: true,
		Logger:             quietLogger(),
	})
	var ackErr *client.AckError
	if !errors.As(err, &ackErr) {
		t.Fatalf("want *AckError, got %v", err)
	}
	if ackErr.Code != protocol.AckResumeNotFound {
		t.Errorf("code: got %d, want %d", ackErr.Code, protocol.AckResumeNotFound)
	}
}

// TestResume_AutoRun_SurvivesDisconnect: Session.Run with AutoResume=true
// transparently reconnects with the same public port after a network
// disconnect, with no caller intervention.
func TestResume_AutoRun_SurvivesDisconnect(t *testing.T) {
	echo := startEchoServer(t)
	defer echo.Close()

	srv, host, ep, token := startServerWithResumeWindow(t, 30*time.Second)
	defer srv.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sess, err := client.Dial(ctx, client.Config{
		Server:             host,
		Endpoint:           ep,
		Token:              token,
		LocalTarget:        echo.Addr().String(),
		TTL:                10 * time.Minute,
		AutoResume:         true,
		InsecureSkipVerify: true,
		Logger:             quietLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	port := sess.PublicPort
	publicAddr := hostnameOf(host) + ":" + strconv.Itoa(int(port))

	runDone := make(chan error, 1)
	go func() { runDone <- sess.Run(ctx) }()

	roundTrip(t, publicAddr, "pre-disconnect")

	// Simulate a transport-layer disconnect. Forward returns; Run sees
	// ctx still alive, kicks off redialResume.
	sess.Close()

	// Wait until traffic round-trips again on the same public port.
	// We poll because the resume dial + backoff has nondeterministic
	// timing, but it should succeed within ~3 seconds (initial backoff
	// is 1s and we don't expect transport failures here).
	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		c, derr := net.DialTimeout("tcp", publicAddr, 250*time.Millisecond)
		if derr != nil {
			lastErr = derr
			time.Sleep(100 * time.Millisecond)
			continue
		}
		_ = c.SetDeadline(time.Now().Add(500 * time.Millisecond))
		if _, werr := c.Write([]byte("post-resume")); werr != nil {
			_ = c.Close()
			lastErr = werr
			time.Sleep(100 * time.Millisecond)
			continue
		}
		buf := make([]byte, len("post-resume"))
		if _, rerr := io.ReadFull(c, buf); rerr != nil {
			_ = c.Close()
			lastErr = rerr
			time.Sleep(100 * time.Millisecond)
			continue
		}
		_ = c.Close()
		if string(buf) == "post-resume" {
			lastErr = nil
			break
		}
	}
	if lastErr != nil {
		t.Fatalf("post-resume round-trip never succeeded; last err: %v", lastErr)
	}

	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Errorf("Run returned: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("Run did not return after ctx cancel")
	}
}

// roundTrip dials publicAddr, writes payload, expects echo, errors fatal.
func roundTrip(t *testing.T, publicAddr, payload string) {
	t.Helper()
	c, err := dialWithRetry("tcp", publicAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", publicAddr, err)
	}
	defer c.Close()
	if _, err := c.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != payload {
		t.Errorf("echo: got %q, want %q", got, payload)
	}
}
