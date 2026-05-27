package client_test

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/jasonwwl/wisp/internal/client"
	"github.com/jasonwwl/wisp/internal/shape"
)

// TestShape_E2E_BurstAndChaff: enabling both burst and chaff must not
// break round-trip echo. We don't try to observe the shaped wire here
// — the shape unit tests cover the byte-level behaviour. This is the
// regression that "shape is wired through the stack end-to-end".
func TestShape_E2E_BurstAndChaff(t *testing.T) {
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
		Shape:              shape.Mode{Burst: true, Chaff: true},
		InsecureSkipVerify: true,
		Logger:             quietLogger(),
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	fwdDone := make(chan error, 1)
	go func() { fwdDone <- sess.Forward(ctx) }()

	publicAddr := hostnameOf(host) + ":" + strconv.Itoa(int(sess.PublicPort))

	// Three back-to-back round-trips. Burst should coalesce yamux frames
	// in the client write path; chaff goroutine runs in the background.
	for i := range 3 {
		roundTrip(t, publicAddr, "shape-"+strconv.Itoa(i))
	}

	cancel()
	select {
	case err := <-fwdDone:
		if err != nil {
			t.Errorf("Forward returned: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("Forward did not stop after ctx cancel")
	}
}

// TestShape_E2E_BurstOnly: burst alone, sanity check.
func TestShape_E2E_BurstOnly(t *testing.T) {
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
		Shape:              shape.Mode{Burst: true},
		InsecureSkipVerify: true,
		Logger:             quietLogger(),
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	go func() { _ = sess.Forward(ctx) }()

	publicAddr := hostnameOf(host) + ":" + strconv.Itoa(int(sess.PublicPort))
	roundTrip(t, publicAddr, "burst-only")
}
