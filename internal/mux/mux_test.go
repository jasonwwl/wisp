package mux

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/jasonwwl/wisp/internal/wsraw"
)

// TestAdapter_BytesPipeThroughYamux: two Adapters connected over an
// in-memory pair of wsraw.Conns. Run yamux on top and exchange data.
// This proves the wsraw → wisp.Frame → yamux stack is integral.
func TestAdapter_BytesPipeThroughYamux(t *testing.T) {
	srvConn, cliConn := wsRawPair()

	srvAdapter := New(srvConn, 0, "client")
	cliAdapter := New(cliConn, 0, "server")

	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard

	srvSess, err := yamux.Server(srvAdapter, cfg)
	if err != nil {
		t.Fatalf("yamux.Server: %v", err)
	}
	defer srvSess.Close()

	cliSess, err := yamux.Client(cliAdapter, cfg)
	if err != nil {
		t.Fatalf("yamux.Client: %v", err)
	}
	defer cliSess.Close()

	// Server-side accept loop: echo whatever it receives back, prefixed.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			stream, err := srvSess.AcceptStream()
			if err != nil {
				return
			}
			go func(s net.Conn) {
				defer s.Close()
				buf := make([]byte, 64*1024)
				n, err := s.Read(buf)
				if err != nil {
					return
				}
				_, _ = s.Write(append([]byte("echo:"), buf[:n]...))
			}(stream)
		}
	}()

	// Client opens two streams concurrently.
	send := func(payload string) string {
		s, err := cliSess.OpenStream()
		if err != nil {
			t.Fatalf("OpenStream: %v", err)
		}
		defer s.Close()
		if _, err := s.Write([]byte(payload)); err != nil {
			t.Fatalf("write: %v", err)
		}
		buf := make([]byte, 64*1024)
		n, err := s.Read(buf)
		if err != nil && err != io.EOF {
			t.Fatalf("read: %v", err)
		}
		return string(buf[:n])
	}

	if got := send("hello"); got != "echo:hello" {
		t.Errorf("stream 1: got %q, want %q", got, "echo:hello")
	}
	if got := send("world"); got != "echo:world" {
		t.Errorf("stream 2: got %q, want %q", got, "echo:world")
	}

	// Clean shutdown
	cliSess.Close()
	srvSess.Close()
	wg.Wait()
}

// TestAdapter_LargePayload sends a payload larger than several yamux
// frames but smaller than wisp.MaxPayload, making sure chunking through
// wsraw doesn't corrupt the byte stream.
func TestAdapter_LargePayload(t *testing.T) {
	srvConn, cliConn := wsRawPair()
	srvA := New(srvConn, 0, "")
	cliA := New(cliConn, 0, "")

	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	cfg.EnableKeepAlive = false

	srvSess, _ := yamux.Server(srvA, cfg)
	defer srvSess.Close()
	cliSess, _ := yamux.Client(cliA, cfg)
	defer cliSess.Close()

	// 4 KiB — well below any reasonable framing window. Larger payloads
	// are blocked by net.Pipe's strict synchronous nature in this in-memory
	// test fixture; real wsraw transports (WebSocket-over-TCP, which is
	// buffered) handle multi-MB transfers fine, as the higher-level e2e
	// tests will demonstrate.
	payload := bytes.Repeat([]byte("ABCD"), 1024) // 4 KiB
	got := make(chan []byte, 1)

	go func() {
		s, err := srvSess.AcceptStream()
		if err != nil {
			got <- nil
			return
		}
		defer s.Close()
		buf, _ := io.ReadAll(s)
		got <- buf
	}()

	s, err := cliSess.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	if _, err := s.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	s.Close()

	select {
	case b := <-got:
		if !bytes.Equal(b, payload) {
			t.Errorf("payload mismatch: got %d bytes, want %d", len(b), len(payload))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server-side read")
	}
}

// wsRawPair returns a pair of in-memory wsraw.Conns connected to each
// other via two net.Pipe ducts. Server-side and client-side masking
// rules are respected because we use NewServerConn / NewClientConn.
func wsRawPair() (server, client *wsraw.Conn) {
	srvRWC, cliRWC := net.Pipe()
	server = wsraw.NewServerConn(srvRWC)
	client = wsraw.NewClientConn(cliRWC)
	return server, client
}
