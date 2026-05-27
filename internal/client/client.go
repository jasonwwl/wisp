// Package client implements the wisp client: outbound TLS dial, WebSocket
// upgrade against the server's obscured endpoint, the HELLO handshake,
// and (in later milestones) daemonization, multiplexing, and local TCP
// forwarding.
//
// See docs/design.md §3, §6, §8.
package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jasonwwl/wisp/internal/frame"
	"github.com/jasonwwl/wisp/internal/wsraw"
)

// Config configures a single Expose run.
type Config struct {
	// Server is the wisp server: either "host" (TLS on 443) or
	// "host:port". Required.
	Server string

	// Endpoint is the path segment (no leading slash) the server is
	// configured with. Required.
	Endpoint string

	// Token is the shared bearer token. Required.
	Token string

	// LocalTarget is the local TCP address to expose, e.g. "127.0.0.1:22".
	// Required even though the milestone-1 server ignores it; it is sent
	// in HELLO so the server can log what the client claims to be exposing.
	LocalTarget string

	// TTL is the requested tunnel lifetime. The server may grant less.
	TTL time.Duration

	// SessionID is the resume key. If empty, a fresh 32-byte base64url
	// id is generated.
	SessionID string

	// InsecureSkipVerify disables TLS certificate verification.
	// Development use only.
	InsecureSkipVerify bool

	// Logger defaults to slog.Default().
	Logger *slog.Logger
}

// Result is the outcome of a successful HELLO/HELLO_ACK exchange.
type Result struct {
	SessionID string
	AckRaw    []byte // raw HELLO_ACK payload, parsed in a later milestone
}

// Run performs the milestone-1 client flow: dial, upgrade, send HELLO,
// receive HELLO_ACK, close. It returns the parsed result.
func Run(ctx context.Context, cfg Config) (*Result, error) {
	if cfg.Server == "" {
		return nil, errors.New("client: Server is required")
	}
	if cfg.Endpoint == "" {
		return nil, errors.New("client: Endpoint is required")
	}
	if cfg.Token == "" {
		return nil, errors.New("client: Token is required")
	}
	if cfg.LocalTarget == "" {
		return nil, errors.New("client: LocalTarget is required")
	}
	if cfg.TTL == 0 {
		cfg.TTL = time.Hour
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.SessionID == "" {
		id, err := newSessionID()
		if err != nil {
			return nil, fmt.Errorf("session id: %w", err)
		}
		cfg.SessionID = id
	}

	host := cfg.Server
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}
	wsURL := "https://" + host + "/" + cfg.Endpoint + "/ws"

	tlsCfg := &tls.Config{
		ServerName:         hostnameOnly(cfg.Server),
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // dev-only opt-in
	}

	cfg.Logger.Info("dialing wisp server",
		"url", wsURL,
		"session", cfg.SessionID,
		"target", cfg.LocalTarget,
	)

	conn, err := wsraw.Dial(wsraw.DialOptions{
		URL:       wsURL,
		Headers:   map[string]string{"Authorization": "Bearer " + cfg.Token},
		TLSConfig: tlsCfg,
	})
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	// Bound the handshake. Without this, a server that accepts the TCP
	// connection but never sends HELLO_ACK would block Run forever.
	const handshakeTimeout = 30 * time.Second
	deadline := time.Now().Add(handshakeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetReadDeadline(deadline)
	_ = conn.SetWriteDeadline(deadline)

	// Honor ctx cancellation by closing the conn, which unblocks any I/O.
	handshakeDone := make(chan struct{})
	defer close(handshakeDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-handshakeDone:
		}
	}()

	hello := frame.Frame{
		Type:    frame.TypeHello,
		Payload: encodeHelloPayload(cfg.SessionID, cfg.LocalTarget, cfg.TTL),
	}
	var buf bytes.Buffer
	if err := hello.Encode(&buf, 64); err != nil {
		return nil, fmt.Errorf("encode hello: %w", err)
	}
	if err := conn.WriteMessage(buf.Bytes()); err != nil {
		return nil, fmt.Errorf("send hello: %w", err)
	}

	msg, err := conn.ReadMessage()
	if err != nil {
		return nil, fmt.Errorf("read ack: %w", err)
	}
	ack, err := frame.Decode(bytes.NewReader(msg))
	if err != nil {
		return nil, fmt.Errorf("decode ack: %w", err)
	}
	if ack.Type != frame.TypeHelloAck {
		return nil, fmt.Errorf("expected hello_ack, got %s", ack.Type)
	}
	cfg.Logger.Info("ack received", "payload", string(ack.Payload))

	return &Result{SessionID: cfg.SessionID, AckRaw: ack.Payload}, nil
}

// encodeHelloPayload returns a minimal text representation of the HELLO
// fields. A binary format will replace this once the protocol stabilizes;
// for now plain text is easy to debug in tcpdump.
func encodeHelloPayload(sessionID, target string, ttl time.Duration) []byte {
	return []byte(fmt.Sprintf("session=%s;target=%s;ttl=%d",
		sessionID, target, int(ttl.Seconds())))
}

func newSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hostnameOnly(hostPort string) string {
	if i := strings.LastIndex(hostPort, ":"); i >= 0 {
		// careful with IPv6 in brackets, but milestone 1 doesn't worry
		// about that
		if !strings.HasPrefix(hostPort, "[") {
			return hostPort[:i]
		}
	}
	return hostPort
}
