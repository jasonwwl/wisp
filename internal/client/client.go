// Package client implements the wisp client: outbound TLS dial, the
// WebSocket upgrade against the server's obscured endpoint, the HELLO
// handshake, and (once Forward is called) the per-stream local-target
// dialing loop.
//
// See docs/design.md §3 (wire protocol), §6 (liveness), §8 (daemonization).
package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/jasonwwl/wisp/internal/frame"
	"github.com/jasonwwl/wisp/internal/mux"
	"github.com/jasonwwl/wisp/internal/protocol"
	"github.com/jasonwwl/wisp/internal/wsraw"
)

// Config configures a single Dial.
type Config struct {
	// Server is the wisp server (host, or host:port). Required.
	Server string

	// Endpoint is the obscured path segment configured on the server.
	// Required.
	Endpoint string

	// Token is the shared bearer token. Required.
	Token string

	// LocalTarget is the local TCP address that each incoming yamux
	// stream will be forwarded to (e.g. "127.0.0.1:22"). Required.
	LocalTarget string

	// TTL is the requested tunnel lifetime. The server may grant less.
	// Zero defaults to 1 hour.
	TTL time.Duration

	// SessionID is the resume id. Empty generates a fresh 32-byte
	// base64url id.
	SessionID string

	// InsecureSkipVerify disables TLS certificate verification.
	// Development use only.
	InsecureSkipVerify bool

	// Logger defaults to slog.Default().
	Logger *slog.Logger
}

// Session is an established wisp tunnel. The handshake is complete;
// data plane is live; call Forward to start the accept-and-dial loop.
type Session struct {
	cfg    Config
	wsConn *wsraw.Conn
	ysess  *yamux.Session

	// Negotiated parameters returned by the server.
	SessionID  string
	PublicPort uint16
	GrantedTTL time.Duration
}

// Dial performs the full handshake and returns a live Session. The
// caller is expected to print the negotiated PublicPort to the user
// and then call Forward (which blocks).
func Dial(ctx context.Context, cfg Config) (*Session, error) {
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

	wsc, err := wsraw.Dial(wsraw.DialOptions{
		URL:       wsURL,
		Headers:   map[string]string{"Authorization": "Bearer " + cfg.Token},
		TLSConfig: tlsCfg,
	})
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	// Bound the handshake. ctx cancellation closes the conn so I/O wakes.
	const handshakeTimeout = 30 * time.Second
	deadline := time.Now().Add(handshakeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = wsc.SetReadDeadline(deadline)
	_ = wsc.SetWriteDeadline(deadline)

	handshakeDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = wsc.Close()
		case <-handshakeDone:
		}
	}()

	// Send HELLO.
	hello := &protocol.Hello{
		RequestedTTL: uint32(cfg.TTL.Seconds()),
		Target:       cfg.LocalTarget,
	}
	if err := decodeSessionID(cfg.SessionID, &hello.SessionID); err != nil {
		close(handshakeDone)
		_ = wsc.Close()
		return nil, fmt.Errorf("session id decode: %w", err)
	}
	if _, err := rand.Read(hello.Nonce[:]); err != nil {
		close(handshakeDone)
		_ = wsc.Close()
		return nil, err
	}
	helloBody, _ := hello.Encode()
	if err := writeFrame(wsc, frame.Frame{Type: frame.TypeHello, Payload: helloBody}); err != nil {
		close(handshakeDone)
		_ = wsc.Close()
		return nil, fmt.Errorf("send hello: %w", err)
	}

	// Read HELLO_ACK.
	ackFrame, err := readFrame(wsc)
	if err != nil {
		close(handshakeDone)
		_ = wsc.Close()
		return nil, fmt.Errorf("read ack: %w", err)
	}
	close(handshakeDone)
	if ackFrame.Type != frame.TypeHelloAck {
		_ = wsc.Close()
		return nil, fmt.Errorf("expected hello_ack, got %s", ackFrame.Type)
	}
	ack, err := protocol.DecodeHelloAck(ackFrame.Payload)
	if err != nil {
		_ = wsc.Close()
		return nil, fmt.Errorf("decode ack: %w", err)
	}
	if ack.Code != protocol.AckOK {
		_ = wsc.Close()
		return nil, fmt.Errorf("server rejected hello (code %d): %s", ack.Code, ack.Message)
	}

	// Reset deadlines for the data plane.
	_ = wsc.SetReadDeadline(time.Time{})
	_ = wsc.SetWriteDeadline(time.Time{})

	// Build yamux client session on top of the wsraw conn.
	adapter := mux.New(wsc, 64, "server")
	ycfg := yamux.DefaultConfig()
	ycfg.LogOutput = io.Discard
	ycfg.EnableKeepAlive = true
	ycfg.KeepAliveInterval = 30 * time.Second
	ysess, err := yamux.Client(adapter, ycfg)
	if err != nil {
		_ = wsc.Close()
		return nil, fmt.Errorf("yamux client: %w", err)
	}

	cfg.Logger.Info("tunnel up",
		"public_port", ack.Port,
		"granted_ttl_sec", ack.GrantedTTL,
		"session", cfg.SessionID,
	)

	return &Session{
		cfg:        cfg,
		wsConn:     wsc,
		ysess:      ysess,
		SessionID:  cfg.SessionID,
		PublicPort: ack.Port,
		GrantedTTL: time.Duration(ack.GrantedTTL) * time.Second,
	}, nil
}

// Forward blocks accepting yamux streams from the server, dialing the
// local target for each, and copying bytes both ways until ctx is
// canceled or the session dies.
func (s *Session) Forward(ctx context.Context) error {
	defer s.Close()

	// Stop accepting (and close existing streams' Read) when ctx ends.
	go func() {
		select {
		case <-ctx.Done():
			_ = s.ysess.Close()
		case <-s.ysess.CloseChan():
		}
	}()

	for {
		stream, err := s.ysess.AcceptStream()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, io.EOF) || errors.Is(err, yamux.ErrSessionShutdown) {
				return nil
			}
			return fmt.Errorf("accept stream: %w", err)
		}
		go s.forwardOne(stream)
	}
}

func (s *Session) forwardOne(stream net.Conn) {
	defer stream.Close()
	target, err := net.Dial("tcp", s.cfg.LocalTarget)
	if err != nil {
		s.cfg.Logger.Warn("dial local target", "target", s.cfg.LocalTarget, "err", err)
		return
	}
	defer target.Close()
	s.cfg.Logger.Info("stream opened")
	bidiCopy(stream, target)
	s.cfg.Logger.Info("stream closed")
}

// Close tears the session down. Safe to call multiple times.
func (s *Session) Close() error {
	if s.ysess != nil {
		_ = s.ysess.Close()
	}
	if s.wsConn != nil {
		_ = s.wsConn.Close()
	}
	return nil
}

// --- helpers ---

func writeFrame(c *wsraw.Conn, f frame.Frame) error {
	var buf bytes.Buffer
	if err := f.Encode(&buf, 64); err != nil {
		return err
	}
	return c.WriteMessage(buf.Bytes())
}

func readFrame(c *wsraw.Conn) (frame.Frame, error) {
	msg, err := c.ReadMessage()
	if err != nil {
		return frame.Frame{}, err
	}
	return frame.Decode(bytes.NewReader(msg))
}

func bidiCopy(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(b, a)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(a, b)
		done <- struct{}{}
	}()
	<-done
	_ = a.Close()
	_ = b.Close()
	<-done
}

func newSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// decodeSessionID parses a base64url-no-padding 32-byte session id into
// dst. Used so the wire format stays binary while the user-facing form
// stays printable.
func decodeSessionID(s string, dst *[32]byte) error {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	if len(b) != 32 {
		return fmt.Errorf("session id must decode to 32 bytes (got %d)", len(b))
	}
	copy(dst[:], b)
	return nil
}

func hostnameOnly(hostPort string) string {
	if i := strings.LastIndex(hostPort, ":"); i >= 0 {
		if !strings.HasPrefix(hostPort, "[") {
			return hostPort[:i]
		}
	}
	return hostPort
}
