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
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/jasonwwl/wisp/internal/frame"
	"github.com/jasonwwl/wisp/internal/mux"
	"github.com/jasonwwl/wisp/internal/protocol"
	"github.com/jasonwwl/wisp/internal/shape"
	"github.com/jasonwwl/wisp/internal/wsraw"
)

// AckError is returned by Dial when the server completed the WebSocket
// upgrade but rejected the HELLO with a non-OK ack code. Callers (most
// importantly Session.Run) can switch on Code to decide policy: a
// resume-not-found is terminal, a transient port-bind failure is not
// retried because the server already evicted the session.
type AckError struct {
	Code    protocol.AckCode
	Message string
}

func (e *AckError) Error() string {
	return fmt.Sprintf("server hello_ack code %d: %s", e.Code, e.Message)
}

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
	// base64url id. When InitialMode == HelloModeResume this must be
	// the id of a server-side session inside its resume window.
	SessionID string

	// InitialMode is the HELLO mode used on the very first Dial. Defaults
	// to HelloModeFresh. Set to HelloModeResume (with non-empty SessionID)
	// to attach to an existing server-side session — typically after a
	// daemon restart.
	InitialMode protocol.HelloMode

	// AutoResume, when true, makes Session.Run reconnect with mode=resume
	// on transient WS/yamux death. Network errors get exponential backoff;
	// any non-OK ack from the server is terminal (a re-attempt cannot
	// succeed since the server's view is authoritative).
	AutoResume bool

	// Shape selects traffic-shaping primitives applied to the outbound
	// wsraw write path. Zero value (both bits false) is v0.1 pass-through.
	// Burst coalesces small frames within a short window; Chaff emits
	// low-rate dummy frames during idle periods. See docs/design.md §7.
	Shape shape.Mode

	// InsecureSkipVerify disables TLS certificate verification.
	// Development use only.
	InsecureSkipVerify bool

	// Logger defaults to slog.Default().
	Logger *slog.Logger
}

// Session is an established wisp tunnel. The handshake is complete;
// data plane is live; call Forward (or Run for auto-resume) to start
// the accept-and-dial loop.
type Session struct {
	cfg    Config
	wsConn *wsraw.Conn
	ysess  *yamux.Session

	closeOnce sync.Once

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
		Mode:         cfg.InitialMode,
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
		return nil, &AckError{Code: ack.Code, Message: ack.Message}
	}

	// Reset deadlines for the data plane.
	_ = wsc.SetReadDeadline(time.Time{})
	_ = wsc.SetWriteDeadline(time.Time{})

	// Build yamux client session on top of the wsraw conn.
	var adapter *mux.Adapter
	if cfg.Shape.Empty() {
		adapter = mux.New(wsc, 64, "server")
	} else {
		adapter = mux.NewWithShape(wsc, 64, "server", shape.Config{
			Mode:       cfg.Shape,
			MaxPayload: frame.MaxPayload - 64, // leave headroom for header + padding
		})
	}
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

// Run is Forward plus auto-resume. When Config.AutoResume is false it
// is identical to Forward. Otherwise it reconnects with mode=resume on
// transient WS/yamux death, retrying network errors with exponential
// backoff and bailing out on any non-OK ack from the server (a value
// the server is authoritative about).
//
// Run returns nil on ctx cancellation, TTL exhaustion, or server-side
// session termination (BYE → BindResume → AckResumeNotFound). It
// returns the underlying ack error for other terminal cases so callers
// can render a useful message.
func (s *Session) Run(ctx context.Context) error {
	if !s.cfg.AutoResume {
		return s.Forward(ctx)
	}

	// Wall-clock cap on retries: when the original grant elapses,
	// further resume attempts cannot succeed anyway. Slack the
	// deadline by 5s so a client whose clock drifts slightly ahead
	// still hands the server a chance to refuse cleanly.
	deadline := time.Now().Add(s.GrantedTTL).Add(5 * time.Second)

	current := s
	for {
		forwardErr := current.Forward(ctx)
		_ = forwardErr // intentionally ignored; resume decides what to do

		if ctx.Err() != nil {
			return nil
		}
		if !time.Now().Before(deadline) {
			current.cfg.Logger.Info("tunnel ttl exhausted, exiting auto-resume")
			return nil
		}

		current.cfg.Logger.Info("connection lost, attempting resume",
			"session", current.SessionID,
		)

		next, err := redialResume(ctx, current.cfg, current.SessionID, deadline)
		if err != nil {
			return err
		}
		if next == nil {
			// ctx canceled or deadline reached inside backoff; either way exit clean.
			return nil
		}
		current = next
	}
}

// redialResume reconnects with mode=resume, backing off exponentially
// on transport-layer errors and short-circuiting on AckError (which
// the server has no way to retract). Returns (nil, nil) when ctx ends
// or the wall-clock deadline arrives mid-backoff; (nil, *AckError) for
// terminal server refusals; (sess, nil) on success.
func redialResume(ctx context.Context, base Config, sessionID string, deadline time.Time) (*Session, error) {
	backoff := time.Second
	const maxBackoff = 30 * time.Second

	cfg := base
	cfg.SessionID = sessionID
	cfg.InitialMode = protocol.HelloModeResume
	cfg.AutoResume = false // redialResume is the resume primitive itself

	for {
		dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		sess, err := Dial(dialCtx, cfg)
		cancel()
		if err == nil {
			return sess, nil
		}
		if ctx.Err() != nil {
			return nil, nil
		}

		var ackErr *AckError
		if errors.As(err, &ackErr) {
			base.Logger.Info("resume rejected by server",
				"code", ackErr.Code,
				"msg", ackErr.Message,
			)
			return nil, err
		}

		if !time.Now().Add(backoff).Before(deadline) {
			base.Logger.Info("tunnel ttl exhausted during resume backoff")
			return nil, nil
		}
		base.Logger.Warn("resume dial failed, retrying",
			"err", err,
			"backoff", backoff,
		)
		select {
		case <-ctx.Done():
			return nil, nil
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
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

// Close tears the session down. Safe to call multiple times and from
// multiple goroutines.
func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		if s.ysess != nil {
			_ = s.ysess.Close()
		}
		if s.wsConn != nil {
			_ = s.wsConn.Close()
		}
	})
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
