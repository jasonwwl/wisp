package server

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/jasonwwl/wisp/internal/frame"
	"github.com/jasonwwl/wisp/internal/mux"
	"github.com/jasonwwl/wisp/internal/protocol"
	"github.com/jasonwwl/wisp/internal/wsraw"
)

const (
	// maxTTLSec is the upper bound a HELLO can request; anything past
	// it is silently clamped down.
	maxTTLSec = 8 * 60 * 60
	// defaultTTLSec is granted when HELLO.RequestedTTL == 0.
	defaultTTLSec = 60 * 60
	// freshBindRetries is how many adjacent ports the fresh fixed-range
	// path will probe past a TIME_WAIT collision.
	freshBindRetries = 8
)

// tunnelHandler is the entry point for /<endpoint>/ws requests. After
// authentication and the WebSocket upgrade, it dispatches to either the
// fresh or resume path, then runs the data plane until lifecycle ends.
// Supports both legacy h1 Upgrade (RFC 6455) and h2 Extended CONNECT
// (RFC 8441); ALPN decides which one the peer used.
func (s *Server) tunnelHandler(w http.ResponseWriter, r *http.Request) {
	log := s.log.With("remote", r.RemoteAddr, "proto", r.Proto)

	if !s.checkAuth(r) {
		s.write404(w)
		log.Warn("tunnel auth failed")
		return
	}

	var (
		wsc      *wsraw.Conn
		hijacked bool
		err      error
	)
	if wsraw.IsH2WebSocket(r) {
		wsc, hijacked, err = wsraw.AcceptH2Upgrade(w, r)
	} else {
		wsc, hijacked, err = wsraw.AcceptUpgrade(w, r)
	}
	if err != nil {
		log.Warn("ws upgrade failed", "err", err, "hijacked", hijacked)
		if !hijacked {
			s.write404(w)
		}
		return
	}
	defer wsc.Close()
	log.Info("client connected")

	// Read HELLO with a deadline so a misbehaving client cannot pin a
	// goroutine forever.
	_ = wsc.SetReadDeadline(time.Now().Add(30 * time.Second))
	helloFrame, err := readControlFrame(wsc)
	if err != nil {
		log.Warn("read hello", "err", err)
		return
	}
	if helloFrame.Type != frame.TypeHello {
		log.Warn("expected hello", "got", helloFrame.Type)
		_ = sendAck(wsc, &protocol.HelloAck{Code: protocol.AckBadHello, Message: "expected hello"})
		return
	}
	hello, err := protocol.DecodeHello(helloFrame.Payload)
	if err != nil {
		log.Warn("decode hello", "err", err)
		_ = sendAck(wsc, &protocol.HelloAck{Code: protocol.AckBadHello, Message: err.Error()})
		return
	}
	log = log.With("session", base64Short(hello.SessionID[:]), "mode", hello.Mode)
	log.Info("hello received",
		"requested_ttl", hello.RequestedTTL,
		"target", hello.Target,
	)

	isResume := hello.Mode == protocol.HelloModeResume

	var (
		entry    *sessionEntry
		listener net.Listener
		port     int
	)

	if isResume {
		entry, listener, port, err = s.acceptResume(wsc, hello, log)
	} else {
		entry, listener, port, err = s.acceptFresh(wsc, hello, log)
	}
	if err != nil {
		// acceptFresh / acceptResume already sent an ack and logged.
		return
	}

	// From here, entry is registered with the registry. Default exit is
	// "unbind so client may resume". Terminal events (TTL, server
	// shutdown) call Evict explicitly; Unbind then becomes a no-op
	// because the entry is no longer in the map.
	defer s.sessions.Unbind(entry.ID())
	defer listener.Close()

	log = log.With("public_port", port, "resume", isResume)
	log.Info("listener up")

	// Reset read deadline now that handshake is done; the data plane
	// runs without an application-layer deadline.
	_ = wsc.SetReadDeadline(time.Time{})

	adapter := mux.New(wsc, 64, "client")
	ycfg := yamux.DefaultConfig()
	ycfg.LogOutput = io.Discard
	ycfg.EnableKeepAlive = true
	ycfg.KeepAliveInterval = 30 * time.Second
	ysess, err := yamux.Server(adapter, ycfg)
	if err != nil {
		log.Warn("yamux server", "err", err)
		// yamux init failure is non-recoverable: the underlying WS is
		// already framed against this peer, and the protocol carries
		// no "retry without resume" affordance. Evict.
		s.sessions.Evict(entry.ID())
		_ = sendAck(wsc, &protocol.HelloAck{Code: protocol.AckInternalError, Message: "yamux init failed"})
		return
	}
	defer ysess.Close()

	// Compute remaining TTL: for a fresh session this is the granted
	// TTL we just minted; for resume it is whatever's left.
	now := time.Now()
	remaining := entry.TTLDeadline().Sub(now)
	if remaining <= 0 {
		log.Warn("ttl already elapsed at ack time")
		s.sessions.Evict(entry.ID())
		_ = sendAck(wsc, &protocol.HelloAck{Code: protocol.AckTTLOutOfRange, Message: "ttl elapsed"})
		return
	}
	if err := sendAck(wsc, &protocol.HelloAck{
		Port:       uint16(port),
		GrantedTTL: uint32(remaining.Round(time.Second).Seconds()),
	}); err != nil {
		log.Warn("write ack", "err", err)
		return
	}
	log.Info("ack sent", "remaining_ttl", remaining)

	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := listener.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) || s.shutdownCtx.Err() != nil {
					return
				}
				log.Warn("accept", "err", err)
				return
			}
			go forwardServerSide(ysess, conn, log)
		}
	}()

	ttlTimer := time.NewTimer(remaining)
	defer ttlTimer.Stop()

	select {
	case <-ttlTimer.C:
		log.Info("ttl expired")
		_ = sendBye(wsc, protocol.ByeTTLExpired, "ttl reached")
		// Give the BYE a moment to leave the socket before we tear down.
		time.Sleep(100 * time.Millisecond)
		s.sessions.Evict(entry.ID())
	case <-ysess.CloseChan():
		log.Info("yamux session closed")
		// Default: entry slides into resume window via the deferred Unbind.
		// On h2 this also fires when the client RSTs the stream because
		// yamux observes the transport break a moment after r.Context()
		// is canceled — kept on this branch deliberately so resume works.
	case <-s.shutdownCtx.Done():
		log.Info("server shutting down, closing tunnel")
		_ = sendBye(wsc, protocol.ByeServerShutdown, "server shutdown")
		s.sessions.Evict(entry.ID())
	}

	_ = listener.Close()
	_ = ysess.Close()
	<-acceptDone
	log.Info("tunnel torn down")
}

// grantTTLSec resolves a client-requested TTL (in seconds) to the TTL
// the server will actually grant. A zero request takes the default; a
// request beyond the ceiling is clamped down to maxTTLSec — NOT reset
// to the default, which would surprisingly shrink an over-ask (e.g. a
// 10h request) below what a smaller in-range ask would have gotten. Any
// in-range request is granted verbatim.
func grantTTLSec(requested uint32) uint32 {
	switch {
	case requested == 0:
		return defaultTTLSec
	case requested > maxTTLSec:
		return maxTTLSec
	default:
		return requested
	}
}

// acceptFresh allocates a port, binds a listener, and registers a fresh
// entry with the session registry. On any failure it sends the
// appropriate ack and returns a non-nil error.
func (s *Server) acceptFresh(wsc *wsraw.Conn, hello *protocol.Hello, log *slog.Logger) (*sessionEntry, net.Listener, int, error) {
	ttl := time.Duration(grantTTLSec(hello.RequestedTTL)) * time.Second

	listener, port, err := s.bindFreshListener(log)
	if err != nil {
		code := protocol.AckInternalError
		msg := err.Error()
		if errors.Is(err, ErrExhausted) {
			code = protocol.AckPortsExhausted
			msg = "no free ports"
		}
		_ = sendAck(wsc, &protocol.HelloAck{Code: code, Message: msg})
		return nil, nil, 0, err
	}

	entry, err := s.sessions.BindFresh(hello.SessionID, port, ttl)
	if err != nil {
		_ = listener.Close()
		s.ports.Release(port)
		code := protocol.AckInternalError
		if errors.Is(err, ErrSessionInUse) {
			code = protocol.AckBadHello
		}
		_ = sendAck(wsc, &protocol.HelloAck{Code: code, Message: err.Error()})
		return nil, nil, 0, err
	}
	return entry, listener, port, nil
}

// bindFreshListener returns a listener bound on a free port, retrying
// adjacent ports past TIME_WAIT collisions in the fixed-range path.
// The returned port has been acquired from the PortAllocator; the
// caller is responsible for ensuring it's transferred to the registry
// (BindFresh) or released on failure.
func (s *Server) bindFreshListener(log *slog.Logger) (net.Listener, int, error) {
	if s.ports.Ephemeral() {
		_, _ = s.ports.Acquire() // always 0
		bindAddr := net.JoinHostPort(s.cfg.TunnelBindHost, "0")
		listener, err := net.Listen("tcp", bindAddr)
		if err != nil {
			log.Warn("ephemeral bind failed", "addr", bindAddr, "err", err)
			return nil, 0, err
		}
		port := 0
		if tcp, ok := listener.Addr().(*net.TCPAddr); ok {
			port = tcp.Port
		}
		return listener, port, nil
	}

	var (
		tried    []int
		listener net.Listener
		port     int
		lastErr  error
	)
	for range freshBindRetries {
		p, err := s.ports.Acquire()
		if err != nil {
			lastErr = err
			break
		}
		bindAddr := net.JoinHostPort(s.cfg.TunnelBindHost, strconv.Itoa(p))
		l, lerr := net.Listen("tcp", bindAddr)
		if lerr == nil {
			listener = l
			port = p
			break
		}
		log.Warn("bind retry", "addr", bindAddr, "err", lerr)
		tried = append(tried, p)
		lastErr = lerr
	}
	for _, p := range tried {
		s.ports.Release(p)
	}
	if listener == nil {
		return nil, 0, lastErr
	}
	return listener, port, nil
}

// acceptResume looks up the entry, rebinds its public port, and
// transitions it back to the bound state. On any failure it sends the
// matching ack and returns a non-nil error.
func (s *Server) acceptResume(wsc *wsraw.Conn, hello *protocol.Hello, log *slog.Logger) (*sessionEntry, net.Listener, int, error) {
	entry, err := s.sessions.BindResume(hello.SessionID)
	if err != nil {
		log.Info("resume rejected", "err", err)
		_ = sendAck(wsc, &protocol.HelloAck{Code: protocol.AckResumeNotFound, Message: "no resumable session"})
		return nil, nil, 0, err
	}

	port := entry.Port()
	bindAddr := net.JoinHostPort(s.cfg.TunnelBindHost, strconv.Itoa(port))
	listener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		// Same-port rebind failed (typically TIME_WAIT in ephemeral mode
		// or external interference). Evict so the session is gone:
		// we cannot honor the "same port" contract.
		log.Warn("resume rebind failed", "addr", bindAddr, "err", err)
		s.sessions.Evict(entry.ID())
		_ = sendAck(wsc, &protocol.HelloAck{Code: protocol.AckInternalError, Message: "rebind failed"})
		return nil, nil, 0, err
	}
	return entry, listener, port, nil
}

func forwardServerSide(ysess *yamux.Session, in net.Conn, log *slog.Logger) {
	defer in.Close()

	stream, err := ysess.OpenStream()
	if err != nil {
		log.Warn("open yamux stream", "err", err)
		return
	}
	defer stream.Close()

	log.Info("stream opened", "remote", in.RemoteAddr())
	bidiCopy(in, stream)
	log.Info("stream closed", "remote", in.RemoteAddr())
}

// bidiCopy copies bytes both ways and returns when either side signals
// EOF or error. Both sides are closed on return.
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
	// Closing one side forces the other Copy to return immediately.
	_ = a.Close()
	_ = b.Close()
	<-done
}

func readControlFrame(c *wsraw.Conn) (frame.Frame, error) {
	msg, err := c.ReadMessage()
	if err != nil {
		return frame.Frame{}, err
	}
	return frame.Decode(bytes.NewReader(msg))
}

func sendAck(c *wsraw.Conn, ack *protocol.HelloAck) error {
	body, err := ack.Encode()
	if err != nil {
		return err
	}
	f := frame.Frame{Type: frame.TypeHelloAck, Payload: body}
	var buf bytes.Buffer
	if err := f.Encode(&buf, 64); err != nil {
		return err
	}
	return c.WriteMessage(buf.Bytes())
}

func sendBye(c *wsraw.Conn, code protocol.ByeCode, msg string) error {
	body, err := (&protocol.Bye{Code: code, Message: msg}).Encode()
	if err != nil {
		return err
	}
	f := frame.Frame{Type: frame.TypeBye, Payload: body}
	var buf bytes.Buffer
	if err := f.Encode(&buf, 64); err != nil {
		return err
	}
	return c.WriteMessage(buf.Bytes())
}

func base64Short(b []byte) string {
	if len(b) > 6 {
		b = b[:6]
	}
	return fmt.Sprintf("%x", b)
}
