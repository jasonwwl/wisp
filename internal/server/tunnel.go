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

// tunnelHandler is the entry point for /<endpoint>/ws requests. After
// authentication and the WebSocket upgrade, it:
//  1. reads the HELLO control frame from the client;
//  2. acquires a public TCP port from the allocator;
//  3. binds a listener on that port (cfg.TunnelBindHost);
//  4. spins up a yamux server session on the tunnel;
//  5. writes HELLO_ACK with the chosen port;
//  6. forwards every incoming TCP connection to a new yamux stream;
//  7. blocks until either side closes, then releases the port.
func (s *Server) tunnelHandler(w http.ResponseWriter, r *http.Request) {
	log := s.log.With("remote", r.RemoteAddr)

	if !s.checkAuth(r) {
		w.Header().Set("Server", "nginx/1.24.0")
		w.WriteHeader(http.StatusNotFound)
		log.Warn("tunnel auth failed")
		return
	}

	wsc, hijacked, err := wsraw.AcceptUpgrade(w, r)
	if err != nil {
		log.Warn("ws upgrade failed", "err", err, "hijacked", hijacked)
		if !hijacked {
			w.Header().Set("Server", "nginx/1.24.0")
			w.Header().Set("Content-Type", "text/html; charset=UTF-8")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(builtinNotFound))
		}
		return
	}
	defer wsc.Close()
	log.Info("client connected")

	// 1. Read HELLO (with a deadline so a misbehaving client cannot pin
	//    a goroutine forever).
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
	log = log.With("session", base64Short(hello.SessionID[:]), "target", hello.Target)
	log.Info("hello received", "requested_ttl", hello.RequestedTTL)

	// 2-3. Allocate a public port and bind a listener.
	//
	// In ephemeral mode the allocator returns 0 and we let the kernel
	// pick a port at bind time; that path bypasses TIME_WAIT collisions
	// entirely and is what we use in tests.
	//
	// In fixed-range mode the allocator's in-memory map can hand out a
	// port that's still in TIME_WAIT from a previous tunnel, so we
	// retry the next few free ports before giving up.
	var (
		port     int
		listener net.Listener
		bindAddr string
	)
	if s.ports.Ephemeral() {
		port, _ = s.ports.Acquire() // always 0
		bindAddr = net.JoinHostPort(s.cfg.TunnelBindHost, "0")
		listener, err = net.Listen("tcp", bindAddr)
		if err != nil {
			log.Warn("ephemeral bind failed", "addr", bindAddr, "err", err)
			_ = sendAck(wsc, &protocol.HelloAck{Code: protocol.AckInternalError, Message: "bind failed"})
			return
		}
	} else {
		const maxBindTries = 8
		tried := make([]int, 0, maxBindTries)
		for i := 0; i < maxBindTries; i++ {
			port, err = s.ports.Acquire()
			if err != nil {
				break // exhausted
			}
			bindAddr = net.JoinHostPort(s.cfg.TunnelBindHost, strconv.Itoa(port))
			listener, err = net.Listen("tcp", bindAddr)
			if err == nil {
				break
			}
			log.Warn("bind retry", "addr", bindAddr, "err", err)
			tried = append(tried, port)
		}
		for _, p := range tried {
			s.ports.Release(p)
		}
		if listener == nil {
			log.Warn("could not bind any port in range", "tried", len(tried)+1, "last_err", err)
			_ = sendAck(wsc, &protocol.HelloAck{Code: protocol.AckInternalError, Message: "no free port could be bound"})
			if port > 0 {
				s.ports.Release(port)
			}
			return
		}
	}
	defer s.ports.Release(port)
	defer listener.Close()

	// Re-derive the bound port from the listener (helps in the case where
	// the operator used "0" to mean "ephemeral").
	if tcp, ok := listener.Addr().(*net.TCPAddr); ok {
		port = tcp.Port
	}
	log = log.With("public_port", port)
	log.Info("listener up")

	// Reset deadlines now that handshake is done. The tunnel itself
	// should NOT have application-layer read/write deadlines on the
	// underlying WS — yamux runs forever on it.
	_ = wsc.SetReadDeadline(time.Time{})

	// 4. Build the yamux session over the wsraw conn.
	adapter := mux.New(wsc, 64, "client")
	ycfg := yamux.DefaultConfig()
	ycfg.LogOutput = io.Discard
	ycfg.EnableKeepAlive = true
	ycfg.KeepAliveInterval = 30 * time.Second
	ysess, err := yamux.Server(adapter, ycfg)
	if err != nil {
		log.Warn("yamux server", "err", err)
		_ = sendAck(wsc, &protocol.HelloAck{Code: protocol.AckInternalError, Message: "yamux init failed"})
		return
	}
	defer ysess.Close()

	// 5. Send HELLO_ACK. The TTL we grant is the requested TTL clamped
	//    to the server's policy (kept simple here; future hardening).
	grantedTTL := hello.RequestedTTL
	if grantedTTL == 0 || grantedTTL > 8*60*60 {
		grantedTTL = 60 * 60
	}
	if err := sendAck(wsc, &protocol.HelloAck{
		Port:       uint16(port),
		GrantedTTL: grantedTTL,
	}); err != nil {
		log.Warn("write ack", "err", err)
		return
	}
	log.Info("ack sent", "granted_ttl", grantedTTL)

	// 6. Run the accept loop in a goroutine; the main goroutine waits
	//    for whichever lifecycle signal fires first.
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := listener.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) || r.Context().Err() != nil {
					return
				}
				log.Warn("accept", "err", err)
				return
			}
			go forwardServerSide(ysess, conn, log)
		}
	}()

	// 7. Lifecycle: shut the tunnel down on TTL expiry, on yamux death,
	//    or on server-wide shutdown.
	ttlTimer := time.NewTimer(time.Duration(grantedTTL) * time.Second)
	defer ttlTimer.Stop()

	select {
	case <-ttlTimer.C:
		log.Info("ttl expired")
		// Tell the client politely; ignore errors (it may already be gone).
		_ = sendBye(wsc, protocol.ByeTTLExpired, "ttl reached")
		// Brief drain window so the BYE has a chance to leave the kernel
		// buffer before we slam the underlying conn shut.
		time.Sleep(100 * time.Millisecond)
	case <-ysess.CloseChan():
		log.Info("yamux session closed")
	case <-r.Context().Done():
		log.Info("server shutting down, closing tunnel")
		_ = sendBye(wsc, protocol.ByeServerShutdown, "server shutdown")
	}

	_ = listener.Close()
	_ = ysess.Close()
	<-acceptDone
	log.Info("tunnel torn down")
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
