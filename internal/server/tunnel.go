package server

import (
	"bytes"
	"net/http"

	"github.com/jasonwwl/wisp/internal/frame"
	"github.com/jasonwwl/wisp/internal/wsraw"
)

// tunnelHandler handles GET /<endpoint>/ws: token check, WebSocket upgrade,
// and (for now) a single HELLO / HELLO_ACK exchange. Real tunneling is
// added in a later milestone.
func (s *Server) tunnelHandler(w http.ResponseWriter, r *http.Request) {
	log := s.log.With("remote", r.RemoteAddr)

	if !s.checkAuth(r) {
		// Indistinguishable from any other 404 from the decoy site.
		// (timing-equalization is a future hardening, see design.md §4.2)
		w.Header().Set("Server", "nginx/1.24.0")
		w.WriteHeader(http.StatusNotFound)
		log.Warn("tunnel auth failed")
		return
	}

	conn, hijacked, err := wsraw.AcceptUpgrade(w, r)
	if err != nil {
		log.Warn("ws upgrade failed", "err", err, "hijacked", hijacked)
		if !hijacked {
			// Still own the response writer: respond like the decoy 404.
			// This prevents an HTTP/2 probe (or any malformed upgrade) from
			// leaking a distinguishable "weird 200" or default error page.
			w.Header().Set("Server", "nginx/1.24.0")
			w.Header().Set("Content-Type", "text/html; charset=UTF-8")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(builtinNotFound))
		}
		return
	}
	defer conn.Close()

	log.Info("client connected")

	// Step 1+2+3 milestone: do one HELLO / HELLO_ACK round trip, then close.
	// Tunneling itself comes in a later commit.
	msg, err := conn.ReadMessage()
	if err != nil {
		log.Warn("read hello", "err", err)
		return
	}
	hf, err := frame.Decode(bytes.NewReader(msg))
	if err != nil {
		log.Warn("decode hello", "err", err)
		return
	}
	if hf.Type != frame.TypeHello {
		log.Warn("expected hello", "got", hf.Type)
		return
	}
	log.Info("hello received", "payload_len", len(hf.Payload))

	// Respond with a placeholder HELLO_ACK. Real port allocation happens
	// in the forwarding milestone; for now we always answer 22000.
	var ackBuf bytes.Buffer
	ack := frame.Frame{Type: frame.TypeHelloAck, Payload: []byte("port=22000;ttl=3600")}
	if err := ack.Encode(&ackBuf, 64); err != nil {
		log.Error("encode ack", "err", err)
		return
	}
	if err := conn.WriteMessage(ackBuf.Bytes()); err != nil {
		log.Warn("write ack", "err", err)
		return
	}
	log.Info("ack sent")
}
