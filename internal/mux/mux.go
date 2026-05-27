// Package mux turns a single wsraw.Conn into a net.Conn-compatible
// byte-stream so that a multiplexer (currently github.com/hashicorp/yamux)
// can carry many independent TCP streams over the WebSocket tunnel.
//
// Wire layout from the multiplexer's point of view:
//
//	yamux frame → wisp.Frame{Type=Yamux, Payload=...} → wsraw binary
//	  message → TLS WebSocket frame.
//
// Control wisp frames (PING, PONG, BYE) intermixed with data frames are
// accepted on the read side but currently ignored at the mux layer;
// liveness and shutdown handling moves into this package in a later
// milestone.
package mux

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/jasonwwl/wisp/internal/frame"
	"github.com/jasonwwl/wisp/internal/shape"
	"github.com/jasonwwl/wisp/internal/wsraw"
)

// Adapter wraps a wsraw.Conn in net.Conn shape.
//
// Concurrency: Read may be called from one goroutine and Write from
// another, matching yamux's expectation of an independent reader and
// writer loop. Multiple concurrent calls to Read (or to Write) are
// serialized internally.
//
// When a shaper is attached (NewWithShape) it sits in front of the
// write path: yamux frames go to shaper.Write, which decides whether
// to forward immediately or coalesce within a burst window. The
// shaper also drives idle-period chaff via SendChaff.
type Adapter struct {
	conn       *wsraw.Conn
	padding    int
	remoteName string
	shaper     *shape.Shaper // nil = pass-through

	readMu  sync.Mutex
	readBuf bytes.Buffer

	writeMu sync.Mutex
}

// New wraps conn. padTarget is the maximum random padding (in bytes,
// 0–255) added to each outbound wisp.Frame; 0 disables padding.
// remoteName is shown in LocalAddr/RemoteAddr for log readability;
// it does not affect the wire.
func New(conn *wsraw.Conn, padTarget int, remoteName string) *Adapter {
	return newAdapter(conn, padTarget, remoteName, shape.Config{})
}

// NewWithShape returns an Adapter that routes outbound bytes through a
// Shaper configured by cfg. When cfg.Mode is empty this is equivalent
// to New.
func NewWithShape(conn *wsraw.Conn, padTarget int, remoteName string, cfg shape.Config) *Adapter {
	return newAdapter(conn, padTarget, remoteName, cfg)
}

func newAdapter(conn *wsraw.Conn, padTarget int, remoteName string, cfg shape.Config) *Adapter {
	if padTarget < 0 {
		padTarget = 0
	}
	if padTarget > frame.MaxPad {
		padTarget = frame.MaxPad
	}
	if remoteName == "" {
		remoteName = "wisp"
	}
	a := &Adapter{conn: conn, padding: padTarget, remoteName: remoteName}
	if !cfg.Mode.Empty() {
		if cfg.MaxPayload <= 0 {
			cfg.MaxPayload = frame.MaxPayload
		}
		a.shaper = shape.New(cfg, a)
	}
	return a
}

// Read implements net.Conn. It returns bytes carried in wisp.Frame
// envelopes whose type is TypeYamux. Control frames are absorbed and
// the loop continues.
func (a *Adapter) Read(p []byte) (int, error) {
	a.readMu.Lock()
	defer a.readMu.Unlock()

	for a.readBuf.Len() == 0 {
		msg, err := a.conn.ReadMessage()
		if err != nil {
			return 0, err
		}
		f, err := frame.Decode(bytes.NewReader(msg))
		if err != nil {
			return 0, fmt.Errorf("mux: decode wisp frame: %w", err)
		}
		switch f.Type {
		case frame.TypeYamux:
			if len(f.Payload) > 0 {
				a.readBuf.Write(f.Payload)
			}
		case frame.TypePing, frame.TypePong:
			// liveness — to be wired up in the next milestone
		case frame.TypeBye:
			return 0, io.EOF
		case frame.TypeHello, frame.TypeHelloAck:
			return 0, fmt.Errorf("mux: unexpected %s on data plane", f.Type)
		default:
			return 0, fmt.Errorf("mux: unknown frame type %s", f.Type)
		}
	}
	return a.readBuf.Read(p)
}

// Write implements net.Conn. Without shaping, every Write produces
// exactly one wsraw binary message carrying a wisp.Frame{Type=Yamux}.
// With burst shaping, multiple Writes may coalesce into one wisp
// frame; the byte stream as seen by the peer's yamux is identical
// either way.
//
// We do NOT chunk p across multiple wisp frames here even if p exceeds
// frame.MaxPayload — that would corrupt yamux's framing assumptions.
// yamux is configured (see Config.MaxStreamWindowSize) so its frames
// stay well below MaxPayload.
func (a *Adapter) Write(p []byte) (int, error) {
	if len(p) > frame.MaxPayload {
		return 0, fmt.Errorf("mux: write of %d bytes exceeds wisp frame max %d", len(p), frame.MaxPayload)
	}
	if a.shaper != nil {
		if err := a.shaper.Write(p); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	if err := a.SendData(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// SendData implements shape.Sender: emit p as a single TypeYamux frame.
func (a *Adapter) SendData(p []byte) error {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	f := frame.Frame{Type: frame.TypeYamux, Payload: p}
	var buf bytes.Buffer
	if err := f.Encode(&buf, a.padding); err != nil {
		return err
	}
	return a.conn.WriteMessage(buf.Bytes())
}

// SendChaff implements shape.Sender: emit p as a single TypePing frame.
// The peer's mux absorbs Ping frames at the read side, so chaff never
// reaches yamux.
func (a *Adapter) SendChaff(p []byte) error {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	f := frame.Frame{Type: frame.TypePing, Payload: p}
	var buf bytes.Buffer
	if err := f.Encode(&buf, a.padding); err != nil {
		return err
	}
	return a.conn.WriteMessage(buf.Bytes())
}

// Close implements net.Conn. It drains the shaper (if any) before
// closing the underlying connection.
func (a *Adapter) Close() error {
	if a.shaper != nil {
		_ = a.shaper.Close()
	}
	return a.conn.Close()
}

// LocalAddr and RemoteAddr return synthetic addresses with network
// "wisp"; they exist to satisfy net.Conn for yamux's debug logging.
type wispAddr struct{ name string }

func (wispAddr) Network() string        { return "wisp" }
func (a wispAddr) String() string       { return a.name }
func (a *Adapter) LocalAddr() net.Addr  { return wispAddr{name: "wisp-local"} }
func (a *Adapter) RemoteAddr() net.Addr { return wispAddr{name: a.remoteName} }

// SetDeadline / SetReadDeadline / SetWriteDeadline forward to the
// underlying wsraw.Conn.
func (a *Adapter) SetDeadline(t time.Time) error {
	if err := a.conn.SetReadDeadline(t); err != nil {
		return err
	}
	return a.conn.SetWriteDeadline(t)
}
func (a *Adapter) SetReadDeadline(t time.Time) error  { return a.conn.SetReadDeadline(t) }
func (a *Adapter) SetWriteDeadline(t time.Time) error { return a.conn.SetWriteDeadline(t) }

// Compile-time check that Adapter satisfies net.Conn.
var _ net.Conn = (*Adapter)(nil)

// ensure the errors package is referenced even if no error returns it
// (keeps the import set explicit for future hardening).
var _ = errors.New
