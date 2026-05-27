// Package wsraw is a minimal RFC 6455 WebSocket implementation tailored to
// wisp's needs: binary messages only, no fragmentation, no extensions, no
// compression. Pings and pongs are handled transparently inside ReadMessage.
//
// Why hand-rolled: the standard library has no WebSocket, and the available
// third-party libraries are larger than the entire wisp project. Our usage
// is narrow enough that ~250 lines of careful code suffice.
package wsraw

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const magicGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// MaxPayload is the largest single WebSocket message wsraw will accept.
const MaxPayload = 1 << 24 // 16 MiB

// Opcode identifies a WebSocket frame's type.
type Opcode uint8

const (
	OpContinuation Opcode = 0x0
	OpText         Opcode = 0x1
	OpBinary       Opcode = 0x2
	OpClose        Opcode = 0x8
	OpPing         Opcode = 0x9
	OpPong         Opcode = 0xA
)

var (
	ErrFragmented    = errors.New("wsraw: fragmented frames not supported")
	ErrPayloadTooBig = errors.New("wsraw: payload exceeds 16 MiB")
	ErrBadOpcode     = errors.New("wsraw: unexpected opcode")
	ErrBadHandshake  = errors.New("wsraw: bad handshake")
)

// Accept computes the value of Sec-WebSocket-Accept from a client's
// Sec-WebSocket-Key per RFC 6455 §4.2.2.
func Accept(clientKey string) string {
	h := sha1.New()
	h.Write([]byte(clientKey))
	h.Write([]byte(magicGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// Conn is a single, full-duplex WebSocket connection. Multiple goroutines
// may call ReadMessage and WriteMessage concurrently with each other, but
// neither method is safe to call from multiple goroutines simultaneously.
type Conn struct {
	rwc  io.ReadWriteCloser
	mask bool // client-side conns mask outgoing frames

	writeMu sync.Mutex

	closeOnce sync.Once
}

// NewServerConn wraps an already-upgraded server-side connection.
func NewServerConn(rwc io.ReadWriteCloser) *Conn {
	return &Conn{rwc: rwc, mask: false}
}

// NewClientConn wraps an already-upgraded client-side connection.
func NewClientConn(rwc io.ReadWriteCloser) *Conn {
	return &Conn{rwc: rwc, mask: true}
}

// ReadMessage reads one complete binary message. Control frames (ping,
// pong, close) are handled internally: pings get a matching pong reply,
// pongs are dropped, close causes io.EOF to be returned.
func (c *Conn) ReadMessage() ([]byte, error) {
	for {
		op, payload, err := readFrame(c.rwc)
		if err != nil {
			return nil, err
		}
		switch op {
		case OpBinary:
			return payload, nil
		case OpPing:
			if err := c.writeFrame(OpPong, payload); err != nil {
				return nil, err
			}
		case OpPong:
			// drop
		case OpClose:
			// echo close, then signal EOF
			_ = c.writeFrame(OpClose, payload)
			return nil, io.EOF
		case OpText:
			return nil, fmt.Errorf("%w: text frame", ErrBadOpcode)
		default:
			return nil, fmt.Errorf("%w: 0x%x", ErrBadOpcode, op)
		}
	}
}

// WriteMessage writes one complete binary message.
func (c *Conn) WriteMessage(b []byte) error {
	return c.writeFrame(OpBinary, b)
}

// SetReadDeadline sets a deadline for the next ReadMessage. A zero value
// disables the deadline. If the underlying transport does not support
// deadlines, this is a no-op and returns nil.
func (c *Conn) SetReadDeadline(t time.Time) error {
	if d, ok := c.rwc.(interface{ SetReadDeadline(time.Time) error }); ok {
		return d.SetReadDeadline(t)
	}
	return nil
}

// SetWriteDeadline sets a deadline for the next WriteMessage. See
// SetReadDeadline for semantics.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	if d, ok := c.rwc.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return d.SetWriteDeadline(t)
	}
	return nil
}

// Close sends an empty close frame (best-effort) and closes the underlying
// transport. It is safe to call Close multiple times.
func (c *Conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		_ = c.writeFrame(OpClose, nil)
		err = c.rwc.Close()
	})
	return err
}

func (c *Conn) writeFrame(op Opcode, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return writeFrame(c.rwc, op, payload, c.mask)
}

// --- low-level frame I/O ---

func readFrame(r io.Reader) (Opcode, []byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	fin := hdr[0]&0x80 != 0
	rsv := hdr[0] & 0x70
	op := Opcode(hdr[0] & 0x0F)
	masked := hdr[1]&0x80 != 0
	plen := uint64(hdr[1] & 0x7F)

	if !fin {
		return 0, nil, ErrFragmented
	}
	if rsv != 0 {
		return 0, nil, fmt.Errorf("wsraw: non-zero rsv bits")
	}

	switch plen {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		plen = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		plen = binary.BigEndian.Uint64(ext[:])
	}
	if plen > MaxPayload {
		return 0, nil, ErrPayloadTooBig
	}

	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(r, maskKey[:]); err != nil {
			return 0, nil, err
		}
	}

	payload := make([]byte, plen)
	if plen > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, err
		}
	}
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}
	return op, payload, nil
}

func writeFrame(w io.Writer, op Opcode, payload []byte, mask bool) error {
	if len(payload) > MaxPayload {
		return ErrPayloadTooBig
	}
	var hdr [14]byte
	hdr[0] = 0x80 | byte(op)
	hidx := 2
	switch {
	case len(payload) < 126:
		hdr[1] = byte(len(payload))
	case len(payload) <= 0xFFFF:
		hdr[1] = 126
		binary.BigEndian.PutUint16(hdr[2:4], uint16(len(payload)))
		hidx = 4
	default:
		hdr[1] = 127
		binary.BigEndian.PutUint64(hdr[2:10], uint64(len(payload)))
		hidx = 10
	}

	var out []byte
	if mask {
		hdr[1] |= 0x80
		var key [4]byte
		if _, err := rand.Read(key[:]); err != nil {
			return err
		}
		copy(hdr[hidx:hidx+4], key[:])
		hidx += 4
		masked := make([]byte, len(payload))
		for i := range payload {
			masked[i] = payload[i] ^ key[i%4]
		}
		out = masked
	} else {
		out = payload
	}

	if _, err := w.Write(hdr[:hidx]); err != nil {
		return err
	}
	if len(out) > 0 {
		if _, err := w.Write(out); err != nil {
			return err
		}
	}
	return nil
}

// --- server-side handshake ---

// AcceptUpgrade performs the server-side WebSocket handshake.
//
// It returns:
//   - conn: the upgraded connection on success.
//   - hijacked: true once the underlying TCP connection has been taken
//     over from the http.Server (the caller must NOT write further to w
//     after that point). When false, the caller is free to send an HTTP
//     response (e.g. a 404 indistinguishable from the decoy site).
//   - err: non-nil on any failure.
//
// Handshake failures that happen before hijack (HTTP/2 — Hijacker
// unavailable, bad method, missing/garbage WS headers) leave the
// response writer usable so the caller can mimic the decoy site instead
// of leaking a "weird 200" fingerprint.
func AcceptUpgrade(w http.ResponseWriter, r *http.Request) (conn *Conn, hijacked bool, err error) {
	if r.Method != http.MethodGet {
		return nil, false, fmt.Errorf("%w: method %s", ErrBadHandshake, r.Method)
	}
	if !headerContainsToken(r.Header, "Connection", "upgrade") {
		return nil, false, fmt.Errorf("%w: missing Connection: upgrade", ErrBadHandshake)
	}
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return nil, false, fmt.Errorf("%w: missing Upgrade: websocket", ErrBadHandshake)
	}
	if r.Header.Get("Sec-WebSocket-Version") != "13" {
		return nil, false, fmt.Errorf("%w: bad WS version", ErrBadHandshake)
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return nil, false, fmt.Errorf("%w: missing Sec-WebSocket-Key", ErrBadHandshake)
	}

	// Hijacker is unavailable on HTTP/2; this is the most common
	// pre-hijack failure path and the one we explicitly want callers to
	// dress up as a decoy 404.
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, false, fmt.Errorf("%w: ResponseWriter is not a Hijacker (HTTP/2?)", ErrBadHandshake)
	}

	netConn, brw, err := hj.Hijack()
	if err != nil {
		return nil, false, fmt.Errorf("hijack: %w", err)
	}
	// From here on, the response writer is dead; we own netConn.

	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Server: nginx/1.24.0\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + Accept(key) + "\r\n" +
		"\r\n"
	if _, werr := brw.WriteString(resp); werr != nil {
		_ = netConn.Close()
		return nil, true, fmt.Errorf("write 101: %w", werr)
	}
	if ferr := brw.Flush(); ferr != nil {
		_ = netConn.Close()
		return nil, true, fmt.Errorf("flush 101: %w", ferr)
	}

	return NewServerConn(netConn), true, nil
}

// --- client-side dial ---

// DialOptions configures Dial.
type DialOptions struct {
	URL       string            // e.g. https://wisp.example.com/<endpoint>/ws
	Headers   map[string]string // extra request headers (Authorization, etc.)
	TLSConfig *tls.Config       // SNI defaults to URL host if ServerName is empty
	UserAgent string            // override the default User-Agent
}

// Dial connects to a WebSocket endpoint over TLS and returns a client-side
// Conn. The default User-Agent matches a current Chrome on Linux.
func Dial(opts DialOptions) (*Conn, error) {
	u, err := url.Parse(opts.URL)
	if err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("only https:// is supported (got %q)", u.Scheme)
	}
	host := u.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(u.Hostname(), "443")
	}

	tlsCfg := opts.TLSConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{}
	}
	if tlsCfg.ServerName == "" {
		tlsCfg.ServerName = u.Hostname()
	}
	// Browsers performing a WebSocket upgrade only negotiate http/1.1 at
	// ALPN time: they know they will need Connection: Upgrade semantics,
	// which HTTP/2 does not provide (RFC 8441 is rarely supported).
	// Matching this avoids the "empty ALPN" fingerprint that Go's default
	// TLS client would otherwise expose.
	if tlsCfg.NextProtos == nil {
		tlsCfg.NextProtos = []string{"http/1.1"}
	}

	tcpConn, err := tls.Dial("tcp", host, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("tls dial %s: %w", host, err)
	}

	keyRaw := make([]byte, 16)
	if _, err := rand.Read(keyRaw); err != nil {
		_ = tcpConn.Close()
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(keyRaw)

	ua := opts.UserAgent
	if ua == "" {
		ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	}

	// Header order and contents below mirror a current Chrome WebSocket
	// upgrade. Static fingerprint tools cluster by exactly these headers
	// (presence, order, casing). Sec-WebSocket-Extensions is sent for
	// authenticity; the server is free to ignore it and we won't have
	// negotiated compression as a result.
	var sb strings.Builder
	fmt.Fprintf(&sb, "GET %s HTTP/1.1\r\n", u.RequestURI())
	fmt.Fprintf(&sb, "Host: %s\r\n", u.Host)
	sb.WriteString("Connection: Upgrade\r\n")
	sb.WriteString("Pragma: no-cache\r\n")
	sb.WriteString("Cache-Control: no-cache\r\n")
	fmt.Fprintf(&sb, "User-Agent: %s\r\n", ua)
	sb.WriteString("Upgrade: websocket\r\n")
	fmt.Fprintf(&sb, "Origin: https://%s\r\n", u.Hostname())
	sb.WriteString("Sec-WebSocket-Version: 13\r\n")
	sb.WriteString("Accept-Encoding: gzip, deflate, br\r\n")
	sb.WriteString("Accept-Language: en-US,en;q=0.9\r\n")
	fmt.Fprintf(&sb, "Sec-WebSocket-Key: %s\r\n", key)
	sb.WriteString("Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n")
	for k, v := range opts.Headers {
		fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
	}
	sb.WriteString("\r\n")

	if _, err := tcpConn.Write([]byte(sb.String())); err != nil {
		_ = tcpConn.Close()
		return nil, fmt.Errorf("write request: %w", err)
	}

	br := bufio.NewReader(tcpConn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		_ = tcpConn.Close()
		return nil, fmt.Errorf("read response: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		_ = tcpConn.Close()
		return nil, fmt.Errorf("upgrade failed: %s", resp.Status)
	}
	if got := resp.Header.Get("Sec-WebSocket-Accept"); got != Accept(key) {
		_ = tcpConn.Close()
		return nil, fmt.Errorf("%w: bad Sec-WebSocket-Accept", ErrBadHandshake)
	}

	// Any bytes the bufio reader buffered past the 101 response are early
	// WebSocket frames; we must consume them before the underlying conn.
	rwc := io.ReadWriteCloser(tcpConn)
	if n := br.Buffered(); n > 0 {
		peek, _ := br.Peek(n)
		rwc = &prefixedRWC{prefix: peek, under: tcpConn}
	}
	return NewClientConn(rwc), nil
}

type prefixedRWC struct {
	prefix []byte
	under  net.Conn
}

func (p *prefixedRWC) Read(b []byte) (int, error) {
	if len(p.prefix) > 0 {
		n := copy(b, p.prefix)
		p.prefix = p.prefix[n:]
		return n, nil
	}
	return p.under.Read(b)
}

func (p *prefixedRWC) Write(b []byte) (int, error)        { return p.under.Write(b) }
func (p *prefixedRWC) Close() error                       { return p.under.Close() }
func (p *prefixedRWC) SetReadDeadline(t time.Time) error  { return p.under.SetReadDeadline(t) }
func (p *prefixedRWC) SetWriteDeadline(t time.Time) error { return p.under.SetWriteDeadline(t) }

func headerContainsToken(h http.Header, name, want string) bool {
	for _, v := range h.Values(name) {
		for _, p := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(p), want) {
				return true
			}
		}
	}
	return false
}
