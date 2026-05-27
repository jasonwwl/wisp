package wsraw

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
	_ "unsafe" // for go:linkname

	"golang.org/x/net/http2"
)

// disableExtendedConnectProtocol is a package-level switch inside
// golang.org/x/net/http2 that turns RFC 8441 Extended CONNECT on or
// off. Upstream defaults to true (off) pending Go issue #71128, but
// the wisp threat model needs it on so the tunnel can ride h2 and
// the server's ALPN matches a 2025+ HTTPS site.
//
// linkname-flipping is the smallest hammer that works: it's a stable
// var, x/net/http2 reads it on every settings frame (not just at
// init), and no upstream API is exposed yet. We force x/net/http2 to
// own server-side h2 (via http2.ConfigureServer) so this flip alone
// is sufficient; the bundled net/http h2 stack is bypassed.
//
//go:linkname x_net_http2_disableExtendedConnectProtocol golang.org/x/net/http2.disableExtendedConnectProtocol
var x_net_http2_disableExtendedConnectProtocol bool

func init() {
	x_net_http2_disableExtendedConnectProtocol = false
}

// h2RWC bridges an h2 Extended CONNECT stream to wsraw.Conn's
// io.ReadWriteCloser expectation. Reads come from the response body
// (the server-to-client half of the stream); writes go into the
// request-body pipe (the client-to-server half).
type h2RWC struct {
	r    io.ReadCloser
	w    io.WriteCloser
	once sync.Once
	done func()
}

func (c *h2RWC) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *h2RWC) Write(p []byte) (int, error) { return c.w.Write(p) }
func (c *h2RWC) Close() error {
	c.once.Do(func() {
		_ = c.w.Close()
		_ = c.r.Close()
		if c.done != nil {
			c.done()
		}
	})
	return nil
}

// h2ServerRWC bridges an h2 server-side Extended CONNECT handler to
// wsraw.Conn. The wsraw frame layer writes whole frames in one Write
// (see writeFrame); we flush after each so frame boundaries don't get
// blurred by the h2 stack's internal bufio writer.
type h2ServerRWC struct {
	r        io.ReadCloser
	w        http.ResponseWriter
	flusher  http.Flusher
	closeOne sync.Once
	closeFn  func()
}

func (c *h2ServerRWC) Read(p []byte) (int, error) { return c.r.Read(p) }
func (c *h2ServerRWC) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if err == nil && c.flusher != nil {
		c.flusher.Flush()
	}
	return n, err
}
func (c *h2ServerRWC) Close() error {
	c.closeOne.Do(func() {
		_ = c.r.Close()
		if c.closeFn != nil {
			c.closeFn()
		}
	})
	return nil
}

// h2Transport is reused across dials. Frame size and idle ping match
// Chrome's behavior loosely; the values are not security-sensitive.
var (
	h2TransportOnce sync.Once
	h2Transport     *http2.Transport
)

func sharedH2Transport() *http2.Transport {
	h2TransportOnce.Do(func() {
		// SETTINGS values mirror Chrome 120: MAX_FRAME_SIZE = 16384,
		// HEADER_TABLE_SIZE = 65536. Real browsers leak these via the
		// initial SETTINGS frame and a NGFW with deep DPI clusters
		// h2 clients by the exact set. We hold the line at "looks
		// like Chrome" because the uTLS ClientHello already does.
		h2Transport = &http2.Transport{
			AllowHTTP:        false,
			ReadIdleTimeout:  30 * time.Second,
			PingTimeout:      15 * time.Second,
			MaxReadFrameSize: 16384,
		}
	})
	return h2Transport
}

// dialH2 performs RFC 8441 Extended CONNECT over the already-handshaken
// uTLS connection. The returned wsraw.Conn speaks the same WebSocket
// frame protocol the h1 path does, masked frames included.
func dialH2(tlsConn net.Conn, u *url.URL, opts DialOptions) (*Conn, error) {
	cc, err := sharedH2Transport().NewClientConn(tlsConn)
	if err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("h2 new client conn: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	// We feed the request body via an io.Pipe; outgoing WS frames go
	// through pw, the h2 stack drains pr into DATA frames.
	pr, pw := io.Pipe()

	ua := opts.UserAgent
	if ua == "" {
		ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	}

	hdr := make(http.Header, 4+len(opts.Headers))
	hdr.Set("User-Agent", ua)
	hdr.Set("Origin", "https://"+u.Hostname())
	hdr.Set("Sec-WebSocket-Version", "13")
	// :protocol is how x/net/http2.Transport recognizes an Extended
	// CONNECT request and emits SETTINGS_ENABLE_CONNECT_PROTOCOL-aware
	// framing.
	hdr.Set(":protocol", "websocket")
	for k, v := range opts.Headers {
		hdr.Set(k, v)
	}

	req := (&http.Request{
		Method:     http.MethodConnect,
		URL:        u,
		Host:       u.Host,
		Header:     hdr,
		Body:       io.NopCloser(pr),
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
		ProtoMinor: 0,
	}).WithContext(ctx)

	resp, err := cc.RoundTrip(req)
	if err != nil {
		cancel()
		_ = pw.Close()
		_ = tlsConn.Close()
		return nil, fmt.Errorf("h2 extended connect: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		cancel()
		_ = pw.Close()
		_ = resp.Body.Close()
		_ = tlsConn.Close()
		return nil, fmt.Errorf("h2 connect status: %s", resp.Status)
	}

	rwc := &h2RWC{
		r: resp.Body,
		w: pw,
		done: func() {
			cancel()
			_ = tlsConn.Close()
		},
	}
	return NewClientConn(rwc), nil
}

// AcceptH2Upgrade handles a server-side RFC 8441 Extended CONNECT
// request. It returns:
//   - conn: the upgraded WebSocket connection on success.
//   - ok: true if the request matched the h2 Extended CONNECT shape
//     and headers were sent. When false, the caller is free to send
//     an HTTP response (a 404 dressed like the decoy site).
//   - err: non-nil on any post-200 hijack failure.
//
// Mirrors AcceptUpgrade's contract: failures before the 200 leave the
// ResponseWriter usable; failures after return (conn=nil, ok=true,
// err=...).
func AcceptH2Upgrade(w http.ResponseWriter, r *http.Request) (conn *Conn, ok bool, err error) {
	if !IsH2WebSocket(r) {
		return nil, false, nil
	}
	flusher, hasFlush := w.(http.Flusher)
	if !hasFlush {
		// Should not happen on a real h2 stream; if it does, fall back
		// so the caller can serve a decoy 404.
		return nil, false, fmt.Errorf("%w: ResponseWriter has no Flusher", ErrBadHandshake)
	}

	// RFC 8441 §4: a 2xx response confirms the tunnel; the body of the
	// stream then carries WebSocket frames as ordinary octets.
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	rwc := &h2ServerRWC{
		r:       r.Body,
		w:       w,
		flusher: flusher,
	}
	return NewServerConn(rwc), true, nil
}

// IsH2WebSocket reports whether r is a well-formed RFC 8441 Extended
// CONNECT request asking for the "websocket" protocol. Negative cases
// fall back to the legacy h1 Upgrade path or to a decoy response.
func IsH2WebSocket(r *http.Request) bool {
	if r.ProtoMajor != 2 {
		return false
	}
	if r.Method != http.MethodConnect {
		return false
	}
	if r.Header.Get(":protocol") != "websocket" {
		return false
	}
	return true
}

// Compile-time assert: h2RWC implements both halves of the wsraw RWC
// requirement; h2ServerRWC implements the server side.
var (
	_ io.ReadWriteCloser = (*h2RWC)(nil)
	_ io.ReadWriteCloser = (*h2ServerRWC)(nil)
)

// ErrH2ExtendedConnectUnsupported is returned by Dial when the server
// negotiated h2 but did not advertise SETTINGS_ENABLE_CONNECT_PROTOCOL.
// Exposed so callers can decide whether to retry with PreferH1.
var ErrH2ExtendedConnectUnsupported = errors.New("wsraw: server did not advertise extended CONNECT (RFC 8441)")
