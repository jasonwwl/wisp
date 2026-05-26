// Package client implements the wisp client: outbound TLS dial with a
// browser-equivalent fingerprint, WebSocket upgrade, daemonization, and
// the local TCP accept loop that hands new connections to the
// multiplexer.
//
// See docs/design.md §3 (wire protocol), §6 (liveness), §8 (daemonization).
//
// Not yet implemented.
package client
