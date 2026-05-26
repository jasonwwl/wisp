// Package server implements the wisp server: TLS termination, HTTP/WS
// upgrade, session lifecycle, dynamic public-port allocation, and the
// decoy site that hides the tunnel endpoint behind an ordinary HTTPS
// service.
//
// See docs/design.md §3 (wire protocol), §5 (session lifecycle), §9
// (port allocation), and §11 (decoy site).
//
// Not yet implemented.
package server
