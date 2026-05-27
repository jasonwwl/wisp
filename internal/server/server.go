// Package server implements the wisp server: TLS termination, the decoy
// HTTPS site, the obscured tunnel endpoint, token authentication, and
// (in later milestones) public-port allocation and tunnel forwarding.
//
// See docs/design.md §3, §4, §5, §9, §11.
package server

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Config is the user-facing configuration for a wisp server. Zero values
// are filled in by New where reasonable defaults exist.
type Config struct {
	// Listen is the TCP address to bind. Default ":443".
	Listen string

	// Domain is the public hostname; must match the certificate. Required.
	Domain string

	// Token is the shared bearer token clients must present. Required.
	Token string

	// Endpoint is the path segment (no leading slash) at which the tunnel
	// upgrade lives. If empty, a fresh random 32-byte base64url segment is
	// generated at startup and logged.
	Endpoint string

	// PortRange is the inclusive TCP port range for public tunnel ports,
	// formatted "lo-hi". Default "22000-22099". (Not yet used; reserved
	// for the forwarding milestone.)
	PortRange string

	// DecoyDir is an optional path to a directory of static files served
	// as the decoy site. If empty, a built-in "Welcome to nginx" page is
	// served.
	DecoyDir string

	// TLSConfig is used as-is for the listener. If nil, the caller is
	// expected to set TLSCert/TLSKey or use TLSAutoSelfSigned for dev.
	TLSConfig *tls.Config

	// TLSCert and TLSKey are filesystem paths to a PEM-encoded certificate
	// and private key. Ignored if TLSConfig is non-nil.
	TLSCert string
	TLSKey  string

	// TLSAutoSelfSigned, if true, generates an ephemeral self-signed
	// certificate at startup. Development use only; clients must opt in
	// with --insecure-dev to trust it.
	TLSAutoSelfSigned bool

	// Logger is the structured logger. Defaults to slog.Default().
	Logger *slog.Logger
}

// Server is a configured but not-yet-running wisp server.
type Server struct {
	cfg  Config
	hsrv *http.Server
	log  *slog.Logger
	mux  *http.ServeMux
}

// New validates cfg and returns a ready-to-Run Server.
func New(cfg Config) (*Server, error) {
	if cfg.Domain == "" {
		return nil, errors.New("server: Domain is required")
	}
	if cfg.Token == "" {
		return nil, errors.New("server: Token is required")
	}
	if cfg.Listen == "" {
		cfg.Listen = ":443"
	}
	if cfg.PortRange == "" {
		cfg.PortRange = "22000-22099"
	}
	if cfg.Endpoint == "" {
		ep, err := generateEndpoint()
		if err != nil {
			return nil, fmt.Errorf("generate endpoint: %w", err)
		}
		cfg.Endpoint = ep
	} else if !isValidEndpoint(cfg.Endpoint) {
		return nil, fmt.Errorf("invalid endpoint %q (must be base64url, 32-128 chars)", cfg.Endpoint)
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	tlsCfg, err := resolveTLS(cfg)
	if err != nil {
		return nil, err
	}

	s := &Server{cfg: cfg, log: cfg.Logger, mux: http.NewServeMux()}
	s.mux.HandleFunc("/", s.decoyHandler)
	s.mux.HandleFunc("/"+cfg.Endpoint+"/ws", s.tunnelHandler)

	s.hsrv = &http.Server{
		Addr:              cfg.Listen,
		Handler:           s.mux,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		// We intentionally do *not* set ErrorLog → slog. The default
		// behavior leaks little, and rerouting requires an io.Writer
		// adapter that's noisy in tests.
	}
	return s, nil
}

// Endpoint returns the resolved tunnel-endpoint path segment (no leading
// slash).
func (s *Server) Endpoint() string { return s.cfg.Endpoint }

// Addr returns the listener address as configured. After Run starts, the
// actual bound address is available on the underlying http.Server.
func (s *Server) Addr() string { return s.cfg.Listen }

// Run starts the TLS listener and blocks until ctx is canceled or the
// server returns an error. On ctx cancel, Run performs a graceful
// Shutdown.
func (s *Server) Run(ctx context.Context) error {
	s.log.Info("wisp server starting",
		"listen", s.cfg.Listen,
		"domain", s.cfg.Domain,
		"endpoint", s.cfg.Endpoint,
	)

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.hsrv.ListenAndServeTLS("", "")
	}()

	select {
	case <-ctx.Done():
		s.log.Info("wisp server shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.hsrv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		// drain ListenAndServe's error
		<-errCh
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// checkAuth returns true iff the request carries a valid Authorization:
// Bearer header. Compared in constant time.
func (s *Server) checkAuth(r *http.Request) bool {
	got := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(got, prefix) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got[len(prefix):]), []byte(s.cfg.Token)) == 1
}
