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

	// ResumeWindow is how long a disconnected session may be re-attached
	// to via mode=resume. Zero defaults to DefaultResumeWindow (5 min).
	// Tests use shorter values to keep total runtime down.
	ResumeWindow time.Duration

	// DecoyDir is an optional path to a directory of static files served
	// as the decoy site. If empty, a built-in "Welcome to nginx" page is
	// served.
	DecoyDir string

	// TunnelBindHost is the host address to bind each tunnel listener on
	// (the ports that external SSH/HTTP/etc. clients connect to). Empty
	// defaults to "0.0.0.0". Use "127.0.0.1" for local-only testing or
	// when the server itself is behind a reverse-proxy that should be
	// the only ingress to tunnel ports.
	TunnelBindHost string

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

	// ACMEEnabled, if true, obtains and auto-renews a Let's Encrypt
	// certificate for Domain via golang.org/x/crypto/acme/autocert.
	// Mutually exclusive with TLSCert/TLSKey and TLSAutoSelfSigned.
	ACMEEnabled bool

	// ACMEEmail is the contact email for the ACME account. Optional but
	// recommended (Let's Encrypt sends expiry reminders if renewal stops).
	ACMEEmail string

	// ACMECacheDir is the on-disk path where autocert persists issued
	// certificates, ACME account keys, and challenge state. Must survive
	// process restarts to avoid re-issuance and rate limits.
	ACMECacheDir string

	// ACMEHTTPListen, if non-empty, starts a separate HTTP listener on
	// that address for HTTP-01 challenges (typical: ":80"). If empty,
	// only TLS-ALPN-01 challenges work — fine on most modern networks
	// but requires nothing else on :443.
	ACMEHTTPListen string

	// Logger is the structured logger. Defaults to slog.Default().
	Logger *slog.Logger
}

// Server is a configured but not-yet-running wisp server.
type Server struct {
	cfg      Config
	hsrv     *http.Server
	log      *slog.Logger
	mux      *http.ServeMux
	ports    *PortAllocator
	sessions *sessionRegistry
	acme     *acmeRuntime
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
	if cfg.TunnelBindHost == "" {
		cfg.TunnelBindHost = "0.0.0.0"
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

	// Set up ACME first because resolveTLS may need its GetCertificate hook.
	var acme *acmeRuntime
	if cfg.ACMEEnabled {
		var aerr error
		acme, aerr = setupACME(cfg)
		if aerr != nil {
			return nil, aerr
		}
	}

	tlsCfg, err := resolveTLS(cfg, acme)
	if err != nil {
		return nil, err
	}

	alloc, err := NewPortAllocator(cfg.PortRange)
	if err != nil {
		return nil, err
	}

	sessions := newSessionRegistry(alloc, cfg.ResumeWindow, cfg.Logger)

	s := &Server{
		cfg:      cfg,
		log:      cfg.Logger,
		mux:      http.NewServeMux(),
		ports:    alloc,
		sessions: sessions,
		acme:     acme,
	}
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

// Run starts the TLS listener (and the optional ACME HTTP-01 listener)
// and blocks until ctx is canceled or the server returns an error. On
// ctx cancel, Run performs a graceful Shutdown.
func (s *Server) Run(ctx context.Context) error {
	s.log.Info("wisp server starting",
		"listen", s.cfg.Listen,
		"domain", s.cfg.Domain,
		"endpoint", s.cfg.Endpoint,
		"acme", s.acme != nil,
	)

	if s.acme != nil && s.cfg.ACMEHTTPListen != "" {
		s.acme.startHTTP01(s.cfg.ACMEHTTPListen, s.log)
	}

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
		if s.acme != nil {
			_ = s.acme.Shutdown(shutdownCtx)
		}
		s.sessions.Close()
		<-errCh
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			s.sessions.Close()
			return nil
		}
		s.sessions.Close()
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
