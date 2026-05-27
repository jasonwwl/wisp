package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// acmeRuntime owns the autocert.Manager and the optional HTTP-01
// challenge listener (typically :80) that Let's Encrypt sometimes
// uses to verify domain control. TLS-ALPN-01 challenges are handled
// transparently by the manager's GetCertificate hook over the main
// :443 listener via the "acme-tls/1" ALPN value.
type acmeRuntime struct {
	manager *autocert.Manager
	hsrv    *http.Server
	log     *slog.Logger
}

func setupACME(cfg Config) (*acmeRuntime, error) {
	if cfg.Domain == "" {
		return nil, errors.New("acme: Domain is required (must match the certificate that will be issued)")
	}
	if cfg.ACMECacheDir == "" {
		return nil, errors.New("acme: ACMECacheDir is required (where issued certs and account keys are persisted)")
	}
	m := &autocert.Manager{
		Cache:      autocert.DirCache(cfg.ACMECacheDir),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(cfg.Domain),
		Email:      cfg.ACMEEmail,
	}
	return &acmeRuntime{manager: m}, nil
}

// startHTTP01 launches the dedicated HTTP-01 listener. It serves the
// autocert HTTPHandler (which answers /.well-known/acme-challenge/*
// for Let's Encrypt) and 301-redirects everything else to https://.
// This is optional: a server reachable on :443 with the TLS-ALPN-01
// path works without it. We start it only when ACMEHTTPListen is set.
func (a *acmeRuntime) startHTTP01(addr string, log *slog.Logger) {
	a.hsrv = &http.Server{
		Addr:              addr,
		Handler:           a.manager.HTTPHandler(nil),
		ReadHeaderTimeout: 10 * time.Second,
	}
	a.log = log
	go func() {
		log.Info("ACME HTTP-01 listener up", "addr", addr)
		if err := a.hsrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("ACME HTTP-01 listener exited", "err", err)
		}
	}()
}

// Shutdown gracefully stops the HTTP-01 listener if one was started.
func (a *acmeRuntime) Shutdown(ctx context.Context) error {
	if a.hsrv == nil {
		return nil
	}
	if err := a.hsrv.Shutdown(ctx); err != nil {
		return fmt.Errorf("acme http shutdown: %w", err)
	}
	return nil
}
