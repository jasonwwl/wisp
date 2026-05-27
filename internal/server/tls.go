package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// resolveTLS turns Config's TLS knobs into a *tls.Config suitable for an
// http.Server. Priority:
//
//  1. Caller-supplied TLSConfig.
//  2. TLSCert / TLSKey filesystem paths.
//  3. TLSAutoSelfSigned (development only).
func resolveTLS(cfg Config) (*tls.Config, error) {
	if cfg.TLSConfig != nil {
		return cfg.TLSConfig, nil
	}
	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("load cert/key: %w", err)
		}
		return baseTLSConfig(cert), nil
	}
	if cfg.TLSAutoSelfSigned {
		cert, err := generateSelfSignedCert(cfg.Domain)
		if err != nil {
			return nil, fmt.Errorf("self-sign: %w", err)
		}
		return baseTLSConfig(cert), nil
	}
	return nil, errors.New("server: no TLS configured (set TLSCert/TLSKey, TLSConfig, or TLSAutoSelfSigned)")
}

// baseTLSConfig returns the shared *tls.Config we use for every wisp
// listener. We pin ALPN to "http/1.1" so the tunnel endpoint (which
// requires HTTP/1.1 Upgrade semantics) is never negotiated as HTTP/2 —
// real WebSocket-over-HTTP/2 (RFC 8441) would need a separate
// implementation, and selective per-path ALPN is not a thing in TLS.
// The decoy site is content with HTTP/1.1; small self-hosted sites
// commonly run that way.
func baseTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}
}

// generateSelfSignedCert returns an ephemeral self-signed certificate.
// Development use only.
func generateSelfSignedCert(host string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
}
