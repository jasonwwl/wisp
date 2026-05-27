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
//  2. ACME via autocert (Let's Encrypt-class CA).
//  3. TLSCert / TLSKey filesystem paths.
//  4. TLSAutoSelfSigned (development only).
func resolveTLS(cfg Config, acme *acmeRuntime) (*tls.Config, error) {
	if cfg.TLSConfig != nil {
		return cfg.TLSConfig, nil
	}
	if acme != nil {
		// autocert.Manager.GetCertificate handles both regular ServerName
		// SNI and TLS-ALPN-01 challenges (via "acme-tls/1" ALPN). We
		// advertise h2 first to match a modern HTTPS site; the tunnel
		// endpoint supports both h2 Extended CONNECT and h1 Upgrade.
		return &tls.Config{
			GetCertificate: acme.manager.GetCertificate,
			NextProtos:     []string{"h2", "http/1.1", "acme-tls/1"},
			MinVersion:     tls.VersionTLS12,
		}, nil
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
	return nil, errors.New("server: no TLS configured (set --acme, --cert/--key, --tls-config, or --tls-self-signed)")
}

// baseTLSConfig returns the shared *tls.Config we use for every wisp
// listener. We advertise h2 first then http/1.1: a 2025+ HTTPS site
// almost always defaults to h2, so a single-domain h1-only fingerprint
// would itself be a tell. The tunnel endpoint dispatches between RFC
// 8441 Extended CONNECT (on h2) and the legacy h1 Upgrade in
// tunnelHandler; the decoy site serves both transparently.
func baseTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
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
