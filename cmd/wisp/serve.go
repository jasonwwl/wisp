package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/jasonwwl/wisp/internal/server"
)

type serveOpts struct {
	listen    string
	domain    string
	token     string
	endpoint  string
	portRange string
	decoyDir  string
	stateDir  string

	tlsCert       string
	tlsKey        string
	tlsSelfSigned bool

	verbose bool
}

func serveFlags(opts *serveOpts) *flag.FlagSet {
	fs := flag.NewFlagSet("wisp serve", flag.ContinueOnError)
	fs.StringVar(&opts.listen, "listen", ":443", "TLS listen address")
	fs.StringVar(&opts.domain, "domain", "", "public hostname (must match certificate)")
	fs.StringVar(&opts.token, "token", os.Getenv("WISP_TOKEN"), "shared bearer token (env: WISP_TOKEN)")
	fs.StringVar(&opts.endpoint, "endpoint", "", "tunnel path segment (random if empty)")
	fs.StringVar(&opts.portRange, "port-range", "22000-22099", "public TCP port range for tunnels (reserved for forwarding milestone)")
	fs.StringVar(&opts.decoyDir, "decoy-dir", "", "directory of static files to serve as the decoy site")
	fs.StringVar(&opts.stateDir, "state-dir", defaultStateDir("server"), "directory for persistent state (reserved)")
	fs.StringVar(&opts.tlsCert, "cert", "", "path to PEM certificate")
	fs.StringVar(&opts.tlsKey, "key", "", "path to PEM private key")
	fs.BoolVar(&opts.tlsSelfSigned, "tls-self-signed", false, "generate an ephemeral self-signed cert (development only)")
	fs.BoolVar(&opts.verbose, "verbose", false, "enable debug logging")
	return fs
}

func runServe(args []string, stdout, stderr io.Writer) error {
	var opts serveOpts
	fs := serveFlags(&opts)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if opts.domain == "" {
		return errors.New("--domain is required")
	}
	if opts.token == "" {
		return errors.New("--token is required (or set WISP_TOKEN)")
	}
	if !opts.tlsSelfSigned && (opts.tlsCert == "" || opts.tlsKey == "") {
		return errors.New("provide --cert and --key, or --tls-self-signed for development")
	}

	logger := newLogger(stderr, opts.verbose)

	srv, err := server.New(server.Config{
		Listen:            opts.listen,
		Domain:            opts.domain,
		Token:             opts.token,
		Endpoint:          opts.endpoint,
		PortRange:         opts.portRange,
		DecoyDir:          opts.decoyDir,
		TLSCert:           opts.tlsCert,
		TLSKey:            opts.tlsKey,
		TLSAutoSelfSigned: opts.tlsSelfSigned,
		Logger:            logger,
	})
	if err != nil {
		return err
	}

	fmt.Fprintf(stdout, "wisp server listening on %s (domain %s)\n", opts.listen, opts.domain)
	fmt.Fprintf(stdout, "  endpoint: %s\n", srv.Endpoint())
	fmt.Fprintf(stdout, "  client:   wisp expose --server %s --endpoint %s --token $WISP_TOKEN ...\n",
		opts.domain, srv.Endpoint())

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	return srv.Run(ctx)
}

func defaultStateDir(role string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".wisp", role)
}

func newLogger(w io.Writer, verbose bool) *slog.Logger {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level}))
}
