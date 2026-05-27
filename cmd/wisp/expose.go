package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jasonwwl/wisp/internal/client"
)

type exposeOpts struct {
	server     string
	endpoint   string
	token      string
	to         string
	ttl        time.Duration
	resume     string
	foreground bool
	insecure   bool
	verbose    bool
}

func exposeFlags(opts *exposeOpts) *flag.FlagSet {
	fs := flag.NewFlagSet("wisp expose", flag.ContinueOnError)
	fs.StringVar(&opts.server, "server", "", "wisp server (host or host:port)")
	fs.StringVar(&opts.server, "s", "", "alias for --server")
	fs.StringVar(&opts.endpoint, "endpoint", "", "tunnel path segment configured on the server")
	fs.StringVar(&opts.token, "token", os.Getenv("WISP_TOKEN"), "bearer token (env: WISP_TOKEN)")
	fs.StringVar(&opts.token, "t", os.Getenv("WISP_TOKEN"), "alias for --token")
	fs.StringVar(&opts.to, "to", "127.0.0.1:22", "local TCP target to expose")
	fs.DurationVar(&opts.ttl, "ttl", time.Hour, "tunnel time-to-live")
	fs.StringVar(&opts.resume, "resume", "", "resume a previous session by id (reserved)")
	fs.BoolVar(&opts.foreground, "foreground", false, "do not daemonize (reserved; current build is always foreground)")
	fs.BoolVar(&opts.insecure, "insecure-dev", false, "skip TLS verification (development only)")
	fs.BoolVar(&opts.verbose, "verbose", false, "enable debug logging")
	return fs
}

func runExpose(args []string, stdout, stderr io.Writer) error {
	var opts exposeOpts
	fs := exposeFlags(&opts)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if opts.server == "" {
		return errors.New("--server is required")
	}
	if opts.endpoint == "" {
		return errors.New("--endpoint is required (printed by the server at startup)")
	}
	if opts.token == "" {
		return errors.New("--token is required (or set WISP_TOKEN)")
	}

	logger := newLogger(stderr, opts.verbose)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	sess, err := client.Dial(ctx, client.Config{
		Server:             opts.server,
		Endpoint:           opts.endpoint,
		Token:              opts.token,
		LocalTarget:        opts.to,
		TTL:                opts.ttl,
		SessionID:          opts.resume,
		InsecureSkipVerify: opts.insecure,
		Logger:             logger,
	})
	if err != nil {
		return err
	}
	defer sess.Close()

	fmt.Fprintf(stdout, "wisp: tunnel up\n")
	fmt.Fprintf(stdout, "  public:  %s:%d\n", hostOnly(opts.server), sess.PublicPort)
	fmt.Fprintf(stdout, "  session: %s\n", sess.SessionID)
	fmt.Fprintf(stdout, "  target:  %s\n", opts.to)
	fmt.Fprintf(stdout, "  ttl:     %s\n", sess.GrantedTTL)
	fmt.Fprintln(stdout, "Ctrl-C to stop.")
	return sess.Forward(ctx)
}

func hostOnly(hostPort string) string {
	if i := lastColonNonBracket(hostPort); i >= 0 {
		return hostPort[:i]
	}
	return hostPort
}

func lastColonNonBracket(s string) int {
	if len(s) > 0 && s[0] == '[' {
		// IPv6 literal — keep as-is
		return -1
	}
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			return i
		}
	}
	return -1
}
