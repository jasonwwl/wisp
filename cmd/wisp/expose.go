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
	server   string
	endpoint string
	token    string
	to       string
	ttl      time.Duration
	resume   string
	detach   bool
	insecure bool
	verbose  bool
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
	fs.BoolVar(&opts.detach, "detach", false, "re-exec as a background daemon; closing the terminal does not stop the tunnel")
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

	// If --detach is set and we're the launcher (not the daemon child),
	// re-exec self as a background process and exit.
	if opts.detach {
		handled, err := daemonize(stdout)
		if err != nil {
			return err
		}
		if handled {
			return nil
		}
		// fall through: we ARE the daemon child; continue as foreground.
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
		// If we are a daemon child whose handshake failed, tell the
		// launcher so it can surface the error.
		signalReady(readyMessage{OK: false, Error: err.Error()})
		return err
	}
	defer sess.Close()

	// Tell the launcher we're up. (No-op when not running as a daemon.)
	signalReady(readyMessage{
		OK:         true,
		Session:    sess.SessionID,
		Server:     hostOnly(opts.server),
		PublicPort: int(sess.PublicPort),
		GrantedTTL: int(sess.GrantedTTL.Seconds()),
	})

	// In daemon mode, the launcher already printed the user-facing
	// summary; skip the duplicate here. We can detect that via the env
	// var the launcher injected.
	if os.Getenv(envDaemonized) != "1" {
		fmt.Fprintf(stdout, "wisp: tunnel up\n")
		fmt.Fprintf(stdout, "  public:  %s:%d\n", hostOnly(opts.server), sess.PublicPort)
		fmt.Fprintf(stdout, "  session: %s\n", sess.SessionID)
		fmt.Fprintf(stdout, "  target:  %s\n", opts.to)
		fmt.Fprintf(stdout, "  ttl:     %s\n", sess.GrantedTTL)
		fmt.Fprintln(stdout, "Ctrl-C to stop.")
	} else {
		logger.Info("daemon up",
			"public_port", sess.PublicPort,
			"session", sess.SessionID,
			"ttl", sess.GrantedTTL,
		)
	}
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
		return -1
	}
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			return i
		}
	}
	return -1
}
