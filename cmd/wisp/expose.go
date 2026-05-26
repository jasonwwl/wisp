package main

import (
	"errors"
	"flag"
	"io"
	"os"
	"time"
)

type exposeOpts struct {
	server     string
	token      string
	to         string
	ttl        time.Duration
	resume     string
	foreground bool
	insecure   bool
}

func exposeFlags(opts *exposeOpts) *flag.FlagSet {
	fs := flag.NewFlagSet("wisp expose", flag.ContinueOnError)
	fs.StringVar(&opts.server, "server", "", "wisp server (host or host:port)")
	fs.StringVar(&opts.server, "s", "", "alias for --server")
	fs.StringVar(&opts.token, "token", os.Getenv("WISP_TOKEN"), "bearer token (env: WISP_TOKEN)")
	fs.StringVar(&opts.token, "t", os.Getenv("WISP_TOKEN"), "alias for --token")
	fs.StringVar(&opts.to, "to", "127.0.0.1:22", "local TCP target to expose")
	fs.DurationVar(&opts.ttl, "ttl", time.Hour, "tunnel time-to-live")
	fs.StringVar(&opts.resume, "resume", "", "resume a previous session by id")
	fs.BoolVar(&opts.foreground, "foreground", false, "do not daemonize (for systemd or debugging)")
	fs.BoolVar(&opts.insecure, "insecure-dev", false, "skip TLS verification (development only)")
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
	if opts.token == "" {
		return errors.New("--token is required (or set WISP_TOKEN)")
	}
	return errors.New("expose: not implemented yet — see docs/design.md")
}
