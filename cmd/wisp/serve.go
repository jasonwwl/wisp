package main

import (
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
)

type serveOpts struct {
	listen    string
	domain    string
	token     string
	portRange string
	decoyDir  string
	stateDir  string
}

func serveFlags(opts *serveOpts) *flag.FlagSet {
	fs := flag.NewFlagSet("wisp serve", flag.ContinueOnError)
	fs.StringVar(&opts.listen, "listen", ":443", "TLS listen address")
	fs.StringVar(&opts.domain, "domain", "", "public hostname (must match certificate)")
	fs.StringVar(&opts.token, "token", os.Getenv("WISP_TOKEN"), "shared bearer token (env: WISP_TOKEN)")
	fs.StringVar(&opts.portRange, "port-range", "22000-22099", "public TCP port range for tunnels")
	fs.StringVar(&opts.decoyDir, "decoy-dir", "", "directory of static files to serve as the decoy site")
	fs.StringVar(&opts.stateDir, "state-dir", defaultStateDir("server"), "directory for persistent state")
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
	return errors.New("serve: not implemented yet — see docs/design.md")
}

func defaultStateDir(role string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".wisp", role)
}
