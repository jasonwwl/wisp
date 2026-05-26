// Command wisp is the CLI entry point for the wisp tunneling tool.
//
// See docs/design.md for the design rationale and wire protocol.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/wenleigood/wisp/internal/version"
)

const rootUsage = `wisp — ephemeral reverse TCP tunnels.

Usage:
  wisp <command> [flags]

Commands:
  serve      Run a wisp server on a public host.
  expose     Expose a local TCP target through a server.
  version    Print version information.
  help       Show help for a command.

Run "wisp help <command>" for command-specific flags.
See https://github.com/wenleigood/wisp for documentation.
`

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(os.Stderr, "wisp:", err)
		}
		os.Exit(2)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(stdout, rootUsage)
		return nil
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "serve":
		return runServe(rest, stdout, stderr)
	case "expose":
		return runExpose(rest, stdout, stderr)
	case "version", "-v", "--version":
		fmt.Fprintf(stdout, "wisp %s\n", version.String())
		return nil
	case "help", "-h", "--help":
		return runHelp(rest, stdout, stderr)
	default:
		return fmt.Errorf("unknown command %q (try \"wisp help\")", cmd)
	}
}

func runHelp(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(stdout, rootUsage)
		return nil
	}
	switch args[0] {
	case "serve":
		fs := serveFlags(&serveOpts{})
		fs.SetOutput(stdout)
		fs.Usage()
		return nil
	case "expose":
		fs := exposeFlags(&exposeOpts{})
		fs.SetOutput(stdout)
		fs.Usage()
		return nil
	default:
		return fmt.Errorf("no help available for %q", args[0])
	}
}
