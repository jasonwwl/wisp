//go:build windows

package main

import (
	"errors"
	"io"
)

// daemonize on Windows is intentionally not implemented in this
// milestone. The pattern (CreateProcessW with DETACHED_PROCESS) works
// but requires the golang.org/x/sys/windows package, which is the kind
// of indirect dependency we want to add deliberately rather than now.
//
// Workaround: run wisp under a Windows service manager (NSSM, sc.exe)
// or simply leave the terminal window open. This matches how most Go
// CLI tools on Windows handle background execution.
func daemonize(_ io.Writer) (handled bool, err error) {
	return false, errors.New("--detach is not supported on Windows yet; use --foreground (default) with a service manager like NSSM")
}

// signalReady is a no-op on Windows for now.
func signalReady(_ readyMessage) {}
