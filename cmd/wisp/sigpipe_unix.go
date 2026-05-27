//go:build !windows

package main

import (
	"os/signal"
	"syscall"
)

func ignoreStdioSignals() {
	signal.Ignore(syscall.SIGPIPE)
}
