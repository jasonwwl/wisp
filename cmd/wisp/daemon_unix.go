//go:build !windows

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// daemonize, when called by the launcher process, re-execs the current
// binary with setsid + a fresh log file and waits on a pipe for the
// child's ready report. Returns (true, nil) once the child reports
// success; the launcher should then print info and exit.
//
// If the current process is already the daemon child (envDaemonized=1),
// daemonize returns (false, nil) and the caller continues with the
// regular Dial+Forward flow — but should call signalReady once the
// handshake has completed so the launcher knows what to print.
func daemonize(stdout io.Writer) (handled bool, err error) {
	if os.Getenv(envDaemonized) == "1" {
		return false, nil
	}

	stateDir, err := wispStateDir()
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return false, fmt.Errorf("mkdir %s: %w", stateDir, err)
	}

	stamp := time.Now().Format("20060102-150405")
	logPath := filepath.Join(stateDir, "wisp-"+stamp+".log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return false, fmt.Errorf("open log %s: %w", logPath, err)
	}
	defer logFile.Close()

	readyR, readyW, err := os.Pipe()
	if err != nil {
		return false, err
	}
	defer readyR.Close()

	// Re-exec with the same argv but with daemon env vars set, stdio
	// redirected, and setsid so SIGHUP on PTY close does not propagate.
	cmd := exec.Command(os.Args[0], os.Args[1:]...)
	cmd.Env = append(os.Environ(),
		envDaemonized+"=1",
		envReadyFD+"=3",
		"WISP_LOG_PATH="+logPath, // child uses this for ready report
	)
	cmd.Stdin = nil
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.ExtraFiles = []*os.File{readyW} // fd 3 in child
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := cmd.Start(); err != nil {
		_ = readyW.Close()
		return false, fmt.Errorf("start daemon: %w", err)
	}
	pid := cmd.Process.Pid // capture before Release() invalidates Process.Pid
	_ = readyW.Close()     // parent doesn't need the write end

	// Read the ready report with a deadline. Pipe reads on Linux support
	// SetReadDeadline since Go 1.10.
	_ = readyR.SetReadDeadline(time.Now().Add(35 * time.Second))

	var msg readyMessage
	dec := json.NewDecoder(readyR)
	if err := dec.Decode(&msg); err != nil {
		// If the child died before sending anything, surface its exit.
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		if errors.Is(err, io.EOF) || os.IsTimeout(err) {
			return false, fmt.Errorf("daemon did not signal ready (check %s)", logPath)
		}
		return false, fmt.Errorf("decode ready: %w (check %s)", err, logPath)
	}
	// Let the daemon become independent — we don't Wait on it.
	if err := cmd.Process.Release(); err != nil {
		// Non-fatal; the OS will reap the zombie eventually anyway since
		// we're about to exit and init takes over.
		_ = err
	}

	if !msg.OK {
		return false, fmt.Errorf("daemon failed: %s\nsee %s", msg.Error, logPath)
	}
	msg.PID = pid
	msg.LogFile = logPath

	// Write a pid file alongside the log so the user has a kill handle.
	pidFile := filepath.Join(stateDir, "wisp-"+stamp+".pid")
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(pid)+"\n"), 0o600); err == nil {
		msg.PIDFile = pidFile
	}

	fmt.Fprintf(stdout, "wisp: tunnel started in background\n")
	fmt.Fprintf(stdout, "  pid:     %d\n", msg.PID)
	fmt.Fprintf(stdout, "  public:  %s:%d\n", msg.Server, msg.PublicPort)
	fmt.Fprintf(stdout, "  session: %s\n", msg.Session)
	fmt.Fprintf(stdout, "  ttl:     %ds\n", msg.GrantedTTL)
	fmt.Fprintf(stdout, "  log:     %s\n", msg.LogFile)
	if msg.PIDFile != "" {
		fmt.Fprintf(stdout, "  pidfile: %s\n", msg.PIDFile)
	}
	fmt.Fprintf(stdout, "  stop:    kill %d\n", msg.PID)
	return true, nil
}

// signalReady is called by the daemon child once Dial succeeds. It
// writes a readyMessage JSON object to envReadyFD and closes the fd
// so the parent can move on. On any failure it is a no-op (the parent
// will timeout and surface an error).
func signalReady(msg readyMessage) {
	fdStr := os.Getenv(envReadyFD)
	if fdStr == "" {
		return // not running as daemon
	}
	fd, err := strconv.Atoi(fdStr)
	if err != nil {
		return
	}
	f := os.NewFile(uintptr(fd), "ready")
	if f == nil {
		return
	}
	defer f.Close()
	_ = json.NewEncoder(f).Encode(msg)
}

func wispStateDir() (string, error) {
	if d := os.Getenv("WISP_STATE_DIR"); d != "" {
		return d, nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", errors.New("could not resolve home directory")
	}
	return filepath.Join(home, ".wisp"), nil
}
