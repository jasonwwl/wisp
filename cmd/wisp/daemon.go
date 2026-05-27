package main

// daemon-related types shared by the per-platform implementations.

const (
	envDaemonized = "WISP_DAEMONIZED"
	envReadyFD    = "WISP_READY_FD"
)

// readyMessage is sent from the daemon child to the launcher parent
// over a pipe (envReadyFD) so the parent can report the negotiated
// tunnel parameters before exiting. Encoded as one JSON object
// followed by EOF.
type readyMessage struct {
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
	Session    string `json:"session,omitempty"`
	Server     string `json:"server,omitempty"`
	PublicPort int    `json:"public_port,omitempty"`
	GrantedTTL int    `json:"granted_ttl_sec,omitempty"`
	PID        int    `json:"pid,omitempty"`
	PIDFile    string `json:"pid_file,omitempty"`
	LogFile    string `json:"log_file,omitempty"`
}
