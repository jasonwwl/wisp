// Package version reports the build version of the wisp binary.
//
// At release time the linker overrides Tag and Commit via -ldflags:
//
//	go build -ldflags="-X github.com/jasonwwl/wisp/internal/version.Tag=v0.1.0 \
//	                   -X github.com/jasonwwl/wisp/internal/version.Commit=$(git rev-parse --short HEAD)"
package version

import (
	"fmt"
	"runtime/debug"
)

// Tag is the human-readable release tag (e.g. "v0.1.0"). For development
// builds it stays at "0.0.0-dev"; the linker overwrites it at release time.
var Tag = "0.0.0-dev"

// Commit is the git short SHA the binary was built from. For untagged
// development builds it is taken from runtime/debug.BuildInfo when available.
var Commit = ""

// String returns a single-line version banner suitable for "wisp version".
func String() string {
	commit := Commit
	if commit == "" {
		if info, ok := debug.ReadBuildInfo(); ok {
			for _, s := range info.Settings {
				if s.Key == "vcs.revision" && len(s.Value) >= 7 {
					commit = s.Value[:7]
					break
				}
			}
		}
	}
	if commit == "" {
		return Tag
	}
	return fmt.Sprintf("%s (%s)", Tag, commit)
}
