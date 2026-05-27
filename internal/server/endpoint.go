package server

import (
	"crypto/rand"
	"encoding/base64"
)

// generateEndpoint returns a fresh 32-byte base64url-no-padding string
// suitable as the tunnel endpoint path segment. 32 bytes = 256 bits of
// entropy = 43 ASCII characters.
func generateEndpoint() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// isValidEndpoint reports whether s is a plausible endpoint path segment:
// base64url-no-padding, length 32-128 characters.
func isValidEndpoint(s string) bool {
	if len(s) < 32 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_':
		default:
			return false
		}
	}
	return true
}
