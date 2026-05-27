package server

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// decoyHandler serves the public-facing site at "/". Any path other than
// the configured tunnel endpoint reaches this handler. The intent is to
// look like an ordinary low-traffic self-hosted HTTPS service.
//
// See docs/design.md §11.
func (s *Server) decoyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "nginx/1.24.0")
	// X-Content-Type-Options is set by many real nginx defaults; including
	// it raises the bar slightly for trivial fingerprinting.
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if r.URL.Path == "/robots.txt" {
		w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
		_, _ = w.Write([]byte("User-agent: *\nDisallow:\n"))
		return
	}

	if s.cfg.DecoyDir != "" {
		if served := s.serveFromDecoyDir(w, r); served {
			return
		}
		// fall through to built-in 404
	}

	if r.URL.Path == "/" || r.URL.Path == "/index.html" {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		_, _ = w.Write([]byte(builtinIndex))
		return
	}

	s.write404(w)
}

// write404 is the single emission point for nginx-style 404 responses.
// All paths that need to look like a "wrong URL on an ordinary nginx
// site" — decoy fall-through, tunnel-endpoint-without-token, tunnel
// upgrade failure — go through here so a passive observer cannot
// distinguish them by body length, headers, or content.
func (s *Server) write404(w http.ResponseWriter) {
	w.Header().Set("Server", "nginx/1.24.0")
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(builtinNotFound))
}

func (s *Server) serveFromDecoyDir(w http.ResponseWriter, r *http.Request) bool {
	clean := filepath.Clean(r.URL.Path)
	if strings.HasPrefix(clean, "..") {
		return false
	}
	if clean == "/" {
		clean = "/index.html"
	}
	full := filepath.Join(s.cfg.DecoyDir, clean)
	info, err := os.Stat(full)
	if err != nil || info.IsDir() {
		return false
	}
	http.ServeFile(w, r, full)
	return true
}

const builtinIndex = `<!DOCTYPE html>
<html>
<head><title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
`

const builtinNotFound = `<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.24.0</center>
</body>
</html>
`
