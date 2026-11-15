package httpapi

import (
	"bytes"
	"fmt"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

const surfaceMarker = `<meta name="pki-surface" content="auto" />`

// MountFrontend serves the embedded SPA on both configured hostnames. APIs and
// publication endpoints always retain their own routing and error behavior.
func (s *Server) MountFrontend(assets fs.FS) error {
	index, err := fs.ReadFile(assets, "index.html")
	if err != nil || !bytes.Contains(index, []byte(surfaceMarker)) {
		return fmt.Errorf("frontend bundle missing or invalid; build with make pki-console")
	}
	s.consoleFrontend = frontendHandler(assets, index, "console")
	s.publicFrontend = frontendHandler(assets, index, "public")
	return nil
}

func serveSurface(w http.ResponseWriter, r *http.Request, api *http.ServeMux, frontend http.Handler) {
	name := strings.TrimPrefix(r.URL.Path, "/")
	for _, prefix := range []string{"api", "pki", "issuers", "crl", "ocsp", "tsa", "health", "signing"} {
		if name == prefix || strings.HasPrefix(name, prefix+"/") {
			api.ServeHTTP(w, r)
			return
		}
	}
	if frontend != nil {
		frontend.ServeHTTP(w, r)
		return
	}
	api.ServeHTTP(w, r)
}

func frontendHandler(assets fs.FS, index []byte, surface string) http.Handler {
	index = bytes.Replace(index, []byte(surfaceMarker), []byte(`<meta name="pki-surface" content="`+surface+`" />`), 1)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		for _, part := range strings.Split(name, "/") {
			if strings.HasPrefix(part, ".") && part != "." {
				http.NotFound(w, r)
				return
			}
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'; img-src 'self' data:; font-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; worker-src 'self'; manifest-src 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cache-Control", "no-cache")
		if name != "" && name != "." && name != "index.html" {
			info, err := fs.Stat(assets, name)
			if err == nil && info.Mode().IsRegular() {
				if strings.HasPrefix(name, "assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				http.FileServerFS(assets).ServeHTTP(w, r)
				return
			}
			if path.Ext(name) != "" || strings.HasPrefix(name, "assets/") || name == "assets" {
				http.NotFound(w, r)
				return
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(index))
	})
}
