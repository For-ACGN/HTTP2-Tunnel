package h2tunnel

import (
	"compress/flate"
	"compress/gzip"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type hfs struct {
	dir string
	hfs http.Handler
}

func newHFS(dir string) http.Handler {
	fs := http.FileServer(http.Dir(dir))
	return &hfs{dir: dir, hfs: fs}
}

func (hfs *hfs) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// prevent directory traversal
	path := r.URL.Path
	if path == "/" {
		path = "/index.html"
	}
	if isDir(filepath.Join(hfs.dir, path)) {
		w.WriteHeader(http.StatusOK)
		return
	}
	// process compress
	encoding := r.Header.Get("Accept-Encoding")
	switch {
	case strings.Contains(encoding, "gzip"):
		w.Header().Set("Content-Encoding", "gzip")
		gzw := gzip.NewWriter(w)
		defer func() {
			if w.Header().Get("Content-Encoding") == "gzip" {
				_ = gzw.Close()
			}
		}()
		w = &gzipResponseWriter{ResponseWriter: w, w: gzw}
	case strings.Contains(encoding, "deflate"):
		w.Header().Set("Content-Encoding", "deflate")
		dw, _ := flate.NewWriter(w, flate.BestCompression)
		defer func() {
			if w.Header().Get("Content-Encoding") == "deflate" {
				_ = dw.Close()
			}
		}()
		w = &flateResponseWriter{ResponseWriter: w, w: dw}
	}
	// prevent incorrect cache
	r.Header.Del("If-Modified-Since")
	// process file
	hfs.hfs.ServeHTTP(w, r)
}

func isDir(path string) bool {
	file, err := os.Open(path) // #nosec
	if err != nil {
		return false
	}
	defer func() { _ = file.Close() }()
	stat, err := file.Stat()
	if err != nil {
		return false
	}
	return stat.IsDir()
}

type gzipResponseWriter struct {
	http.ResponseWriter
	w *gzip.Writer

	written bool
	enabled bool
}

func (rw *gzipResponseWriter) Write(b []byte) (int, error) {
	if !rw.written {
		rw.enabled = rw.Header().Get("Content-Encoding") == "gzip"
		rw.written = true
	}
	if rw.enabled {
		return rw.w.Write(b)
	}
	return rw.ResponseWriter.Write(b)
}

type flateResponseWriter struct {
	http.ResponseWriter
	w *flate.Writer

	written bool
	enabled bool
}

func (rw *flateResponseWriter) Write(b []byte) (int, error) {
	if !rw.written {
		rw.enabled = rw.Header().Get("Content-Encoding") == "deflate"
		rw.written = true
	}
	if rw.enabled {
		return rw.w.Write(b)
	}
	return rw.ResponseWriter.Write(b)
}
