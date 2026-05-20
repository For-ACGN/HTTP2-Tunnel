package h2tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReverseProxy(t *testing.T) {
	defer testRemoveServerLogFile(t)

	// start mock backend server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header
		require.Empty(t, header.Get("Cookie"))
		require.Empty(t, header.Get("Authorization"))
		require.Empty(t, header.Get("Filtered-Header"))

		header = w.Header()
		header.Set("X-Backend-Host", r.Host)
		header.Set("Server", "nginx/1.0")
		header.Set("Set-Cookie", "session=abc123")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	config := testBuildServerConfig()
	config.Web.Mode = WebModeProxy
	config.Web.Proxy.Target = backend.URL
	config.Web.Proxy.Filter = []string{"Filtered-Header"}
	server, err := NewServer(context.Background(), config)
	require.NoError(t, err)

	go func() {
		err := server.Serve()
		require.NoError(t, err)
	}()

	cfg := testBuildClientConfig()
	certs, err := parseCertificatesPEM([]byte(cfg.Client.RootCA))
	require.NoError(t, err)
	tlsConfig := &tls.Config{}
	tlsConfig.RootCAs = x509.NewCertPool()
	tlsConfig.RootCAs.AddCert(certs[0])
	tr := http.Transport{
		TLSClientConfig: tlsConfig,
	}
	client := http.Client{
		Transport: &tr,
	}
	URL := "https://127.0.0.1:2019/"

	t.Run("basic proxy", func(t *testing.T) {
		resp, err := client.Get(URL)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		require.Equal(t, http.StatusOK, resp.StatusCode)
		data, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, []byte("backend response"), data)
	})

	t.Run("request headers stripped", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, URL, nil)
		require.NoError(t, err)
		header := req.Header
		header.Set("Cookie", "secret=token")
		header.Set("Authorization", "Bearer secret")
		resp, err := client.Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
	})

	t.Run("strip custom headers", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, URL, nil)
		require.NoError(t, err)
		header := req.Header
		header.Set("filtered_header", "secret=token")
		resp, err := client.Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
	})

	t.Run("strip response headers", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, URL, nil)
		require.NoError(t, err)
		header := req.Header
		header.Set("Cookie", "secret=token")
		header.Set("Authorization", "Bearer secret")
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		header = resp.Header
		require.Equal(t, "", header.Get("Set-Cookie"))
		require.Equal(t, "", header.Get("Authorization"))
	})

	err = server.Close()
	require.NoError(t, err)
}
