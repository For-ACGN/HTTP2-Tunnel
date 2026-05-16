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
		w.Header().Set("X-Backend-Host", r.Host)
		w.Header().Set("Set-Cookie", "session=abc123")
		w.Header().Set("Server", "nginx/1.0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	config := testBuildServerConfig()
	config.Web.Mode = WebModeProxy
	config.Web.Proxy.Target = backend.URL
	config.Web.Proxy.Filter = []string{"filtered_header"}
	server, err := NewServer(context.Background(), config)
	require.NoError(t, err)

	go func() {
		err := server.Serve()
		require.NoError(t, err)
	}()

	cfg := testBuildClientConfig()
	certs, err := parseCertificatesPEM([]byte(cfg.Server.RootCA))
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

	t.Run("basic proxy", func(t *testing.T) {
		resp, err := client.Get("https://127.0.0.1:2019/")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		require.Equal(t, http.StatusOK, resp.StatusCode)
		data, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, []byte("backend response"), data)
	})

	// TODO more sub tests

	err = server.Close()
	require.NoError(t, err)
}
