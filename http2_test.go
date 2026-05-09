package msocks

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestHTTP2Simulation(t *testing.T) {
	t.Run("function", func(t *testing.T) {
		client, server := net.Pipe()

		go func() {
			err := simulateHTTP2Server(server)
			require.NoError(t, err)

			_, err = server.Write([]byte{0x01, 0x02, 0x03, 0x04})
			require.NoError(t, err)
		}()

		err := simulateHTTP2Client(client, nil)
		require.NoError(t, err)

		buf := make([]byte, 4)
		_, err = io.ReadFull(client, buf)
		require.NoError(t, err)

		expected := []byte{0x01, 0x02, 0x03, 0x04}
		require.Equal(t, expected, buf)

		err = client.Close()
		require.NoError(t, err)
		err = server.Close()
		require.NoError(t, err)
	})

	t.Run("instance", func(t *testing.T) {
		defer func() {
			testRemoveClientLogFile(t)
			testRemoveServerLogFile(t)
		}()

		serverCfg := testBuildServerConfig()
		server, err := NewServer(context.Background(), serverCfg)
		require.NoError(t, err)
		require.NotNil(t, server)
		go func() {
			err := server.Serve()
			require.NoError(t, err)
		}()

		clientCfg := testBuildClientConfig()
		clientCfg.Client.PreConns = 0
		client, err := NewClient(clientCfg)
		require.NoError(t, err)
		err = client.Login()
		require.NoError(t, err)

		err = client.Close()
		require.NoError(t, err)

		err = server.Close()
		require.NoError(t, err)
	})
}

func TestHTTPServerSimulation(t *testing.T) {
	config := testBuildServerConfig()
	cert := config.TLS.Static.Cert
	key := config.TLS.Static.Key
	server := http.Server{
		Addr:    config.HTTP.Address,
		Handler: http.DefaultServeMux,
	}
	go func() {
		err := server.ListenAndServeTLS(cert, key)
		require.Equal(t, http.ErrServerClosed, err)
	}()

	cfg := testBuildClientConfig()
	certs, err := parseCertificatesPEM([]byte(cfg.Server.RootCA))
	require.NoError(t, err)
	tlsConfig := &tls.Config{}
	tlsConfig.RootCAs = x509.NewCertPool()
	tlsConfig.RootCAs.AddCert(certs[0])

	URL := fmt.Sprintf("https://%s/", server.Addr)

	t.Run("http/1.1", func(t *testing.T) {
		for i := 0; i < 20; i++ {
			tlsConfig = tlsConfig.Clone()
			tlsConfig.NextProtos = []string{"http/1.1"}

			conn, err := tls.Dial("tcp", server.Addr, tlsConfig)
			require.NoError(t, err)

			err = conn.Handshake()
			require.NoError(t, err)
			proto := conn.ConnectionState().NegotiatedProtocol
			require.Equal(t, "http/1.1", proto)

			req, err := http.NewRequest(http.MethodGet, URL, nil)
			require.NoError(t, err)
			err = req.Write(conn)
			require.NoError(t, err)
			resp, err := http.ReadResponse(bufio.NewReader(conn), req)
			require.NoError(t, err)
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()

			err = conn.Close()
			require.NoError(t, err)

			time.Sleep(10 * time.Millisecond)
		}
	})

	t.Run("http/2.0", func(t *testing.T) {
		for i := 0; i < 20; i++ {
			tlsConfig = tlsConfig.Clone()
			tlsConfig.NextProtos = []string{"h2", "http/1.1"}

			req, err := http.NewRequest(http.MethodGet, URL, nil)
			require.NoError(t, err)

			tr := http.Transport{
				TLSClientConfig:   tlsConfig,
				ForceAttemptHTTP2: true,
			}
			resp, err := tr.RoundTrip(req)
			require.NoError(t, err)
			require.Equal(t, "HTTP/2.0", resp.Proto)
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()

			tr.CloseIdleConnections()

			time.Sleep(10 * time.Millisecond)
		}
	})

	t.Run("h2 but h1 request", func(t *testing.T) {
		for i := 0; i < 20; i++ {
			tlsConfig = tlsConfig.Clone()
			tlsConfig.NextProtos = []string{"h2", "http/1.1"}

			conn, err := tls.Dial("tcp", server.Addr, tlsConfig)
			require.NoError(t, err)

			err = conn.Handshake()
			require.NoError(t, err)
			proto := conn.ConnectionState().NegotiatedProtocol
			require.Equal(t, "h2", proto)

			req, err := http.NewRequest(http.MethodGet, URL, nil)
			require.NoError(t, err)
			err = req.Write(conn)
			require.NoError(t, err)
			resp, err := http.ReadResponse(bufio.NewReader(conn), req)
			t.Log(err)
			require.Nil(t, resp)

			err = conn.Close()
			require.NoError(t, err)

			time.Sleep(100 * time.Millisecond)
		}
	})

	err = server.Close()
	require.NoError(t, err)
}
