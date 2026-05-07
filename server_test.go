package msocks

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const testServerLogFile = "testdata/server.log"

func testRemoveServerLogFile(t *testing.T) {
	err := os.Remove(testServerLogFile)
	require.NoError(t, err)
}

func testBuildServerConfig() *ServerConfig {
	config := ServerConfig{}
	config.Common.LogPath = testServerLogFile
	config.Common.PassHash = testPassHash
	config.HTTP.Network = "tcp"
	config.HTTP.Address = "127.0.0.1:2019"
	config.TLS.Mode = TLSModeStatic
	config.TLS.Static.Cert = "testdata/server_cert.pem"
	config.TLS.Static.Key = "testdata/server_key.pem"
	config.Web.Directory = "cmd/server/web"
	return &config
}

func TestNewServer(t *testing.T) {
	defer testRemoveServerLogFile(t)

	config := testBuildServerConfig()
	server, err := NewServer(context.Background(), config)
	require.NoError(t, err)
	require.NotNil(t, server)

	err = server.Close()
	require.NoError(t, err)
}

func TestServer_Serve(t *testing.T) {
	defer testRemoveServerLogFile(t)

	config := testBuildServerConfig()
	server, err := NewServer(context.Background(), config)
	require.NoError(t, err)
	require.NotNil(t, server)

	go func() {
		err := server.Serve()
		require.NoError(t, err)
	}()

	time.Sleep(time.Second)

	err = server.Close()
	require.NoError(t, err)
}

func TestServer_Simulation(t *testing.T) {
	defer testRemoveServerLogFile(t)

	config := testBuildServerConfig()
	server, err := NewServer(context.Background(), config)
	require.NoError(t, err)
	require.NotNil(t, server)
	address := config.HTTP.Address

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

	t.Run("http/1.1", func(t *testing.T) {
		for i := 0; i < 20; i++ {
			tlsConfig = tlsConfig.Clone()
			tlsConfig.NextProtos = []string{"http/1.1"}

			conn, err := tls.Dial("tcp", address, tlsConfig)
			require.NoError(t, err)

			err = conn.Handshake()
			require.NoError(t, err)
			proto := conn.ConnectionState().NegotiatedProtocol
			require.Equal(t, "http/1.1", proto)

			req, err := http.NewRequest(http.MethodGet, "/", nil)
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

	t.Run("http/2", func(t *testing.T) {
		for i := 0; i < 20; i++ {
			tlsConfig = tlsConfig.Clone()
			tlsConfig.NextProtos = []string{"h2", "http/1.1"}

			conn, err := tls.Dial("tcp", address, tlsConfig)
			require.NoError(t, err)

			err = conn.Handshake()
			require.NoError(t, err)
			proto := conn.ConnectionState().NegotiatedProtocol
			require.Equal(t, "h2", proto)

			req, err := http.NewRequest(http.MethodGet, "/", nil)
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
