package h2tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/For-ACGN/utls"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

const testServerLogFile = "testdata/server.log"

func testRemoveServerLogFile(t *testing.T) {
	err := os.Remove(testServerLogFile)
	require.NoError(t, err)
}

func testBuildServerConfig() *ServerConfig {
	config := ServerConfig{}
	config.Common.PassHash = testPassHash
	config.Common.LogPath = testServerLogFile
	config.HTTP.Network = "tcp"
	config.HTTP.Address = "127.0.0.1:2019"
	config.TLS.Mode = TLSModeStatic
	config.TLS.Static.Cert = "testdata/server_cert.pem"
	config.TLS.Static.Key = "testdata/server_key.pem"
	config.Web.Mode = WebModeStatic
	config.Web.Static.Directory = "cmd/server/web"
	return &config
}

func TestNewServer(t *testing.T) {
	defer testRemoveServerLogFile(t)

	config := testBuildServerConfig()
	server, err := NewServer(context.Background(), config)
	require.NoError(t, err)

	err = server.Close()
	require.NoError(t, err)
}

func TestServer_CertPinning(t *testing.T) {
	defer testRemoveServerLogFile(t)

	config := testBuildServerConfig()
	server, err := NewServer(context.Background(), config)
	require.NoError(t, err)

	list, err := server.CertPinning(context.Background())
	require.NoError(t, err)
	require.Len(t, list, 1)
	t.Logf("%X\n", list[0])

	err = server.Close()
	require.NoError(t, err)
}

func TestServer_Serve(t *testing.T) {
	defer testRemoveServerLogFile(t)

	config := testBuildServerConfig()
	server, err := NewServer(context.Background(), config)
	require.NoError(t, err)

	go func() {
		err := server.Serve()
		require.NoError(t, err)
	}()

	time.Sleep(time.Second)

	err = server.Close()
	require.NoError(t, err)
}

func TestServer_handleConn(t *testing.T) {
	defer func() {
		testRemoveServerLogFile(t)
		testRemoveClientLogFile(t)
	}()

	serverCfg := testBuildServerConfig()
	server, err := NewServer(context.Background(), serverCfg)
	require.NoError(t, err)
	address := serverCfg.HTTP.Address

	go func() {
		err := server.Serve()
		require.NoError(t, err)
	}()

	clientCfg := testBuildClientConfig()
	client, err := NewClient(clientCfg)
	require.NoError(t, err)

	certs, err := parseCertificatesPEM([]byte(clientCfg.Client.RootCA))
	require.NoError(t, err)
	tlsConfig := utls.Config{
		NextProtos: []string{"h2", "http/1.1"},
	}
	tlsConfig.RootCAs = x509.NewCertPool()
	tlsConfig.RootCAs.AddCert(certs[0])

	transport := http2.Transport{
		DialTLSContext: func(context.Context, string, string, *tls.Config) (net.Conn, error) {
			cfg := tlsConfig.Clone()
			cfg.Random = <-client.randCh
			conn, err := utls.Dial("tcp", address, cfg)
			if err != nil {
				return nil, err
			}
			err = conn.Handshake()
			if err != nil {
				return nil, err
			}
			return conn, nil
		},
	}
	httpClient := http.Client{
		Transport: &transport,
		Timeout:   defaultClientTimeout,
	}
	URL := fmt.Sprintf("https://%s/", address)
	resp, err := httpClient.Get(URL)
	require.NoError(t, err)
	require.Equal(t, "HTTP/2.0", resp.Proto)
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	t.Log(len(data))
	t.Log(string(data))
	transport.CloseIdleConnections()

	err = client.Close()
	require.NoError(t, err)

	err = server.Close()
	require.NoError(t, err)
}

func TestServer_Simulation(t *testing.T) {
	defer testRemoveServerLogFile(t)

	config := testBuildServerConfig()
	server, err := NewServer(context.Background(), config)
	require.NoError(t, err)
	address := config.HTTP.Address

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

	URL := fmt.Sprintf("https://%s/", address)

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

			conn, err := tls.Dial("tcp", address, tlsConfig)
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
