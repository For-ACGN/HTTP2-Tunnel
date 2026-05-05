package msocks

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

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
	tlsConfig.NextProtos = []string{"h2", "http/1.1"}

	conn, err := tls.Dial("tcp", server.Addr, tlsConfig)
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

	err = server.Close()
	require.NoError(t, err)
}
