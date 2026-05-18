package h2tunnel

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/For-ACGN/utls"
	"github.com/stretchr/testify/require"
)

func TestClient_DisablePreConn(t *testing.T) {
	defer func() {
		testRemoveClientLogFile(t)
		testRemoveServerLogFile(t)
	}()

	serverCfg := testBuildServerConfig()
	server, err := NewServer(context.Background(), serverCfg)
	require.NoError(t, err)

	go func() {
		err := server.Serve()
		require.NoError(t, err)
	}()

	clientCfg := testBuildClientConfig()
	clientCfg.Client.PreConns = 0
	client, err := NewClient(clientCfg)
	require.NoError(t, err)
	hijacked, err := client.Detect()
	require.NoError(t, err)
	require.False(t, hijacked)
	err = client.Login()
	require.NoError(t, err)

	go func() {
		err := client.Serve()
		require.NoError(t, err)
	}()

	transport := http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) {
			return url.Parse("http://127.0.0.1:2020/")
		},
	}
	httpClient := http.Client{
		Transport: &transport,
	}
	resp, err := httpClient.Get("https://github.com/")
	require.NoError(t, err)
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	t.Log(len(data))
	t.Log(string(data))

	err = client.Logout()
	require.NoError(t, err)
	err = client.Close()
	require.NoError(t, err)

	err = server.Close()
	require.NoError(t, err)
}

func TestClient_Hijacked(t *testing.T) {
	defer func() {
		testRemoveClientLogFile(t)
		testRemoveServerLogFile(t)
	}()

	serverCfg := testBuildServerConfig()
	server, err := NewServer(context.Background(), serverCfg)
	require.NoError(t, err)

	go func() {
		err := server.Serve()
		require.NoError(t, err)
	}()

	clientCfg := testBuildClientConfig()
	pin := strings.Repeat("a", len(testCertPin))
	clientCfg.Server.CertPin = []string{pin}
	client, err := NewClient(clientCfg)
	require.NoError(t, err)

	hijacked, err := client.Detect()
	require.Error(t, err)
	require.True(t, hijacked)
	t.Log(err)

	err = client.Close()
	require.NoError(t, err)

	err = server.Close()
	require.NoError(t, err)
}

func TestClient_connect(t *testing.T) {
	defer func() {
		testRemoveClientLogFile(t)
		testRemoveServerLogFile(t)
	}()

	serverCfg := testBuildServerConfig()
	server, err := NewServer(context.Background(), serverCfg)
	require.NoError(t, err)

	go func() {
		err := server.Serve()
		require.NoError(t, err)
	}()

	clientCfg := testBuildClientConfig()
	clientCfg.Client.PreConns = 1
	client, err := NewClient(clientCfg)
	require.NoError(t, err)
	hijacked, err := client.Detect()
	require.NoError(t, err)
	require.False(t, hijacked)
	err = client.Login()
	require.NoError(t, err)

	go func() {
		err := client.Serve()
		require.NoError(t, err)
	}()

	transport := http.Transport{
		DialContext: func(_ context.Context, net, addr string) (net.Conn, error) {
			return client.connect("test", net, addr)
		},
	}
	httpClient := http.Client{
		Transport: &transport,
	}
	resp, err := httpClient.Get("https://github.com/")
	require.NoError(t, err)
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	t.Log(len(data))
	t.Log(string(data))

	err = client.Logout()
	require.NoError(t, err)
	err = client.Close()
	require.NoError(t, err)

	err = server.Close()
	require.NoError(t, err)
}

func TestClient_mimic(t *testing.T) {
	defer func() {
		testRemoveClientLogFile(t)
		testRemoveServerLogFile(t)
	}()

	serverCfg := testBuildServerConfig()
	server, err := NewServer(context.Background(), serverCfg)
	require.NoError(t, err)

	go func() {
		err := server.Serve()
		require.NoError(t, err)
	}()

	clientCfg := testBuildClientConfig()
	client, err := NewClient(clientCfg)
	require.NoError(t, err)
	hijacked, err := client.Detect()
	require.NoError(t, err)
	require.False(t, hijacked)
	err = client.Login()
	require.NoError(t, err)

	conn, err := utls.Dial(client.serverNet, client.serverAddr, client.tlsConfig)
	require.NoError(t, err)
	err = client.mimic(conn)
	require.NoError(t, err)

	err = client.Logout()
	require.NoError(t, err)
	err = client.Close()
	require.NoError(t, err)

	err = server.Close()
	require.NoError(t, err)
}
