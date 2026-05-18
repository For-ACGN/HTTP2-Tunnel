package h2tunnel

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

const testClientLogFile = "testdata/client.log"

var (
	testProxyUsername = "proxy_user"
	testProxyPassword = "proxy_pass"
)

func testRemoveClientLogFile(t *testing.T) {
	err := os.Remove(testClientLogFile)
	require.NoError(t, err)
}

func testBuildClientConfig() *ClientConfig {
	ca, err := os.ReadFile("testdata/root_ca.pem")
	if err != nil {
		panic(err)
	}
	config := ClientConfig{}
	config.Common.LogPath = testClientLogFile
	config.Common.Password = testPassword
	config.Client.PreConns = 4
	config.Server.Network = "tcp4"
	config.Server.Address = "localhost:2019"
	config.Server.RootCA = string(ca)
	config.Server.CertPin = []string{testCertPin}
	config.Front.Network = "tcp"
	config.Front.Address = "127.0.0.1:2020"
	return &config
}

func TestNewClient(t *testing.T) {
	defer testRemoveClientLogFile(t)

	config := testBuildClientConfig()
	client, err := NewClient(config)
	require.NoError(t, err)

	err = client.Close()
	require.NoError(t, err)
}

func TestClient_Check(t *testing.T) {
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

	err = client.Close()
	require.NoError(t, err)

	err = server.Close()
	require.NoError(t, err)
}

func TestClient_Login(t *testing.T) {
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

	err = client.Close()
	require.NoError(t, err)

	err = server.Close()
	require.NoError(t, err)
}

func TestClient_Logout(t *testing.T) {
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

	err = client.Logout()
	require.NoError(t, err)
	err = client.Close()
	require.NoError(t, err)

	err = server.Close()
	require.NoError(t, err)
}

func TestClient_Serve(t *testing.T) {
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
	require.Equal(t, "HTTP/2.0", resp.Proto)
	t.Log(len(data))
	t.Log(string(data))

	err = client.Logout()
	require.NoError(t, err)
	err = client.Close()
	require.NoError(t, err)

	err = server.Close()
	require.NoError(t, err)
}
