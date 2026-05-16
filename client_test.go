package h2tunnel

import (
	"context"
	"io"
	"net"
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
	config.Server.CertPin = []string{"2DE2FF137B4B825A511B52C9CCD6CB4DC3F4676A7F6E1EB3F2AE8C30FFA09640"}
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

	err = client.Check()
	require.NoError(t, err)

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

	err = client.Check()
	require.NoError(t, err)
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

	err = client.Check()
	require.NoError(t, err)
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

	err = client.Close()
	require.NoError(t, err)

	err = server.Close()
	require.NoError(t, err)
}

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

	err = client.Close()
	require.NoError(t, err)

	err = server.Close()
	require.NoError(t, err)
}

func TestClient_mimic(t *testing.T) {

}
