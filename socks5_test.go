package msocks

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSOCKS5_ServeSOCKS5(t *testing.T) {
	t.Run("common", func(t *testing.T) {
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
		client, err := NewClient(clientCfg)
		require.NoError(t, err)
		require.NotNil(t, client)

		go func() {
			err := client.Serve()
			require.NoError(t, err)
		}()

		transport := http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) {
				return url.Parse("socks5://127.0.0.1:2020/")
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
	})

	t.Run("failed to connect", func(t *testing.T) {
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
		clientCfg.Client.Timeout = duration(3 * time.Second)

		client, err := NewClient(clientCfg)
		require.NoError(t, err)
		require.NotNil(t, client)

		go func() {
			err := client.Serve()
			require.NoError(t, err)
		}()

		transport := http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) {
				return url.Parse("socks5://127.0.0.1:2020/")
			},
		}
		httpClient := http.Client{
			Transport: &transport,
		}
		resp, err := httpClient.Get("https://invalid-fff17531.com/")
		require.Error(t, err)
		require.Nil(t, resp)

		err = client.Close()
		require.NoError(t, err)

		err = server.Close()
		require.NoError(t, err)
	})
}

func TestSOCKS5_Authenticate(t *testing.T) {
	t.Run("common", func(t *testing.T) {
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
		clientCfg.Front.Username = testProxyUsername
		clientCfg.Front.Password = testProxyPassword

		client, err := NewClient(clientCfg)
		require.NoError(t, err)
		require.NotNil(t, client)

		go func() {
			err := client.Serve()
			require.NoError(t, err)
		}()

		transport := http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) {
				format := "socks5://%s:%s@127.0.0.1:2020/"
				URL := fmt.Sprintf(format, testProxyUsername, testProxyPassword)
				return url.Parse(URL)
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
	})

	t.Run("without password", func(t *testing.T) {
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
		clientCfg.Front.Username = testProxyUsername
		clientCfg.Front.Password = testProxyPassword

		client, err := NewClient(clientCfg)
		require.NoError(t, err)
		require.NotNil(t, client)

		go func() {
			err := client.Serve()
			require.NoError(t, err)
		}()

		transport := http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) {
				return url.Parse("socks5://127.0.0.1:2020/")
			},
		}
		httpClient := http.Client{
			Transport: &transport,
		}
		resp, err := httpClient.Get("https://github.com/")
		require.ErrorContains(t, err, "no acceptable authentication methods")
		require.Nil(t, resp)

		err = client.Close()
		require.NoError(t, err)

		err = server.Close()
		require.NoError(t, err)
	})

	t.Run("failed to authenticate", func(t *testing.T) {
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
		clientCfg.Front.Username = testProxyUsername
		clientCfg.Front.Password = testProxyPassword

		client, err := NewClient(clientCfg)
		require.NoError(t, err)
		require.NotNil(t, client)

		go func() {
			err := client.Serve()
			require.NoError(t, err)
		}()

		transport := http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) {
				format := "socks5://%s:%s@127.0.0.1:2020/"
				URL := fmt.Sprintf(format, "invalid_user", "invalid_pass")
				return url.Parse(URL)
			},
		}
		httpClient := http.Client{
			Transport: &transport,
		}
		resp, err := httpClient.Get("https://github.com/")
		require.ErrorContains(t, err, "authentication failed")
		require.Nil(t, resp)

		err = client.Close()
		require.NoError(t, err)

		err = server.Close()
		require.NoError(t, err)
	})
}
