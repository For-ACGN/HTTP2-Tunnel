package msocks

import (
	"time"
)

const (
	defaultMaxBufferSize = 32 * 1024
	defaultBufferSize    = 4096
	defaultJitterLevel   = 3
	maximumJitterLevel   = 10
)

// ServerConfig contains configurations for proxy server.
type ServerConfig struct {
	Common struct {
		PassHash string `toml:"pwd_hash"`
		LogPath  string `toml:"log_path"`
	} `toml:"common"`

	HTTP struct {
		Network  string   `toml:"network"`
		Address  string   `toml:"address"`
		Timeout  duration `toml:"timeout"`
		MaxConns int      `toml:"max_conns"`
	} `toml:"http"`

	TLS struct {
		Mode string `toml:"mode"`

		ACME struct {
			Domains []string `toml:"domains"`
		} `toml:"acme"`

		Static struct {
			Cert string `toml:"cert_path"`
			Key  string `toml:"key_path"`
		} `toml:"static"`
	} `toml:"tls"`

	Tunnel struct {
		MaxBufferSize int `toml:"max_buffer_size"`
	} `toml:"tunnel"`

	Web struct {
		Mode string `toml:"mode"`

		Proxy struct {
			Target string   `toml:"target"`
			Filter []string `toml:"filter"`
		} `toml:"proxy"`

		Static struct {
			Directory string `toml:"dir"`
		} `toml:"static"`
	} `toml:"web"`
}

// ClientConfig contains configurations for proxy client.
type ClientConfig struct {
	Common struct {
		Password string `toml:"password"`
		LogPath  string `toml:"log_path"`
	} `toml:"common"`

	Client struct {
		Timeout  duration `toml:"timeout"`
		PreConns int      `toml:"pre_conns"`
	} `toml:"client"`

	Server struct {
		Network string `toml:"network"`
		Address string `toml:"address"`
		RootCA  string `toml:"root_ca"`
	} `toml:"server"`

	Front struct {
		Network  string `toml:"network"`
		Address  string `toml:"address"`
		Username string `toml:"username"`
		Password string `toml:"password"`
	} `toml:"front"`

	Tunnel struct {
		BufferSize  int `toml:"buffer_size"`
		JitterLevel int `toml:"jitter_level"`
	} `toml:"tunnel"`

	Android struct {
		DNSServer string `toml:"dns_server"`
	} `toml:"android"`
} // #nosec

// duration is patch for toml v2.
type duration time.Duration

// MarshalText implement encoding.TextMarshaler.
func (d duration) MarshalText() ([]byte, error) {
	return []byte(time.Duration(d).String()), nil
}

// UnmarshalText implement encoding.TextUnmarshaler.
func (d *duration) UnmarshalText(b []byte) error {
	x, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	*d = duration(x)
	return nil
}
