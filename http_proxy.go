package h2tunnel

import (
	"bufio"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
)

func (c *Client) serveHTTPRequest(conn net.Conn, reader *bufio.Reader) (*tunnel, error) {
	req, err := http.ReadRequest(reader)
	if err != nil {
		c.logger.Warningf("invalid http request: %s from %s", err, conn.RemoteAddr())
		return nil, err
	}
	if !c.httpProxyAuthenticate(conn, req) {
		return nil, errors.New("http proxy authentication failed")
	}
	if req.Method == http.MethodConnect {
		return c.serveHTTPConnect(conn, req)
	}
	err = c.serveHTTPForward(conn, reader, req)
	return nil, err
}

func (c *Client) httpProxyAuthenticate(conn net.Conn, req *http.Request) bool {
	if c.frontUsername == "" && c.frontPassword == "" {
		return true
	}
	authInfo := strings.Split(req.Header.Get("Proxy-Authorization"), " ")
	if len(authInfo) != 2 {
		c.httpProxyFailedToAuth(conn)
		return false
	}
	authMethod := authInfo[0]
	authBase64 := authInfo[1]
	switch authMethod {
	case "Basic":
		auth, err := base64.StdEncoding.DecodeString(authBase64)
		if err != nil {
			c.httpProxyFailedToAuth(conn)
			return false
		}
		userPass := strings.SplitN(string(auth), ":", 2)
		if len(userPass) == 1 {
			userPass = append(userPass, "")
		}
		user := []byte(userPass[0])
		pass := []byte(userPass[1])
		eUser := []byte(c.frontUsername)
		ePass := []byte(c.frontPassword)
		userErr := subtle.ConstantTimeCompare(user, eUser) != 1
		passErr := subtle.ConstantTimeCompare(pass, ePass) != 1
		if userErr || passErr {
			userInfo := fmt.Sprintf("%s:%s", user, pass)
			c.logger.Warning("invalid username or password:", userInfo)
			c.httpProxyFailedToAuth(conn)
			return false
		}
		return true
	default:
		c.logger.Warning("unsupported authentication method:", authMethod)
		c.httpProxyFailedToAuth(conn)
		return false
	}
}

func (c *Client) httpProxyFailedToAuth(conn net.Conn) {
	resp := http.Response{}
	resp.StatusCode = http.StatusProxyAuthRequired
	resp.Proto = "HTTP/1.1"
	resp.ProtoMajor = 1
	resp.ProtoMinor = 1
	resp.Header = make(http.Header)
	resp.Header.Set("Proxy-Authenticate", "Basic realm=\"HTTP2-Tunnel\"")
	_ = resp.Write(conn)
}

func (c *Client) serveHTTPConnect(conn net.Conn, req *http.Request) (*tunnel, error) {
	tun, err := c.connect("HTTP-Tunnel", "tcp", req.URL.Host)
	if err != nil {
		resp := http.Response{}
		resp.StatusCode = http.StatusBadGateway
		resp.Proto = "HTTP/1.1"
		resp.ProtoMajor = 1
		resp.ProtoMinor = 1
		_ = resp.Write(conn)
		return nil, err
	}
	var success bool
	defer func() {
		if !success {
			_ = tun.Close()
		}
	}()
	_, err = conn.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n"))
	if err != nil {
		return nil, err
	}
	success = true
	return tun, nil
}

func (c *Client) serveHTTPForward(conn net.Conn, rd *bufio.Reader, req *http.Request) error {
	badResp := http.Response{}
	badResp.StatusCode = http.StatusBadGateway
	badResp.Proto = "HTTP/1.1"
	badResp.ProtoMajor = 1
	badResp.ProtoMinor = 1

	port := req.URL.Port()
	if port == "" {
		port = "80"
	}
	address := net.JoinHostPort(req.URL.Host, port)

	tun, err := c.connect("HTTP-Forward", "tcp", address)
	if err != nil {
		_ = badResp.Write(conn)
		return err
	}
	defer func() { _ = tun.Close() }()

	// process request loop
	tunBuf := bufio.NewReader(tun)
	for {
		err = req.Write(tun)
		if err != nil {
			_ = badResp.Write(conn)
			return err
		}
		resp, err := http.ReadResponse(tunBuf, req)
		if err != nil {
			_ = badResp.Write(conn)
			return err
		}
		err = resp.Write(conn)
		if err != nil {
			return nil
		}
		req, err = http.ReadRequest(rd)
		if err != nil {
			return nil
		}
	}
}
