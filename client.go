package msocks

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/For-ACGN/utls"
	"github.com/dustin/go-humanize"
	"github.com/pkg/errors"
	"golang.org/x/crypto/curve25519"
)

const (
	defaultPreConns      = 32
	defaultClientTimeout = 10 * time.Second
)

// Client is a SoH client with SOCKS4, SOCKS5 and HTTP proxy server.
type Client struct {
	logger *logger

	secret     []byte
	passHash   string
	pathHash   string
	timeout    time.Duration
	preConns   int
	bufferSize int
	jitLevel   int
	dnsServer  string

	serverNet  string
	serverAddr string
	tlsConfig  *utls.Config

	frontUsername string
	frontPassword string
	frontListener net.Listener

	randCh chan []byte
	connCh chan net.Conn

	numConns  int64
	numSend   int64
	numRecv   int64
	counterMu sync.Mutex

	inShutdown atomic.Bool

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewClient is used to create SoH client.
func NewClient(config *ClientConfig) (*Client, error) {
	logger, err := newLogger(config.Common.LogPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open log file")
	}
	h := sha256.Sum256([]byte(config.Common.Password))
	secret := h[:]
	passHash := hex.EncodeToString(secret)
	pathHash := passHash[:8] + passHash[32:32+8]
	timeout := time.Duration(config.Client.Timeout)
	if timeout < time.Second {
		timeout = defaultClientTimeout
	}
	preConns := config.Client.PreConns
	if preConns < 0 {
		preConns = defaultPreConns
	}
	bufferSize := config.Tunnel.BufferSize
	if bufferSize < 1 {
		bufferSize = defaultBufferSize
	}
	jitLevel := config.Tunnel.JitterLevel
	if jitLevel < 1 {
		jitLevel = defaultJitterLevel
	}
	if jitLevel > maximumJitterLevel {
		return nil, errors.Errorf("jitter level must be between 1 and %d", maximumJitterLevel)
	}
	// prepare tls config for client
	tlsConfig := &utls.Config{}
	rootCA := config.Server.RootCA
	if rootCA != "" {
		certs, err := parseCertificatesPEM([]byte(rootCA))
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse Root CA certificates")
		}
		certPool := x509.NewCertPool()
		for _, cert := range certs {
			certPool.AddCert(cert)
		}
		tlsConfig.RootCAs = certPool
	}
	// prepare the front server listener
	listener, err := net.Listen(config.Front.Network, config.Front.Address)
	if err != nil {
		return nil, errors.Wrap(err, "failed to listen for the front server")
	}
	// build pre-connection channel
	var connCh chan net.Conn
	if preConns != 0 {
		connCh = make(chan net.Conn, preConns)
	} else {
		connCh = make(chan net.Conn, 1)
	}
	client := Client{
		logger: logger,

		secret:     secret,
		passHash:   passHash,
		pathHash:   pathHash,
		timeout:    timeout,
		preConns:   preConns,
		bufferSize: bufferSize,
		jitLevel:   jitLevel,
		dnsServer:  config.Android.DNSServer,

		serverNet:  config.Server.Network,
		serverAddr: config.Server.Address,
		tlsConfig:  tlsConfig,

		frontUsername: config.Front.Username,
		frontPassword: config.Front.Password,
		frontListener: listener,

		randCh: make(chan []byte, 128+preConns),
		connCh: connCh,
	}
	client.ctx, client.cancel = context.WithCancel(context.Background())
	// start secret random generator
	client.wg.Add(1)
	go client.generator()
	return &client, nil
}

func (c *Client) buildURL(path string) string {
	return fmt.Sprintf("https://%s/%s/%s", c.serverAddr, c.pathHash, path)
}

// Login is used to log in to server.
func (c *Client) Login() error {
	conn, err := c.dial()
	if err != nil {
		return err
	}
	var success bool
	defer func() {
		if !success {
			_ = conn.Close()
		}
	}()
	// build request about login
	req, err := http.NewRequestWithContext(c.ctx, http.MethodGet, c.buildURL("login"), nil)
	if err != nil {
		return errors.Wrap(err, "failed to create request for login")
	}
	garbage := make([]byte, 128+newMathRand().Intn(4*1024))
	header := req.Header
	header.Set("Pass-Hash", c.passHash)
	header.Set("Obfuscation", hex.EncodeToString(garbage))
	// send request and process response
	err = req.Write(conn)
	if err != nil {
		return errors.Wrap(err, "failed to write log in request")
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return errors.Wrap(err, "failed to read response about log in")
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("login failed with status: %s", resp.Status)
	}
	// send to the pre connection channel
	select {
	case c.connCh <- conn:
		success = true
	case <-c.ctx.Done():
	}
	return nil
}

// Logout is used to log out to server.
func (c *Client) Logout() error {
	conn, err := c.dial()
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	// build request about logout
	req, err := http.NewRequestWithContext(c.ctx, http.MethodGet, c.buildURL("logout"), nil)
	if err != nil {
		return errors.Wrap(err, "failed to create request for logout")
	}
	garbage := make([]byte, 128+newMathRand().Intn(4*1024))
	header := req.Header
	header.Set("Pass-Hash", c.passHash)
	header.Set("Obfuscation", hex.EncodeToString(garbage))
	// send request and process response
	err = req.Write(conn)
	if err != nil {
		return errors.Wrap(err, "failed to write log out request")
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return errors.Wrap(err, "failed to read response about log out")
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("logout failed with status: %s", resp.Status)
	}
	return nil
}

func (c *Client) shuttingDown() bool {
	return c.inShutdown.Load()
}

// Serve is used to start front server.
func (c *Client) Serve() error {
	// start pre-connection connector
	num := 2 + newMathRand().Intn(4)
	for i := 0; i < num; i++ {
		c.wg.Add(1)
		go c.connector()
	}
	c.logger.Infof("front proxy server listening on %s", c.frontListener.Addr())
	var tempDelay time.Duration
	maxDelay := time.Second
	for {
		conn, err := c.frontListener.Accept()
		if err == nil {
			go c.handleConn(conn)
			continue
		}
		if c.shuttingDown() {
			return nil
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			if tempDelay == 0 {
				tempDelay = 5 * time.Millisecond
			} else {
				tempDelay *= 2
			}
			if tempDelay > maxDelay {
				tempDelay = maxDelay
			}
			c.logger.Warningf("accept error: %s; retrying in %v", err, tempDelay)
			time.Sleep(tempDelay)
			continue
		}
		return err
	}
}

func (c *Client) handleConn(conn net.Conn) {
	var success bool
	defer func() {
		if !success {
			_ = conn.Close()
		}
	}()

	// apply timeout
	_ = conn.SetDeadline(time.Now().Add(c.timeout))

	// peek first byte for switch protocol type
	reader := bufio.NewReader(conn)
	protocol, err := reader.Peek(1)
	if err != nil {
		return
	}
	var tun *tunnel
	switch protocol[0] {
	case version4:
		tun, err = c.serveSOCKS4(conn, reader)
	case version5:
		tun, err = c.serveSOCKS5(conn, reader)
	default:
		tun, err = c.serveHTTPRequest(conn, reader)
	}
	if err != nil {
		// not append error that contain private data to the log file
		errStr := err.Error()
		switch {
		case strings.Contains(errStr, "no such host"):
		default:
			c.logger.Warningf("failed to create tunnel: %s", err)
			return
		}
		lg, _ := newLogger("")
		lg.Warningf("failed to create tunnel: %s", err)
		return
	}

	// clear deadline about timeout
	_ = conn.SetDeadline(time.Time{})

	// process common HTTP request
	if tun == nil {
		success = true
		return
	}

	// start forward connection data
	go func() {
		// not append connection history to the log file
		lg, _ := newLogger("")
		lg.Infof(
			"{%s} <%s> connect %s (%dms)", tun.Protocol, tun.IPType, tun.Address,
			tun.Elapsed.Milliseconds(),
		)

		var (
			numSend int64
			numRecv int64
		)
		wg := sync.WaitGroup{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { _ = conn.Close() }()
			buffer := make([]byte, c.bufferSize)
			numRecv, _ = io.CopyBuffer(conn, tun, buffer)
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { _ = tun.Close() }()
			buffer := make([]byte, c.bufferSize)
			numSend, _ = io.CopyBuffer(tun, conn, buffer)
		}()
		wg.Wait()

		lg.Infof(
			"{%s} <%s> disconnect %s (%s/%s)", tun.Protocol, tun.IPType, tun.Address,
			strings.ReplaceAll(humanize.IBytes(uint64(numSend)), "i", ""),
			strings.ReplaceAll(humanize.IBytes(uint64(numRecv)), "i", ""),
		)

		// update status
		c.counterMu.Lock()
		defer c.counterMu.Unlock()
		c.numConns++
		c.numSend += numSend
		c.numRecv += numRecv
	}()
	success = true
}

func (c *Client) connect(protocol, network, address string) (*tunnel, error) {
	now := time.Now()
	// get connection from preconnect
	conn, err := c.getPreConn()
	if err != nil {
		return nil, err
	}
	// check connection type
	addrPort, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse remote address")
	}
	addr := addrPort.Addr()
	var ipType string
	switch {
	case addr.Is4():
		ipType = "IPv4"
	case addr.Is6():
		ipType = "IPv6"
	}
	// apply timeout
	_ = conn.SetDeadline(time.Now().Add(c.timeout))
	// process key exchange
	clientPri := make([]byte, curve25519.ScalarSize)
	_, err = rand.Read(clientPri)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate random data for key exchange")
	}
	clientPub, err := curve25519.X25519(clientPri, curve25519.Basepoint)
	if err != nil {
		return nil, errors.Wrap(err, "failed to x25519 with base point")
	}
	// send connect request
	req, err := http.NewRequestWithContext(c.ctx, http.MethodGet, c.buildURL("connect"), nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create request for connect")
	}
	garbage := make([]byte, 256+newMathRand().Intn(2*1024))
	header := req.Header
	header.Set("Pass-Hash", c.passHash)
	header.Set("Public-Key", hex.EncodeToString(clientPub))
	header.Set("Network", network)
	header.Set("Address", address)
	header.Set("Buffer-Size", strconv.Itoa(c.bufferSize))
	header.Set("Jitter-Level", strconv.Itoa(c.jitLevel))
	header.Set("Obfuscation", hex.EncodeToString(garbage))
	err = req.Write(conn)
	if err != nil {
		return nil, errors.Wrap(err, "failed to send request for connect")
	}
	// process response for get connect error and public key
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read response about connect")
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("invalid response status: %s", resp.Status)
	}
	header = resp.Header
	connectErr := header.Get("Connect-Error")
	if connectErr != "" {
		return nil, errors.New(connectErr)
	}
	serverPub, err := hex.DecodeString(header.Get("Public-Key"))
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode public key")
	}
	sessionKey, err := curve25519.X25519(clientPri, serverPub)
	if err != nil {
		return nil, errors.Wrap(err, "failed to negotiate session key")
	}
	// clear deadline that connector set
	_ = conn.SetDeadline(time.Time{})
	// create crypto tunnel
	tun, err := newClientTunnel(newBufConn(conn, reader), sessionKey, c.jitLevel)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create tunnel")
	}
	// record context data
	tun.Elapsed = time.Since(now)
	tun.Protocol = protocol
	tun.IPType = ipType
	tun.Address = address
	return tun, nil
}

func (c *Client) getPreConn() (net.Conn, error) {
	// try to get connection from preconnect channel
	select {
	case conn := <-c.connCh:
		return conn, nil
	case <-c.ctx.Done():
		return nil, c.ctx.Err()
	default:
	}
	// if channel is empty(A large number of connections
	// were used in a short period of time), connect at once
	return c.preconnect()
}

func (c *Client) generator() {
	defer func() {
		if r := recover(); r != nil {
			c.logger.Fatal("generator", r)
		}
		c.wg.Done()
	}()
	rd := newMathRand()
	buf := make([]byte, 32)
	hash := sha256.New()
	for {
		rd.Read(buf)
		hash.Reset()
		hash.Write(buf)
		hash.Write(c.secret)
		if !isCovertDigest(hash.Sum(nil)) {
			continue
		}
		random := bytes.Clone(buf)

		select {
		case c.randCh <- random:
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *Client) connector() {
	defer func() {
		if r := recover(); r != nil {
			c.logger.Fatal("connector", r)
		}
		c.wg.Done()
	}()
	if c.preConns == 0 {
		return
	}
	mRand := newMathRand()
	for {
		// check client is closed
		select {
		case <-c.ctx.Done():
			return
		default:
		}
		// wait random time
		var delay time.Duration
		switch mRand.Intn(10) {
		case 0, 1, 2:
			delay = 0 * time.Second
		case 3, 4:
			delay = time.Duration(20+mRand.Intn(300)) * time.Millisecond
		case 5, 6:
			delay = time.Duration(80+mRand.Intn(900)) * time.Millisecond
		default:
			delay = time.Duration(10+mRand.Intn(250)) * time.Millisecond
		}
		// preconnect
		select {
		case <-time.After(delay):
			if len(c.connCh) == c.preConns {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			conn, err := c.preconnect()
			if err != nil {
				c.logger.Warning("failed to preconnect:", err)
				continue
			}
			select {
			case c.connCh <- conn:
			case <-c.ctx.Done():
				_ = conn.Close()
				return
			}
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *Client) dial() (net.Conn, error) {
	dialer := c.buildDialer()
	conn, err := dialer.DialContext(c.ctx, c.serverNet, c.serverAddr)
	if err != nil {
		return nil, errors.Wrap(err, "failed to connect to server")
	}
	colonPos := strings.LastIndex(c.serverAddr, ":")
	if colonPos == -1 {
		colonPos = len(c.serverAddr)
	}
	serverName := c.serverAddr[:colonPos]
	tlsConfig := &utls.Config{
		ServerName: serverName,
		RootCAs:    c.tlsConfig.RootCAs,
		NextProtos: tlsNextProtos,
	}
	uc := utls.UClient(conn, tlsConfig, utls.HelloFirefox_Auto)
	err = uc.BuildHandshakeState()
	if err != nil {
		return nil, err
	}
	err = uc.SetClientRandom(<-c.randCh)
	if err != nil {
		return nil, err
	}
	err = uc.Handshake()
	if err != nil {
		return nil, err
	}
	if uc.ConnectionState().NegotiatedProtocol != "h2" {
		return nil, errors.New("invalid negotiated protocol")
	}
	return uc, nil
}

func (c *Client) buildDialer() *net.Dialer {
	if runtime.GOOS != "android" {
		return new(net.Dialer)
	}
	dialer := net.Dialer{
		Timeout: 3 * time.Second,
	}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, c.dnsServer)
		},
	}
	return &net.Dialer{Resolver: resolver, Timeout: c.timeout}
}

func (c *Client) preconnect() (net.Conn, error) {
	conn, err := c.dial()
	if err != nil {
		return nil, err
	}
	var success bool
	defer func() {
		if !success {
			_ = conn.Close()
		}
	}()
	// apply timeout
	_ = conn.SetDeadline(time.Now().Add(c.timeout))
	req, err := http.NewRequestWithContext(c.ctx, http.MethodGet, c.buildURL("ping"), nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create request for preconnect")
	}
	garbage := make([]byte, 512+newMathRand().Intn(2*1024))
	header := req.Header
	header.Set("Pass-Hash", c.passHash)
	header.Set("Obfuscation", hex.EncodeToString(garbage))
	err = req.Write(conn)
	if err != nil {
		return nil, errors.Wrap(err, "failed to send request for preconnect")
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read response about preconnect")
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("invalid response status: %s", resp.Status)
	}
	if resp.Header.Get("Pong") != "Ping-Pong" {
		return nil, errors.New("invalid server response about ping")
	}
	// reset deadline
	_ = conn.SetDeadline(time.Time{})
	success = true
	return conn, nil
}

// Close is used to close front server.
func (c *Client) Close() error {
	c.inShutdown.Store(true)
	c.logger.Infof(
		"total connection: %d, total traffic: (%s/%s)", c.numConns,
		strings.ReplaceAll(humanize.IBytes(uint64(c.numSend)), "i", ""),
		strings.ReplaceAll(humanize.IBytes(uint64(c.numRecv)), "i", ""),
	)
	c.logger.Info("close connectors")
	c.cancel()
	c.wg.Wait()
	var err error
	if c.frontListener != nil {
		err = c.frontListener.Close()
		if err != nil {
			err = errors.Wrap(err, "failed to close front listener")
		}
	}
	c.logger.Info("client is closed")
	_ = c.logger.Close()
	return err
}
