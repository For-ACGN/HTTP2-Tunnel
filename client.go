package h2tunnel

import (
	"bufio"
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
	defaultClientMaxConns = 4
	defaultClientTimeout  = 15 * time.Second
	minimumClientConns    = 2
)

// Client is a HTTP2-Tunnel client.
type Client struct {
	logger *logger

	hashBin  []byte
	passHash string
	pathHash string
	preface  []byte

	certPin    []string
	timeout    time.Duration
	maxConns   int
	bufferSize int
	jitLevel   int
	dnsServer  string

	// about connect remote server
	serverNet  string
	serverAddr string
	localNet   string
	localAddr  string
	tlsConfig  *utls.Config

	// about front proxy server
	proxyListener net.Listener
	proxyUsername string
	proxyPassword string

	portmappers []*portmapper

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

type portmapper struct {
	listener net.Listener
	network  string
	address  string
}

// NewClient is used to create a HTTP2-Tunnel client.
func NewClient(config *ClientConfig) (*Client, error) {
	logger, err := newLogger(config.Common.LogPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open log file")
	}
	h := sha256.Sum256([]byte(config.Common.Password))
	hashBin := h[:]
	passHash := hex.EncodeToString(hashBin)
	pathHash := passHash[:8] + passHash[32:32+8]
	preface := hashBin[:http2PrefaceSize]
	timeout := time.Duration(config.Client.Timeout)
	if timeout < time.Second {
		timeout = defaultClientTimeout
	}
	maxConns := config.Tunnel.MaxConns
	if maxConns < minimumClientConns {
		maxConns = defaultClientMaxConns
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
	// prepare certificate pinning
	certPin, err := prepareCertPinning(config.Client.CertPin)
	if err != nil {
		return nil, err
	}
	certPool, err := prepareRootCA(config.Client.RootCA)
	if err != nil {
		return nil, err
	}
	// prepare tls config for client
	tlsConfig := &utls.Config{
		RootCAs:            certPool,
		NextProtos:         tlsNextProtos,
		ClientSessionCache: utls.NewLRUClientSessionCache(64),
		OmitEmptyPsk:       true,
	}
	// prepare the front proxy listener
	var proxy net.Listener
	if config.Proxy.Enabled {
		proxy, err = net.Listen(config.Proxy.Network, config.Proxy.Address)
		if err != nil {
			return nil, errors.Wrap(err, "failed to listen for the front proxy")
		}
	}
	// prepare the portmapper listeners
	var portmappers []*portmapper
	for _, portmap := range config.Portmaps {
		if !portmap.Enabled {
			continue
		}
		listener, err := net.Listen(portmap.LocalNetwork, portmap.LocalAddress)
		if err != nil {
			return nil, errors.Wrap(err, "failed to listen for the portmap")
		}
		portmappers = append(portmappers, &portmapper{
			listener: listener,
			network:  portmap.RemoteNetwork,
			address:  portmap.RemoteAddress,
		})
	}
	client := Client{
		logger: logger,

		hashBin:  hashBin,
		passHash: passHash,
		pathHash: pathHash,
		preface:  preface,

		certPin:    certPin,
		timeout:    timeout,
		maxConns:   maxConns,
		bufferSize: bufferSize,
		jitLevel:   jitLevel,
		dnsServer:  config.Android.DNSServer,

		serverNet:  config.Server.RemoteNetwork,
		serverAddr: config.Server.RemoteAddress,
		localNet:   config.Server.LocalNetwork,
		localAddr:  config.Server.LocalAddress,
		tlsConfig:  tlsConfig,

		proxyListener: proxy,
		proxyUsername: config.Proxy.Username,
		proxyPassword: config.Proxy.Password,
		portmappers:   portmappers,

		randCh: make(chan []byte, 4*maxConns),
		connCh: make(chan net.Conn, maxConns),
	}
	client.ctx, client.cancel = context.WithCancel(context.Background())
	return &client, nil
}

func prepareCertPinning(list []string) ([]string, error) {
	var certPin []string
	for _, pin := range list {
		b, err := hex.DecodeString(pin)
		if err != nil {
			return nil, errors.Wrap(err, "invalid server certificate pin")
		}
		if len(b) != sha256.Size {
			return nil, errors.New("invalid server certificate pin format")
		}
		certPin = append(certPin, hex.EncodeToString(b))
	}
	return certPin, nil
}

func prepareRootCA(pem string) (*x509.CertPool, error) {
	if pem == "" {
		return nil, nil
	}
	certs, err := parseCertificatesPEM([]byte(pem))
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse Root CA certificates")
	}
	certPool := x509.NewCertPool()
	for _, cert := range certs {
		certPool.AddCert(cert)
	}
	return certPool, nil
}

func (c *Client) buildURL(path string) string {
	return fmt.Sprintf("https://%s/%s/%s", c.serverAddr, c.pathHash, path)
}

func (c *Client) shuttingDown() bool {
	return c.inShutdown.Load()
}

// Detect is used to detect the server has been hijacked.
func (c *Client) Detect() (bool, error) {
	conn, hijacked, err := c.dial(true)
	if err != nil && !hijacked {
		return false, errors.Wrap(err, "failed to connect to server")
	}
	if hijacked {
		return true, err
	}
	// send to the pre-connection channel even if it is disabled
	return false, c.putConn(conn)
}

// Login is used to log in to server.
func (c *Client) Login() error {
	conn, hijacked, err := c.dial(false)
	if err != nil && !hijacked {
		return errors.Wrap(err, "failed to connect to server")
	}
	if hijacked {
		return errors.Errorf("[!] detect attacker [!] - %s", err)
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
	garbage := make([]byte, 128+newMathRand().Intn(256))
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
	// send to the pre-connection channel even if it is disabled
	err = c.putConn(conn)
	if err != nil {
		return err
	}
	success = true
	return nil
}

// Logout is used to log out to server.
func (c *Client) Logout() error {
	conn, err := c.getConn()
	if err != nil {
		return errors.Wrap(err, "failed to connect to server")
	}
	defer func() { _ = conn.Close() }()
	// build request about logout
	req, err := http.NewRequestWithContext(c.ctx, http.MethodGet, c.buildURL("logout"), nil)
	if err != nil {
		return errors.Wrap(err, "failed to create request for logout")
	}
	garbage := make([]byte, 128+newMathRand().Intn(256))
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
	return simulateHTTP2GoAway(conn)
}

// Start is used to start background workers.
func (c *Client) Start() {
	// start secret random generator
	c.wg.Add(1)
	go c.generator()
	// start pre-connection connector
	num := 2 + newMathRand().Intn(4)
	for i := 0; i < num; i++ {
		c.wg.Add(1)
		go c.connector()
	}
	// start pre-connection watcher
	for i := 0; i < c.maxConns+2; i++ {
		c.wg.Add(1)
		go c.watcher()
	}
}

// Serve is used to start front proxy server and portmaps.
func (c *Client) Serve() {
	if c.proxyListener != nil {
		go func() {
			err := c.ServeProxy(c.proxyListener)
			if err != nil {
				c.logger.Error("failed to serve proxy:", err)
			}
		}()
	}
	for i := 0; i < len(c.portmappers); i++ {
		pm := c.portmappers[i]
		go func() {
			err := c.ServePortmap(pm.listener, pm.network, pm.address)
			if err != nil {
				c.logger.Error("failed to serve portmap:", err)
			}
		}()
	}
}

// ServeProxy is used to serve a listener for handle front proxy connection.
func (c *Client) ServeProxy(listener net.Listener) error {
	c.logger.Infof("front proxy server listening on %s", listener.Addr())
	var tempDelay time.Duration
	maxDelay := time.Second
	for {
		conn, err := listener.Accept()
		if err == nil {
			go c.handleProxyConn(conn)
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

func (c *Client) handleProxyConn(conn net.Conn) {
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
	c.forward(conn, tun)
	success = true
}

func (c *Client) ServePortmap(listener net.Listener, network, address string) error {
	c.logger.Infof("portmap server listening on %s", listener.Addr())
	var tempDelay time.Duration
	maxDelay := time.Second
	for {
		conn, err := listener.Accept()
		if err == nil {
			go c.handlePortmapConn(conn, network, address)
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

func (c *Client) handlePortmapConn(conn net.Conn, network, address string) {
	var success bool
	defer func() {
		if !success {
			_ = conn.Close()
		}
	}()

	tun, err := c.connect(c.ctx, "Portmap", network, address)
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
	c.forward(conn, tun)
	success = true
}

func (c *Client) forward(conn net.Conn, tun *tunnel) {
	// not append connection history to the log file
	logger, _ := newLogger("")
	logger.Infof(
		"{%s} <%s> [%dms] connect %s",
		tun.Protocol, tun.IPType, tun.Elapsed.Milliseconds(), tun.Address,
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

	logger.Infof(
		"{%s} <%s> disconnect %s (%s/%s) [%s]",
		tun.Protocol, tun.IPType, tun.Address,
		strings.ReplaceAll(humanize.IBytes(uint64(numSend)), "i", ""), // #nosec G115
		strings.ReplaceAll(humanize.IBytes(uint64(numRecv)), "i", ""), // #nosec G115
		formatDuration(time.Since(tun.Establish)),
	)

	// update status
	c.counterMu.Lock()
	defer c.counterMu.Unlock()
	c.numConns++
	c.numSend += numSend
	c.numRecv += numRecv
}

func formatDuration(d time.Duration) string {
	var s string
	switch {
	case d < time.Second:
		m := d.Milliseconds()
		if m > 0 {
			s = fmt.Sprintf("%dms", m)
		} else {
			s = "0s"
		}
	case d < time.Minute:
		s = fmt.Sprintf("%.1fs", float64(d)/float64(time.Second))
	default:
		s = fmt.Sprintf("%.1fm", float64(d)/float64(time.Minute))
	}
	return strings.ReplaceAll(s, ".0", "")
}

// Connect is used to connect target though the tunnel.
func (c *Client) Connect(ctx context.Context, network, address string) (net.Conn, error) {
	tun, err := c.connect(ctx, "Direct", network, address)
	if err != nil {
		// not append error that contain private data to the log file
		errStr := err.Error()
		switch {
		case strings.Contains(errStr, "no such host"):
		default:
			c.logger.Warningf("failed to create tunnel: %s", err)
			return nil, err
		}
		lg, _ := newLogger("")
		lg.Warningf("failed to create tunnel: %s", err)
		return nil, err
	}
	// not append connection history to the log file
	lg, _ := newLogger("")
	lg.Infof(
		"{%s} <%s> [%dms] connect %s",
		tun.Protocol, tun.IPType, tun.Elapsed.Milliseconds(), tun.Address,
	)
	return tun, nil
}

func (c *Client) connect(ctx context.Context, protocol, network, address string) (*tunnel, error) {
	now := time.Now()
	// get connection from preconnect
	conn, err := c.getConn()
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.buildURL("connect"), nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create request for connect")
	}
	garbage := make([]byte, 128+newMathRand().Intn(512))
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
	tun.Protocol = protocol
	tun.IPType = ipType
	tun.Address = address
	tun.Elapsed = time.Since(now)
	tun.Establish = time.Now()
	return tun, nil
}

// Close is used to close http2-tunnel client.
func (c *Client) Close() error {
	c.inShutdown.Store(true)
	c.cancel()
	c.wg.Wait()
	var err error
	if c.proxyListener != nil {
		c.logger.Info("close front proxy server")
		err = c.proxyListener.Close()
		if err != nil {
			err = errors.Wrap(err, "failed to close front proxy listener")
		}
	}
	if len(c.portmappers) > 0 {
		c.logger.Info("close portmappers")
		for _, pm := range c.portmappers {
			err = pm.listener.Close()
			if err != nil {
				err = errors.Wrap(err, "failed to close portmapper")
			}
		}
	}
	if len(c.connCh) > 0 {
		c.logger.Info("close pre-connections")
		for i := 0; i < len(c.connCh); i++ {
			select {
			case conn := <-c.connCh:
				_ = conn.Close()
			default:
			}
		}
	}
	c.logger.Infof(
		"total connection: %d, total traffic: (%s/%s)", c.numConns,
		strings.ReplaceAll(humanize.IBytes(uint64(c.numSend)), "i", ""), // #nosec G115
		strings.ReplaceAll(humanize.IBytes(uint64(c.numRecv)), "i", ""), // #nosec G115
	)
	c.logger.Info("http2-tunnel client is closed")
	_ = c.logger.Close()
	return err
}
