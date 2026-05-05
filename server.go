package msocks

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/For-ACGN/autocert"
	"github.com/pkg/errors"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/net/http2"
	"golang.org/x/net/netutil"
)

// TLS mode about how to configure the certificate source.
const (
	TLSModeACME   = "acme"
	TLSModeStatic = "static"
)

const (
	defaultMaxConns      = 10000
	defaultServerTimeout = 2 * time.Minute
)

// Server is a SOCKS-over-HTTPS server.
type Server struct {
	logger *logger

	passHash   string
	timeout    time.Duration
	maxBufSize int

	acl *autocert.Listener
	cfg *tls.Config
	dir string
	hfs http.Handler

	listener net.Listener

	http1 *http.Server
	http2 *http.Server

	inShutdown atomic.Bool
}

// NewServer is used to create a SoH server.
func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	logger, err := newLogger(config.Common.LogPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open log file")
	}
	passHash := config.Common.PassHash
	if passHash == "" {
		return nil, errors.New("password hash is empty")
	}
	if len(passHash) != 64 {
		return nil, errors.New("invalid password hash length")
	}
	phBin, err := hex.DecodeString(passHash)
	if err != nil {
		return nil, errors.Wrap(err, "invalid password hash format")
	}
	pathHash := passHash[:8] + passHash[32:32+8]
	timeout := time.Duration(config.HTTP.Timeout)
	if timeout < time.Second {
		timeout = defaultServerTimeout
	}
	maxConns := config.HTTP.MaxConns
	if maxConns < 1 {
		maxConns = defaultMaxConns
	}
	maxBufSize := config.Tunnel.MaxBufferSize
	if maxBufSize < 1 {
		maxBufSize = defaultMaxBufferSize
	}
	webDir := config.Web.Directory
	if !isDir(webDir) {
		return nil, errors.New("invalid web directory")
	}
	network := config.HTTP.Network
	address := config.HTTP.Address
	listener, err := net.Listen(network, address)
	if err != nil {
		return nil, errors.Wrap(err, "failed to listen for http server")
	}
	// apply maximum connections
	listener = netutil.LimitListener(listener, maxConns)
	var (
		acl *autocert.Listener
		cfg *tls.Config
	)
	switch config.TLS.Mode {
	case TLSModeACME:
		ac := autocert.Config{
			Domains:   config.TLS.ACME.Domains,
			ForceHTTP: true,
		}
		acl, err = autocert.NewListener(ctx, listener, &ac)
		if err != nil {
			return nil, err
		}
		cfg = &tls.Config{
			GetCertificate: acl.GetCertificate,
		}
	case TLSModeStatic:
		kp := config.TLS.Static
		cert, err := tls.LoadX509KeyPair(kp.Cert, kp.Key)
		if err != nil {
			return nil, errors.Wrap(err, "failed to load TLS certificate and key")
		}
		cfg = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
	default:
		return nil, fmt.Errorf("unknown TLS mode: %s", config.TLS.Mode)
	}
	listener = newUTLSListener(listener, cfg, phBin)
	// create http servers
	server := Server{
		logger: logger,

		passHash:   passHash,
		timeout:    timeout,
		maxBufSize: maxBufSize,

		acl: acl,
		cfg: cfg,
		dir: webDir,
		hfs: http.FileServer(http.Dir(webDir)),

		listener: listener,
	}
	serverMux := http.NewServeMux()
	serverMux.HandleFunc("/", server.handleIndex)
	serverMux.HandleFunc(fmt.Sprintf("/%s/login", pathHash), server.handleLogin)
	serverMux.HandleFunc(fmt.Sprintf("/%s/logout", pathHash), server.handleLogout)
	serverMux.HandleFunc(fmt.Sprintf("/%s/ping", pathHash), server.handlePing)
	serverMux.HandleFunc(fmt.Sprintf("/%s/connect", pathHash), server.handleConnect)
	// explicitly enable HTTP/1.1 only for covert usage
	h1Server := &http.Server{
		Handler:           serverMux,
		ReadHeaderTimeout: timeout,
		IdleTimeout:       timeout,
	}
	h1Server.Protocols = new(http.Protocols)
	h1Server.Protocols.SetHTTP1(true)
	h1Server.Protocols.SetHTTP2(false)
	h1Server.Protocols.SetUnencryptedHTTP2(false)
	// explicitly enable HTTP/1.1 and HTTP/2 for common usage
	h2Server := &http.Server{
		Handler:           serverMux,
		ReadHeaderTimeout: timeout,
		IdleTimeout:       timeout,
	}
	h2Server.Protocols = new(http.Protocols)
	h2Server.Protocols.SetHTTP1(true)
	h2Server.Protocols.SetHTTP2(true)
	h2Server.Protocols.SetUnencryptedHTTP2(false)
	server.http1 = h1Server
	server.http2 = h2Server
	return &server, nil
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	s.handleFile(w, r)
	// print income request
	buf := bytes.NewBuffer(make([]byte, 0, 512))
	_, _ = fmt.Fprintf(buf, "Remote: %s\n", r.RemoteAddr)                  // client ip
	_, _ = fmt.Fprintf(buf, "%s %s %s\n", r.Method, r.RequestURI, r.Proto) // header line
	_, _ = fmt.Fprintf(buf, "Host: %s", r.Host)                            // dump host
	// dump other header
	for k, v := range r.Header {
		_, _ = fmt.Fprintf(buf, "\n%s: %s", k, v[0])
	}
	buf.WriteString("\n")
	// print post body if exists
	if r.ContentLength != 0 {
		_, _ = io.CopyN(buf, r.Body, 32*1024)
		buf.WriteString("\n")
	}
	s.logger.Info(buf)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Pass-Hash") != s.passHash {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	garbage := make([]byte, 128+newMathRand().Intn(8*1024))
	w.Header().Set("Obfuscation", hex.EncodeToString(garbage))
	w.WriteHeader(http.StatusOK)
	s.logger.Infof("user from %s is login", r.RemoteAddr)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Pass-Hash") != s.passHash {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	garbage := make([]byte, 128+newMathRand().Intn(8*1024))
	w.Header().Set("Obfuscation", hex.EncodeToString(garbage))
	w.WriteHeader(http.StatusOK)
	s.logger.Infof("user from %s is logout", r.RemoteAddr)
}

func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Pass-Hash") != s.passHash {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	garbage := make([]byte, 512+newMathRand().Intn(32*1024))
	header := w.Header()
	header.Set("Obfuscation", hex.EncodeToString(garbage))
	header.Set("Pong", "Ping-Pong")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Pass-Hash") != s.passHash {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// try to hijack connection
	var success bool
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		s.logger.Errorf("connection from %s can not be hijacked", r.RemoteAddr)
		return
	}
	conn, _, err := hijacker.Hijack()
	if err != nil {
		s.logger.Error("failed to hijack connection from", r.RemoteAddr)
		return
	}
	defer func() {
		if !success {
			_ = conn.Close()
		}
	}()

	// reset deadline that server set
	_ = conn.SetDeadline(time.Now().Add(s.timeout))

	// negotiate session key
	sessionKey, serverPub, err := s.negotiate(r)
	if err != nil {
		return
	}
	header := make(http.Header)
	header.Set("Public-Key", hex.EncodeToString(serverPub))

	// append garbage data
	garbage := make([]byte, 256+newMathRand().Intn(16*1024))
	header.Set("Obfuscation", hex.EncodeToString(garbage))

	// process argument about tunnel
	bufferSize, err := strconv.Atoi(r.Header.Get("Buffer-Size"))
	if err != nil {
		s.logger.Errorf("invalid buffer size from %s: %s", r.RemoteAddr, err)
		return
	}
	if bufferSize > s.maxBufSize {
		bufferSize = s.maxBufSize
	}
	jitterLevel, err := strconv.Atoi(r.Header.Get("Jitter-Level"))
	if err != nil {
		s.logger.Errorf("invalid jitter level from %s: %s", r.RemoteAddr, err)
		return
	}

	// try to connect target
	var connectOK bool
	network := r.Header.Get("Network")
	address := r.Header.Get("Address")
	target, err := net.Dial(network, address) // #nosec G704
	if err != nil {
		header.Set("Connect-Error", err.Error())
	} else {
		defer func() {
			if !success {
				_ = target.Close()
			}
		}()
		connectOK = true
	}

	// write response
	resp := http.Response{}
	resp.StatusCode = http.StatusOK
	resp.Proto = "HTTP/1.1"
	resp.ProtoMajor = 1
	resp.ProtoMinor = 1
	resp.Header = header
	err = resp.Write(conn)
	if err != nil {
		s.logger.Errorf("failed to write response to %s: %s", r.RemoteAddr, err)
		return
	}
	if !connectOK {
		return
	}

	// clear deadline that server set
	_ = conn.SetDeadline(time.Time{})

	// start forward connection data
	tun, err := newServerTunnel(conn, sessionKey, jitterLevel)
	if err != nil {
		s.logger.Error("failed to create tunnel:", err)
		return
	}
	go func() {
		defer func() { _ = target.Close() }()
		buffer := make([]byte, bufferSize)
		_, _ = io.CopyBuffer(target, tun, buffer)
	}()
	go func() {
		defer func() { _ = tun.Close() }()
		buffer := make([]byte, bufferSize)
		_, _ = io.CopyBuffer(tun, target, buffer)
	}()
	success = true
}

func (s *Server) negotiate(r *http.Request) ([]byte, []byte, error) {
	// get public key from client
	clientPub, err := hex.DecodeString(r.Header.Get("Public-Key"))
	if err != nil {
		s.logger.Error("failed to decode public key from:", r.RemoteAddr)
		return nil, nil, err
	}
	if len(clientPub) != curve25519.ScalarSize {
		s.logger.Error("receive invalid public key from:", r.RemoteAddr)
		return nil, nil, err
	}
	// process key exchange
	serverPri := make([]byte, curve25519.ScalarSize)
	_, err = rand.Read(serverPri)
	if err != nil {
		s.logger.Error("failed to generate random data for key exchange:", err)
		return nil, nil, err
	}
	serverPub, err := curve25519.X25519(serverPri, curve25519.Basepoint)
	if err != nil {
		s.logger.Errorf("failed to x25519 with base point: %s, from: %s", err, r.RemoteAddr)
		return nil, nil, err
	}
	sessionKey, err := curve25519.X25519(serverPri, clientPub)
	if err != nil {
		s.logger.Errorf("failed to negotiate session key: %s, from: %s", err, r.RemoteAddr)
		return nil, nil, err
	}
	return sessionKey, serverPub, nil
}

func (s *Server) shuttingDown() bool {
	return s.inShutdown.Load()
}

// Serve is used to start http server.
func (s *Server) Serve() error {
	s.logger.Infof("server listening on %s", s.listener.Addr())
	var tempDelay time.Duration
	maxDelay := time.Second
	for {
		conn, err := s.listener.Accept()
		if err == nil {
			go s.handleConn(conn)
			continue
		}
		if s.shuttingDown() {
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
			s.logger.Warningf("http: Accept error: %s; retrying in %v", err, tempDelay)
			time.Sleep(tempDelay)
			continue
		}
		return err
	}
}

func (s *Server) handleConn(conn net.Conn) {
	uConn := conn.(*utlsConn)
	err := uConn.Handshake()
	if err != nil {
		s.logger.Warningf("failed to handshake from %s: %s", uConn.RemoteAddr(), err)
		return
	}
	ol := newOnceListener(uConn)
	if uConn.covert {
		_ = s.http1.Serve(ol)
		return
	}
	proto := uConn.ConnectionState().NegotiatedProtocol
	if proto == "h2" {
		srv := http2.Server{}
		opts := http2.ServeConnOpts{
			BaseConfig: s.http2,
		}
		srv.ServeConn(uConn, &opts)
		return
	}
	_ = s.http2.Serve(ol)
}

// Close is used to close http server.
func (s *Server) Close() error {
	s.inShutdown.Store(true)
	if s.acl != nil {
		_ = s.acl.Close()
	} else {
		_ = s.listener.Close()
	}
	_ = s.http1.Close()
	_ = s.http2.Close()
	s.logger.Info("server is closed")
	_ = s.logger.Close()
	return nil
}
