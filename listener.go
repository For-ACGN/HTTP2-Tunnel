package msocks

import (
	"crypto/sha256"
	"crypto/tls"
	"net"
	"sync"

	"github.com/For-ACGN/utls"
	"github.com/pkg/errors"
)

var tlsNextProtos = []string{"h2", "http/1.1"}

type utlsListener struct {
	net.Listener

	config *utls.Config
	secret []byte
}

func newUTLSListener(listener net.Listener, config *tls.Config, secret []byte) *utlsListener {
	cfg := &utls.Config{}
	if config.GetCertificate != nil {
		wrapper := func(hello *utls.ClientHelloInfo) (*utls.Certificate, error) {
			h := &tls.ClientHelloInfo{
				ServerName:   hello.ServerName,
				CipherSuites: hello.CipherSuites,
			}
			cert, err := config.GetCertificate(h)
			if err == nil {
				return utls.ToUTLSCertificate(cert), nil
			}
			// get the certificate with the first domain name
			// for defense the active detection
			h = &tls.ClientHelloInfo{
				ServerName:   config.ServerName,
				CipherSuites: hello.CipherSuites,
			}
			cert, err = config.GetCertificate(h)
			if err != nil {
				return nil, err
			}
			return utls.ToUTLSCertificate(cert), nil
		}
		cfg.GetCertificate = wrapper
	}
	if len(config.Certificates) > 0 {
		cert := *utls.ToUTLSCertificate(&config.Certificates[0])
		cfg.Certificates = []utls.Certificate{cert}
	}
	cfg.NextProtos = tlsNextProtos
	ul := utlsListener{
		Listener: listener,
		config:   cfg,
		secret:   secret,
	}
	return &ul
}

func (ul *utlsListener) Accept() (net.Conn, error) {
	conn, err := ul.Listener.Accept()
	if err != nil {
		return nil, err
	}
	uc := &utlsConn{}
	cfg := ul.config.Clone()
	cfg.OnClientHelloMessage = func(hello *utls.ClientHelloMessage) error {
		h := sha256.New()
		h.Write(hello.Random)
		h.Write(ul.secret)
		if isCovertDigest(h.Sum(nil)) {
			uc.covert = true
		}
		return nil
	}
	uc.Conn = utls.Server(conn, cfg)
	return uc, nil
}

type utlsConn struct {
	*utls.Conn

	covert bool
}

// for select the http1 or http2 server.
type onceListener struct {
	conn net.Conn
	acc  bool
	mu   sync.Mutex
}

func newOnceListener(conn net.Conn) *onceListener {
	return &onceListener{conn: conn}
}

func (ol *onceListener) Accept() (net.Conn, error) {
	ol.mu.Lock()
	defer ol.mu.Unlock()
	if ol.acc {
		return nil, errors.New("listener is already accepted")
	}
	ol.acc = true
	return ol.conn, nil
}

func (ol *onceListener) Addr() net.Addr {
	return ol.conn.LocalAddr()
}

func (ol *onceListener) Close() error {
	return nil
}

// check the prefix 17 bits are all zero.
func isCovertDigest(digest []byte) bool {
	return digest[0] == 0x00 && digest[1] == 0x00 && digest[2]>>7 == 0x00
}
