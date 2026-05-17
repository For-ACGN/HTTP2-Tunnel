package h2tunnel

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"net"
	"sync"

	"github.com/For-ACGN/htls"
	"github.com/pkg/errors"
)

var tlsNextProtos = []string{"h2", "http/1.1"}

type htlsListener struct {
	net.Listener

	config *htls.Config
	secret []byte
}

func newHTLSListener(listener net.Listener, config *tls.Config, secret []byte) *htlsListener {
	cfg := &htls.Config{
		NextProtos: tlsNextProtos,
		CurvePreferences: []htls.CurveID{
			htls.X25519,
			htls.CurveP256, htls.CurveP384, htls.CurveP521,
		},
	}
	// prepare the session tick key
	var stk [32]byte
	_, err := rand.Read(stk[:])
	if err != nil {
		panic(fmt.Sprintf("failed to generate session ticket key: %s", err))
	}
	cfg.SetSessionTicketKeys([][32]byte{stk})
	// prepare the methods about provide certificate
	if config.GetCertificate != nil {
		wrapper := func(hello *htls.ClientHelloInfo) (*htls.Certificate, error) {
			h := &tls.ClientHelloInfo{
				ServerName:   hello.ServerName,
				CipherSuites: hello.CipherSuites,
			}
			cert, err := config.GetCertificate(h)
			if err == nil {
				return htls.ToHTLSCertificate(cert), nil
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
			return htls.ToHTLSCertificate(cert), nil
		}
		cfg.GetCertificate = wrapper
	}
	if len(config.Certificates) > 0 {
		cert := *htls.ToHTLSCertificate(&config.Certificates[0])
		cfg.Certificates = []htls.Certificate{cert}
	}
	ul := htlsListener{
		Listener: listener,
		config:   cfg,
		secret:   secret,
	}
	return &ul
}

func (ul *htlsListener) Accept() (net.Conn, error) {
	conn, err := ul.Listener.Accept()
	if err != nil {
		return nil, err
	}
	uc := &htlsConn{}
	cfg := ul.config.Clone()
	cfg.OnClientHelloMessage = func(hello *htls.ClientHelloMessage) error {
		h := sha256.New()
		h.Write(hello.Random)
		h.Write(ul.secret)
		if isCovertDigest(h.Sum(nil)) {
			uc.covert = true
		}
		return nil
	}
	uc.Conn = htls.Server(conn, cfg)
	return uc, nil
}

type htlsConn struct {
	*htls.Conn

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
