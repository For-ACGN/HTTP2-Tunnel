package msocks

import (
	"crypto/sha256"
	"crypto/tls"
	"net"
	"sync"

	"github.com/For-ACGN/utls"
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
			if err != nil {
				return nil, err
			}
			return utls.ToUTLSCertificate(cert), nil
		}
		cfg.GetCertificate = wrapper
	}
	if len(config.Certificates) > 0 {
		cfg.Certificates[0] = *utls.ToUTLSCertificate(&config.Certificates[0])
	}
	cfg.NextProtos = tlsNextProtos
	return &utlsListener{
		Listener: listener,
		config:   cfg,
		secret:   secret,
	}
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

	rmu sync.Mutex
	wmu sync.Mutex
}

func (uc *utlsConn) Read(b []byte) (int, error) {
	err := uc.Conn.Handshake()
	if err != nil {
		return 0, err
	}
	uc.rmu.Lock()
	defer uc.rmu.Unlock()
	if uc.covert {
		// TODO simulate http2 behavior
		uc.covert = false
	}
	return uc.Conn.Read(b)
}

func (uc *utlsConn) Write(b []byte) (int, error) {
	err := uc.Conn.Handshake()
	if err != nil {
		return 0, err
	}
	uc.wmu.Lock()
	defer uc.wmu.Unlock()
	if uc.covert {
		// TODO simulate http2 behavior
		uc.covert = false
	}
	return uc.Conn.Write(b)
}

// check the first 18 bit are all zero.
func isCovertDigest(digest []byte) bool {
	return digest[0] == 0x00 && digest[1] == 0x00 && digest[2]>>6 == 0x00
}
