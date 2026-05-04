package msocks

import (
	"crypto/tls"
	"net"

	"github.com/For-ACGN/utls"
)

var tlsNextProtos = []string{"h2", "http/1.1"}

type utlsListener struct {
	listener net.Listener

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
		listener: listener,
		config:   cfg,
		secret:   secret,
	}
}

func (ul *utlsListener) Accept() (net.Conn, error) {
	conn, err := ul.listener.Accept()
	if err != nil {
		return nil, err
	}
	return &utlsConn{Conn: conn}, nil
}

type utlsConn struct {
	net.Conn
}
