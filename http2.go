package msocks

import (
	"net"
)

type http2Listener struct {
	net.Listener
}

func newHTTP2Listener(listener net.Listener) *http2Listener {
	return &http2Listener{Listener: listener}
}

func (hl *http2Listener) Accept() (net.Conn, error) {
	conn, err := hl.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &http2Conn{Conn: conn}, nil
}

type http2Conn struct {
	net.Conn
}
