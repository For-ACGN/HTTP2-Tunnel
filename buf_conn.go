package h2tunnel

import (
	"bufio"
	"net"
)

type bufConn struct {
	net.Conn

	reader *bufio.Reader
}

func newBufConn(conn net.Conn, reader *bufio.Reader) *bufConn {
	return &bufConn{
		Conn:   conn,
		reader: reader,
	}
}

func (c *bufConn) Read(b []byte) (int, error) {
	buffered := c.reader.Buffered()
	if buffered > 0 {
		return c.reader.Read(b)
	}
	return c.Conn.Read(b)
}
