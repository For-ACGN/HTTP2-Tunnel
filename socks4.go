package h2tunnel

import (
	"bufio"
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"io"
	"net"
	"strconv"

	"github.com/pkg/errors"
)

// reference:
//   http://ftp.icm.edu.pl/packages/socks/socks4/SOCKS4.protocol
//   http://www.openssh.com/txt/socks4a.protocol

const (
	version4    = 0x04
	v4Connect   = 0x01
	v4Succeeded = 0x5A
	v4Refused   = 0x5B
	v4InvalidID = 0x5D
)

var (
	v4ReplySucceeded = []byte{0x00, v4Succeeded, 0, 0, 0, 0, 0, 0}
	v4ReplyRefused   = []byte{0x00, v4Refused, 0, 0, 0, 0, 0, 0}
	v4ReplyInvalidID = []byte{0x00, v4InvalidID, 0, 0, 0, 0, 0, 0}
)

func (c *Client) serveSOCKS4(conn net.Conn, reader *bufio.Reader) (*tunnel, error) {
	// 10 = version(1) + cmd(1) + port(2) + address(4) + 2 x NULL(2) maybe
	// 16 = domain name
	buf := make([]byte, 10+16) // prepare
	_, err := io.ReadFull(reader, buf[:8])
	if err != nil {
		return nil, errors.Wrap(err, "failed to read socks4 request")
	}
	// check version
	if buf[0] != version4 {
		return nil, errors.New("unexpected socks4 version")
	}
	// check command
	if buf[1] != v4Connect {
		return nil, errors.Errorf("unknown command: %d", buf[1])
	}
	if !c.socks4CheckUserID(reader) {
		_, _ = conn.Write(v4ReplyInvalidID)
		return nil, errors.New("failed to check user id")
	}
	// process connect target
	port := binary.BigEndian.Uint16(buf[2:4])
	var (
		domain bool
		ip     bool
		host   string
		proto  string
	)
	// check is domain, 0.0.0.x is domain mode
	if bytes.Equal(buf[4:7], []byte{0x00, 0x00, 0x00}) && buf[7] != 0x00 {
		domain = true
		proto = "SOCKS4a"
	} else {
		ip = true
		proto = "SOCKS4"
	}
	if ip {
		host = net.IPv4(buf[4], buf[5], buf[6], buf[7]).String()
	}
	// read domain
	if domain {
		var domainName []byte
		for {
			b, err := reader.ReadByte()
			if err != nil {
				return nil, errors.Wrap(err, "failed to read domain name")
			}
			// find 0x00(end)
			if b == 0x00 {
				break
			}
			domainName = append(domainName, b)
		}
		host = string(domainName)
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))
	// connect target
	tun, err := c.connect(c.ctx, proto, "tcp", target)
	if err != nil {
		_, _ = conn.Write(v4ReplyRefused)
		return nil, errors.Wrap(err, "failed to connect target")
	}
	// write reply
	_, err = conn.Write(v4ReplySucceeded)
	if err != nil {
		_ = tun.Close()
		return nil, errors.Wrap(err, "failed to write reply")
	}
	return tun, nil
}

func (c *Client) socks4CheckUserID(reader *bufio.Reader) bool {
	var userID []byte
	for {
		b, err := reader.ReadByte()
		if err != nil {
			c.logger.Error("failed to read user id:", err)
			return false
		}
		// find 0x00(end)
		if b == 0x00 {
			break
		}
		userID = append(userID, b)
	}
	// compare user id
	if c.proxyUsername == "" {
		return true
	}
	uid := []byte(c.proxyUsername)
	if subtle.ConstantTimeCompare(uid, userID) != 1 {
		c.logger.Errorf("invalid user id: %s", userID)
		return false
	}
	return true
}
