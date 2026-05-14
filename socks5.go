package h2tunnel

import (
	"bufio"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/pkg/errors"
)

// reference:
//   https://www.ietf.org/rfc/rfc1928.txt
//   https://www.ietf.org/rfc/rfc1929.txt

const (
	version5 = 0x05

	// authenticate method
	v5NotRequired         = 0x00
	v5UsernamePassword    = 0x02
	v5NoAcceptableMethods = 0xFF

	// authenticate
	v5UsernamePasswordVersion = 0x01
	v5StatusSucceeded         = 0x00
	v5StatusFailed            = 0x01

	v5Reserve   = 0x00
	v5NoReserve = 0x01

	// command
	v5CmdConnect = 0x01

	// address type
	v5AddrTypeIPv4 = 0x01
	v5AddrTypeFQDN = 0x03
	v5AddrTypeIPv6 = 0x04

	// reply
	v5Succeeded      = 0x00
	v5ConnRefused    = 0x05
	v5CmdNotSupport  = 0x07
	v5AddrNotSupport = 0x08
)

var (
	v5ReplySucceeded      = []byte{version5, v5Succeeded, v5Reserve, v5AddrTypeIPv4, 0, 0, 0, 0, 0, 0}
	v5ReplyConnectRefused = []byte{version5, v5ConnRefused, v5Reserve, v5AddrTypeIPv4, 0, 0, 0, 0, 0, 0}
	v5ReplyAddrNotSupport = []byte{version5, v5AddrNotSupport, v5Reserve, v5AddrTypeIPv4, 0, 0, 0, 0, 0, 0}
)

func (c *Client) serveSOCKS5(conn net.Conn, reader *bufio.Reader) (*tunnel, error) {
	buf := make([]byte, 1)
	// read socks5 version
	_, err := io.ReadFull(reader, buf)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read socks5 version")
	}
	err = c.socks5NegotiateAuthMethod(conn, reader)
	if err != nil {
		return nil, err
	}
	if !c.socks5Authenticate(conn, reader) {
		return nil, errors.New("failed to authenticate")
	}
	target := c.socks5ReceiveConnectTarget(conn, reader)
	if target == "" {
		return nil, errors.New("failed to receive connect target")
	}
	// connect target
	tun, err := c.connect("SOCKS5", "tcp", target)
	if err != nil {
		_, _ = conn.Write(v5ReplyConnectRefused)
		return nil, errors.Wrap(err, "failed to connect target")
	}
	// write reply
	_, err = conn.Write(v5ReplySucceeded)
	if err != nil {
		_ = tun.Close()
		return nil, errors.Wrap(err, "failed to write reply")
	}
	return tun, nil
}

func (c *Client) socks5NegotiateAuthMethod(conn net.Conn, reader *bufio.Reader) error {
	buf := make([]byte, 4)
	_, err := io.ReadFull(reader, buf[:1])
	if err != nil {
		return errors.Wrap(err, "failed to read the number of the authentication methods")
	}
	l := int(buf[0])
	if l == 0 {
		return errors.Wrap(err, "no authentication method")
	}
	if l > len(buf) {
		buf = make([]byte, l)
	}
	_, err = io.ReadFull(reader, buf[:l])
	if err != nil {
		return errors.Wrap(err, "failed to read authentication methods")
	}
	if c.frontUsername == "" && c.frontPassword == "" {
		if !c.socks5HasAuthMethod(buf[:l], v5NotRequired) {
			_, _ = conn.Write([]byte{version5, v5NoAcceptableMethods})
			return errors.New("no acceptable authentication methods")
		}
	} else {
		if !c.socks5HasAuthMethod(buf[:l], v5UsernamePassword) {
			_, _ = conn.Write([]byte{version5, v5NoAcceptableMethods})
			return errors.New("no acceptable authentication methods")
		}
	}
	return nil
}

func (c *Client) socks5HasAuthMethod(methods []byte, method byte) bool {
	for _, m := range methods {
		if m == method {
			return true
		}
	}
	return false
}

func (c *Client) socks5Authenticate(conn net.Conn, reader *bufio.Reader) bool {
	if c.frontUsername == "" && c.frontPassword == "" {
		_, err := conn.Write([]byte{version5, v5NotRequired})
		if err != nil {
			c.logger.Error("failed to write authentication reply:", err)
			return false
		}
		return true
	}
	_, err := conn.Write([]byte{version5, v5UsernamePassword})
	if err != nil {
		c.logger.Error("failed to write authentication methods:", err)
		return false
	}
	username, password, ok := c.socks5ReadCredential(reader)
	if !ok {
		return false
	}
	// write username password version
	_, err = conn.Write([]byte{v5UsernamePasswordVersion})
	if err != nil {
		c.logger.Error("failed to write username password version:", err)
		return false
	}
	// compare username and password
	eUser := []byte(c.frontUsername)
	ePass := []byte(c.frontPassword)
	userErr := subtle.ConstantTimeCompare(username, eUser) != 1
	passErr := subtle.ConstantTimeCompare(password, ePass) != 1
	if userErr || passErr {
		userInfo := fmt.Sprintf("%s:%s", username, password)
		c.logger.Warning("invalid username or password:", userInfo)
		_, _ = conn.Write([]byte{v5StatusFailed})
		return false
	}
	_, err = conn.Write([]byte{v5StatusSucceeded})
	if err != nil {
		c.logger.Error("failed to write authentication reply:", err)
		return false
	}
	return true
}

func (c *Client) socks5ReadCredential(reader *bufio.Reader) ([]byte, []byte, bool) {
	buf := make([]byte, 16)
	// read username and password version
	_, err := io.ReadFull(reader, buf[:1])
	if err != nil {
		c.logger.Error("failed to read username password version:", err)
		return nil, nil, false
	}
	if buf[0] != v5UsernamePasswordVersion {
		c.logger.Error("unexpected username password version")
		return nil, nil, false
	}
	// read username length
	_, err = io.ReadFull(reader, buf[:1])
	if err != nil {
		c.logger.Error("failed to read username length:", err)
		return nil, nil, false
	}
	l := int(buf[0])
	if l > len(buf) {
		buf = make([]byte, l)
	}
	// read username
	_, err = io.ReadFull(reader, buf[:l])
	if err != nil {
		c.logger.Error("failed to read username:", err)
		return nil, nil, false
	}
	username := make([]byte, l)
	copy(username, buf[:l])
	// read password length
	_, err = io.ReadFull(reader, buf[:1])
	if err != nil {
		c.logger.Error("failed to read password length:", err)
		return nil, nil, false
	}
	l = int(buf[0])
	if l > len(buf) {
		buf = make([]byte, l)
	}
	// read password
	_, err = io.ReadFull(reader, buf[:l])
	if err != nil {
		c.logger.Error("failed to read password:", err)
		return nil, nil, false
	}
	password := make([]byte, l)
	copy(password, buf[:l])
	return username, password, true
}

func (c *Client) socks5ReceiveConnectTarget(conn net.Conn, reader *bufio.Reader) string {
	buf := make([]byte, 4+net.IPv4len+2) // 4 + 4(ipv4) + 2(port)
	_, err := io.ReadFull(reader, buf[:4])
	if err != nil {
		c.logger.Error("failed to read version cmd address type:", err)
		return ""
	}
	if buf[0] != version5 {
		c.logger.Error("unexpected socks5 version")
		return ""
	}
	if buf[1] != v5CmdConnect {
		c.logger.Error("unknown command:", buf[1])
		_, _ = conn.Write([]byte{version5, v5CmdNotSupport, v5Reserve})
		return ""
	}
	if buf[2] != v5Reserve { // reserve
		c.logger.Warning("non-zero reserved field")
		_, _ = conn.Write([]byte{version5, v5NoReserve, v5Reserve})
		return ""
	}
	// read host
	var host string
	switch buf[3] {
	case v5AddrTypeIPv4:
		_, err = io.ReadFull(reader, buf[:net.IPv4len])
		if err != nil {
			c.logger.Error("failed to read IPv4 address:", err)
			return ""
		}
		host = net.IP(buf[:net.IPv4len]).String()
	case v5AddrTypeIPv6:
		buf = make([]byte, net.IPv6len)
		_, err = io.ReadFull(reader, buf[:net.IPv6len])
		if err != nil {
			c.logger.Error("failed to read IPv6 address:", err)
			return ""
		}
		host = net.IP(buf[:net.IPv6len]).String()
	case v5AddrTypeFQDN:
		// get FQDN length
		_, err = io.ReadFull(reader, buf[:1])
		if err != nil {
			c.logger.Error("failed to read FQDN length:", err)
			return ""
		}
		l := int(buf[0])
		if l > len(buf) {
			buf = make([]byte, l)
		}
		_, err = io.ReadFull(reader, buf[:l])
		if err != nil {
			c.logger.Error("failed to read FQDN:", err)
			return ""
		}
		host = string(buf[:l])
	default:
		c.logger.Error("invalid address type:", buf[3])
		_, _ = conn.Write(v5ReplyAddrNotSupport)
		return ""
	}
	// get port
	_, err = io.ReadFull(reader, buf[:2])
	if err != nil {
		c.logger.Error("failed to read port:", err)
		return ""
	}
	port := binary.BigEndian.Uint16(buf[:2])
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}
