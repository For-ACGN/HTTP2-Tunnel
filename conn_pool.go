package h2tunnel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/For-ACGN/utls"
	"github.com/pkg/errors"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func (c *Client) getConn() (net.Conn, error) {
	// try to get connection from preconnect channel
	select {
	case conn := <-c.connCh:
		return conn, nil
	case <-c.ctx.Done():
		return nil, c.ctx.Err()
	default:
	}
	// if channel is empty(A large number of connections
	// were used in a short period of time), connect at once
	return c.preconnect()
}

func (c *Client) putConn(conn net.Conn) error {
	select {
	case c.connCh <- conn:
		return nil
	case <-c.ctx.Done():
		_ = simulateHTTP2GoAway(conn)
		_ = conn.Close()
		return c.ctx.Err()
	}
}

func (c *Client) preconnect() (net.Conn, error) {
	conn, hijacked, err := c.dial(false)
	if err != nil && !hijacked {
		return nil, errors.Wrap(err, "failed to connect to server")
	}
	if hijacked {
		return nil, errors.Errorf("[!] detect attacker [!] - %s", err)
	}
	var success bool
	defer func() {
		if !success {
			_ = conn.Close()
		}
	}()
	// apply timeout
	_ = conn.SetDeadline(time.Now().Add(c.timeout))
	req, err := http.NewRequestWithContext(c.ctx, http.MethodGet, c.buildURL("ping"), nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create request for preconnect")
	}
	garbage := make([]byte, 128+newMathRand().Intn(256))
	header := req.Header
	header.Set("Pass-Hash", c.passHash)
	header.Set("Obfuscation", hex.EncodeToString(garbage))
	header.Set("Min-Size", "512")
	header.Set("Max-Size", "32768")
	err = req.Write(conn)
	if err != nil {
		return nil, errors.Wrap(err, "failed to send request for preconnect")
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read response about preconnect")
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("invalid response status: %s", resp.Status)
	}
	if resp.Header.Get("Pong") != "Ping-Pong" {
		return nil, errors.New("invalid server response about ping")
	}
	// reset deadline
	_ = conn.SetDeadline(time.Time{})
	success = true
	return conn, nil
}

func (c *Client) dial(first bool) (net.Conn, bool, error) {
	dialer := c.buildDialer()
	conn, err := dialer.DialContext(c.ctx, c.serverNet, c.serverAddr)
	if err != nil {
		return nil, false, err
	}
	colonPos := strings.LastIndex(c.serverAddr, ":")
	if colonPos == -1 {
		colonPos = len(c.serverAddr)
	}
	serverName := c.serverAddr[:colonPos]
	tlsConfig := c.tlsConfig.Clone()
	tlsConfig.ServerName = serverName
	var clientID utls.ClientHelloID
	if first {
		clientID = utls.HelloFirefox_Auto
	} else {
		clientID = utls.HelloFirefox_PSK_Auto
	}
	uc := utls.UClient(conn, tlsConfig, clientID)
	var success bool
	defer func() {
		if !success {
			_ = uc.Close()
		}
	}()
	// set secret random value
	err = uc.BuildHandshakeState()
	if err != nil {
		return nil, false, err
	}
	var random []byte
	select {
	case random = <-c.randCh:
	case <-c.ctx.Done():
		return nil, false, c.ctx.Err()
	}
	err = uc.SetClientRandom(random)
	if err != nil {
		return nil, false, err
	}
	err = uc.Handshake()
	if err != nil {
		return nil, false, err
	}
	err = c.detect(uc)
	if err != nil {
		_ = c.mimic(uc)
		return nil, true, err
	}
	err = simulateHTTP2Client(uc, c.preface)
	if err != nil {
		return nil, false, err
	}
	success = true
	return uc, false, nil
}

func (c *Client) buildDialer() *net.Dialer {
	if runtime.GOOS != "android" {
		return new(net.Dialer)
	}
	dialer := net.Dialer{
		Timeout: 3 * time.Second,
	}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, c.dnsServer)
		},
	}
	return &net.Dialer{Resolver: resolver, Timeout: c.timeout}
}

func (c *Client) detect(conn *utls.UConn) error {
	state := conn.ConnectionState()
	if state.NegotiatedProtocol != "h2" {
		return errors.New("invalid negotiated protocol")
	}
	if state.Version != utls.VersionTLS13 {
		return errors.New("invalid TLS version")
	}
	var pinned bool
	for _, cert := range state.PeerCertificates {
		hash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		s := hex.EncodeToString(hash[:])
		if slices.Contains(c.certPin, s) {
			pinned = true
			break
		}
	}
	if !pinned {
		return errors.New("invalid public key in certificate")
	}
	return nil
}

//gocyclo:ignore
func (c *Client) mimic(conn net.Conn) error {
	_ = conn.SetDeadline(time.Now().Add(c.timeout))

	// batch preface + SETTINGS + WINDOW_UPDATE into one TLS Record (Firefox behavior)
	buffer := bytes.NewBuffer(make([]byte, 0, 1024))
	buffer.Write([]byte(http2.ClientPreface))
	framer := http2.NewFramer(buffer, nil)
	err := framer.WriteSettings(
		http2.Setting{ID: http2.SettingHeaderTableSize, Val: 65536},
		http2.Setting{ID: http2.SettingEnablePush, Val: 0},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: 131072},
		http2.Setting{ID: http2.SettingMaxFrameSize, Val: 16384},
	)
	if err != nil {
		return err
	}
	err = framer.WriteWindowUpdate(0, 12517377)
	if err != nil {
		return err
	}
	_, err = buffer.WriteTo(conn)
	if err != nil {
		return err
	}

	// encode headers with Firefox order
	hpb := bytes.NewBuffer(make([]byte, 0, 4096))
	encoder := hpack.NewEncoder(hpb)
	wh := func(name, value string) {
		field := hpack.HeaderField{
			Name:  name,
			Value: value,
		}
		_ = encoder.WriteField(field)
	}
	// if the port is 443, it wil remove suffix about ":443"
	authority := c.serverAddr
	host, port, err := net.SplitHostPort(c.serverAddr)
	if err != nil {
		return err
	}
	if port == "443" {
		authority = host
	}
	// pseudo-headers first
	wh(":method", "GET")
	wh(":path", "/")
	wh(":authority", authority)
	wh(":scheme", "https")
	// Firefox specific header order
	wh("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:150.0) Gecko/20100101 Firefox/150.0")
	wh("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	wh("accept-language", "zh-CN,zh;q=0.9,zh-TW;q=0.8,zh-HK;q=0.7,en-US;q=0.6,en;q=0.5")
	wh("accept-encoding", "gzip, deflate, br, zstd")
	wh("dht", "1")
	wh("sec-gpc", "1")
	wh("upgrade-insecure-requests", "1")
	wh("sec-fetch-dest", "document")
	wh("sec-fetch-mode", "navigate")
	wh("sec-fetch-site", "none")
	wh("sec-fetch-user", "?1")
	wh("priority", "u=0, i")
	wh("te", "trailers")
	// send headers frame
	buffer.Reset()
	err = framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:   3,
		PadLength:  0,
		EndHeaders: true,
		EndStream:  true,
		Priority: http2.PriorityParam{
			Exclusive: false,
			StreamDep: 0,
			Weight:    41,
		},
		BlockFragment: hpb.Bytes(),
	})
	if err != nil {
		return err
	}
	err = framer.WriteWindowUpdate(3, 12451840)
	if err != nil {
		return err
	}
	// send Headers and WINDOW_UPDATE
	_, err = buffer.WriteTo(conn)
	if err != nil {
		return err
	}

	// read server SETTINGS and send client ACK
	framer = http2.NewFramer(conn, conn)
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			return err
		}
		_, ok := frame.(*http2.SettingsFrame)
		if ok {
			break
		}
	}
	err = framer.WriteSettingsAck()
	if err != nil {
		return err
	}

	// read and discard server frames
	d := time.Duration(3000+newMathRand().Intn(10000)) * time.Millisecond
	_ = conn.SetDeadline(time.Now().Add(d))
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			break
		}
		switch frame.(type) {
		case *http2.PingFrame:
			err = framer.WritePing(false, [8]byte{})
			if err != nil {
				return err
			}
		case *http2.GoAwayFrame:
			return nil
		}
	}

	// send GOAWAY frame to close HTTP/2 connection gracefully
	_ = conn.SetDeadline(time.Now().Add(c.timeout))
	err = framer.WriteGoAway(0, http2.ErrCodeNo, nil)
	return err
}
