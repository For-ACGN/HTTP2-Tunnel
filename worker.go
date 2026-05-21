package h2tunnel

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/pkg/errors"
)

const (
	watcherBehaviorSleep = iota
	watcherBehaviorPing
	watcherBehaviorBrowse
	watcherBehaviorKill
)

func (c *Client) generator() {
	defer func() {
		if r := recover(); r != nil {
			c.logger.Fatal("generator", r)
		}
		c.wg.Done()
	}()
	defer c.logger.Info("close secret random generator")

	rd := newMathRand()
	buf := make([]byte, 32)
	hash := sha256.New()
	for {
		_, _ = rd.Read(buf)
		hash.Reset()
		hash.Write(buf)
		hash.Write(c.hashBin)
		if !isCovertDigest(hash.Sum(nil)) {
			continue
		}
		random := bytes.Clone(buf)
		select {
		case c.randCh <- random:
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *Client) connector() {
	defer func() {
		if r := recover(); r != nil {
			c.logger.Fatal("connector", r)
		}
		c.wg.Done()
	}()

	if c.maxConns == 0 {
		return
	}
	mRand := newMathRand()
	for {
		// check client is closed
		select {
		case <-c.ctx.Done():
			return
		default:
		}
		// wait random time
		var delay time.Duration
		switch mRand.Intn(10) {
		case 0, 1, 2:
			delay = 0 * time.Second
		case 3, 4:
			delay = time.Duration(200+mRand.Intn(4000)) * time.Millisecond
		case 5, 6:
			delay = time.Duration(800+mRand.Intn(9000)) * time.Millisecond
		default:
			delay = time.Duration(100+mRand.Intn(2000)) * time.Millisecond
		}
		// preconnect
		select {
		case <-time.After(delay):
			if len(c.connCh) == c.maxConns {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			conn, err := c.preconnect()
			if err != nil {
				c.logger.Warning("failed to preconnect:", err)
				continue
			}
			select {
			case c.connCh <- conn:
			case <-c.ctx.Done():
				_ = conn.Close()
				return
			}
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *Client) watcher() {
	defer func() {
		if r := recover(); r != nil {
			c.logger.Fatal("watcher", r)
		}
		c.wg.Done()
	}()

	if c.maxConns == 0 {
		return
	}
	mRand := newMathRand()
	for {
		// sleep and check client is closed
		delay := 2000 + mRand.Intn(5000+mRand.Intn(10000))
		select {
		case <-time.After(time.Duration(delay) * time.Millisecond):
		case <-c.ctx.Done():
			return
		}
		// get preconnection connection
		var conn net.Conn
		select {
		case conn = <-c.connCh:
		case <-c.ctx.Done():
			return
		}
		// select behavior
		var behavior int
		switch mRand.Intn(10) {
		case 0, 1, 2:
			behavior = watcherBehaviorPing
		case 3:
			behavior = watcherBehaviorBrowse
		case 9:
			behavior = watcherBehaviorKill
		default:
			behavior = watcherBehaviorSleep
		}
		if !c.watchConn(conn, behavior) {
			_ = conn.Close()
			continue
		}
		// push to the connection channel
		select {
		case c.connCh <- conn:
		case <-c.ctx.Done():
			_ = conn.Close()
			return
		}
	}
}

func (c *Client) watchConn(conn net.Conn, behavior int) bool {
	switch behavior {
	case watcherBehaviorPing:
		err := c.ping(conn, 4, 256)
		if err != nil {
			c.logger.Warning("failed to ping connection:", err)
			return false
		}
		return true
	case watcherBehaviorBrowse:
		var maxResp int
		switch newMathRand().Intn(10) {
		case 0, 1, 2:
			maxResp = 192 * 1024
		case 3:
			maxResp = 256 * 1024
		case 4:
			maxResp = 512 * 1024
		default:
			maxResp = 128 * 1024
		}
		err := c.ping(conn, 1024, maxResp)
		if err != nil {
			c.logger.Warning("failed to simulate browse:", err)
			return false
		}
		return true
	case watcherBehaviorKill:
		return false
	case watcherBehaviorSleep:
		select {
		case <-time.After(3 * time.Second):
			return true
		case <-c.ctx.Done():
			return false
		}
	default:
		panic("invalid behavior")
	}
}

func (c *Client) ping(conn net.Conn, min, max int) error {
	// apply timeout
	_ = conn.SetDeadline(time.Now().Add(c.timeout))
	// build and send ping request
	req, err := http.NewRequestWithContext(c.ctx, http.MethodGet, c.buildURL("ping"), nil)
	if err != nil {
		return errors.Wrap(err, "failed to create request for ping")
	}
	garbage := make([]byte, 64+newMathRand().Intn(4*1024))
	header := req.Header
	header.Set("Pass-Hash", c.passHash)
	header.Set("Obfuscation", hex.EncodeToString(garbage))
	header.Set("Min-Size", strconv.Itoa(min))
	header.Set("Max-Size", strconv.Itoa(max))
	err = req.Write(conn)
	if err != nil {
		return errors.Wrap(err, "failed to send request for ping")
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return errors.Wrap(err, "failed to read response about ping")
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("invalid response status: %s", resp.Status)
	}
	if resp.Header.Get("Pong") != "Ping-Pong" {
		return errors.New("invalid server response about ping")
	}
	// reset deadline
	_ = conn.SetDeadline(time.Time{})
	return nil
}
