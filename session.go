package h2tunnel

import (
	"net"
	"sync"
	"time"
)

type sessionID = [16]byte

type sessionMgr struct {
	sessions    map[sessionID]*Session
	sessionsRWM sync.RWMutex
}

func newSessionMgr() *sessionMgr {
	return &sessionMgr{
		sessions: make(map[sessionID]*Session),
	}
}

// Session is like the TCP Connection, but a
// virtual connection over the HTTP/2 Tunnel.
type Session struct {
	id sessionID
}

func (s *Session) Read(b []byte) (int, error) {
	return 0, nil
}

func (s *Session) Write(b []byte) (int, error) {
	return 0, nil
}

func (s *Session) LocalAddr() net.Addr {
	return nil
}

func (s *Session) RemoteAddr() net.Addr {
	return nil
}

func (s *Session) SetDeadline(t time.Time) error {
	return nil
}

func (s *Session) SetReadDeadline(t time.Time) error {
	return nil
}

func (s *Session) SetWriteDeadline(t time.Time) error {
	return nil
}

func (s *Session) Close() error {
	return nil
}
