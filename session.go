package h2tunnel

import (
	"crypto/rand"
	"net"
	"sync"
	"time"
)

type sessionID = [16]byte

type sessionMgr struct {
	mRand       *mathRand
	sessions    map[sessionID]*Session
	sessionsRWM sync.RWMutex
}

func newSessionMgr() *sessionMgr {
	mgr := sessionMgr{
		mRand:    newMathRand(),
		sessions: make(map[sessionID]*Session),
	}
	return &mgr
}

func (mgr *sessionMgr) NewSession(tun *tunnel) *Session {
	mgr.sessionsRWM.Lock()
	defer mgr.sessionsRWM.Unlock()
	var id sessionID
	mgr.mRand.Read(id[:])
	_, _ = rand.Read(id[:])
	session := &Session{
		id:  id,
		tun: tun,
	}
	mgr.sessions[id] = session
	return session
}

// Session is like the TCP Connection, but a
// virtual connection over the HTTP/2 Tunnel.
type Session struct {
	id  sessionID
	tun *tunnel
}

// Read implement the net.Conn Read method.
func (s *Session) Read(b []byte) (int, error) {
	return 0, nil
}

// Write implement the net.Conn Write method.
func (s *Session) Write(b []byte) (int, error) {
	return 0, nil
}

// LocalAddr implement the net.Conn LocalAddr method.
func (s *Session) LocalAddr() net.Addr {
	return nil
}

// RemoteAddr implement the net.Conn RemoteAddr method.
func (s *Session) RemoteAddr() net.Addr {
	return nil
}

// SetDeadline implement the net.Conn SetDeadline method.
func (s *Session) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline implement the net.Conn SetReadDeadline method.
func (s *Session) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline implement the net.Conn SetWriteDeadline method.
func (s *Session) SetWriteDeadline(t time.Time) error {
	return nil
}

// Close implement the net.Conn Close method.
func (s *Session) Close() error {
	return nil
}
