package h2tunnel

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/pkg/errors"
)

const (
	maxObfDataSize = 512
	minSegmentSize = 128
)

var (
	tlsClientHelloPrefix = []byte{0x16, 0x03, 0x01}
	tlsClientHelloHTTP1o = []byte("\x00\x09\x08http/1.1")
	tlsClientHelloHTTP2o = []byte("\x00\x03\x02h2")
	tlsClientHelloHTTPx  = []byte("\x00\x0C\x02h2\x08http/1.1")
)

type tunnel struct {
	net.Conn

	clientSide bool
	serverSide bool

	mRand *mathRand
	block cipher.Block

	key []byte
	iv  []byte
	jit int

	isHandshake  bool
	handshakeErr error
	handshakeMu  sync.Mutex

	writeBuf []byte
	writeCtr uint64

	writer cipher.Stream
	reader cipher.Stream

	// about special control
	sniffed bool
	isTLS   bool
	isHTTP1 bool
	isHTTP2 bool

	rmu sync.Mutex
	wmu sync.Mutex
	smu sync.Mutex

	// context data
	Protocol string
	IPType   string
	Address  string
	Elapsed  time.Duration
}

func newClientTunnel(conn net.Conn, key []byte, jitter int) (*tunnel, error) {
	tun, err := newTunnel(conn, key, jitter)
	if err != nil {
		return nil, err
	}
	tun.clientSide = true
	return tun, nil
}

func newServerTunnel(conn net.Conn, key []byte, jitter int) (*tunnel, error) {
	tun, err := newTunnel(conn, key, jitter)
	if err != nil {
		return nil, err
	}
	tun.serverSide = true
	return tun, nil
}

func newTunnel(conn net.Conn, key []byte, jitter int) (*tunnel, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, aes.BlockSize)
	_, err = rand.Read(iv)
	if err != nil {
		return nil, err
	}
	if jitter == 0 {
		jitter = defaultJitterLevel
	}
	if jitter < 1 || jitter > maximumJitterLevel {
		return nil, errors.Errorf("jitter level must be between 1 and %d", maximumJitterLevel)
	}
	tun := tunnel{
		Conn:  conn,
		mRand: newMathRand(),
		block: block,
		key:   key,
		iv:    iv,
		jit:   jitter,
	}
	return &tun, nil
}

// +----------+----------+----------+
// | obf size | obf data |  AES IV  |
// +----------+----------+----------+
// |  uint16  |   var    | 16 bytes |
// +----------+----------+----------+

func (t *tunnel) Handshake() error {
	t.handshakeMu.Lock()
	defer t.handshakeMu.Unlock()
	if t.isHandshake {
		return t.handshakeErr
	}
	t.isHandshake = true
	// generate random size data
	buf := make([]byte, 2)
	_, _ = rand.Read(buf)
	obfSize := binary.BigEndian.Uint16(buf) % maxObfDataSize
	obf := make([]byte, 2+obfSize)
	binary.BigEndian.PutUint16(obf[:2], obfSize)
	_, _ = rand.Read(obf[2:])
	// exchange AES IV for create read stream
	packet := append(obf, t.iv...)
	_, err := t.Conn.Write(packet)
	if err != nil {
		t.handshakeErr = errors.Wrap(err, "failed to write iv packet")
		return t.handshakeErr
	}
	// read random size data
	_, err = io.ReadFull(t.Conn, buf)
	if err != nil {
		t.handshakeErr = errors.Wrap(err, "failed to read obf size")
		return t.handshakeErr
	}
	obfSize = binary.BigEndian.Uint16(buf)
	if obfSize >= maxObfDataSize {
		t.handshakeErr = errors.New("invalid obf data size")
		return t.handshakeErr
	}
	_, err = io.CopyN(io.Discard, t.Conn, int64(obfSize))
	if err != nil {
		t.handshakeErr = errors.Wrap(err, "failed to read obf data")
		return t.handshakeErr
	}
	// read IV from remote connection
	iv := make([]byte, aes.BlockSize)
	_, err = io.ReadFull(t.Conn, iv)
	if err != nil {
		t.handshakeErr = errors.Wrap(err, "failed to read iv data")
		return t.handshakeErr
	}
	block, err := aes.NewCipher(t.key)
	if err != nil {
		t.handshakeErr = errors.Wrap(err, "failed to create reader stream")
		return t.handshakeErr
	}
	t.reader = cipher.NewCTR(block, iv)     // #nosec
	t.writer = cipher.NewCTR(t.block, t.iv) // #nosec
	// clean data after exchange
	t.key = nil
	t.iv = nil
	return nil
}

func (t *tunnel) Read(b []byte) (int, error) {
	err := t.Handshake()
	if err != nil {
		return 0, err
	}
	if len(b) == 0 {
		return 0, nil
	}
	t.rmu.Lock()
	defer t.rmu.Unlock()
	n, err := t.Conn.Read(b)
	if err != nil {
		return n, err
	}
	t.reader.XORKeyStream(b[:n], b[:n])
	t.sniff(b)
	return n, nil
}

func (t *tunnel) Write(b []byte) (int, error) {
	err := t.Handshake()
	if err != nil {
		return 0, err
	}
	if len(b) == 0 {
		return 0, nil
	}
	t.wmu.Lock()
	defer t.wmu.Unlock()
	t.sniff(b)
	// process write buffer
	if len(t.writeBuf) < len(b) {
		t.writeBuf = make([]byte, len(b))
	}
	buf := t.writeBuf[:len(b)]
	t.writer.XORKeyStream(buf, b)
	t.writeCtr++
	// special case for HTTPS
	if t.isHTTP2 {
		return t.writeSegment(buf)
	}
	if t.writeCtr < uint64(16+t.mRand.Intn(32)) { // #nosec
		return t.writeSegment(buf)
	}
	if t.jit > int(buf[0]%maximumJitterLevel) {
		return t.writeSegment(buf)
	}
	return t.Conn.Write(buf)
}

func (t *tunnel) sniff(b []byte) {
	t.smu.Lock()
	defer t.smu.Unlock()
	if t.sniffed {
		return
	}
	t.sniffed = true
	switch {
	case bytes.HasPrefix(b, tlsClientHelloPrefix):
		switch {
		case bytes.Contains(b, tlsClientHelloHTTP1o):
			t.isHTTP1 = true
		case bytes.Contains(b, tlsClientHelloHTTP2o):
			t.isHTTP2 = true
		case bytes.Contains(b, tlsClientHelloHTTPx):
			t.isHTTP2 = true
		}
		t.isTLS = true
	case bytes.HasPrefix(b, []byte(http.MethodGet)),
		bytes.HasPrefix(b, []byte(http.MethodPost)),
		bytes.HasPrefix(b, []byte(http.MethodConnect)),
		bytes.HasPrefix(b, []byte(http.MethodOptions)):
		t.isHTTP1 = true
	}
}

func (t *tunnel) writeSegment(b []byte) (int, error) {
	total := len(b)
	if total <= minSegmentSize {
		return t.Conn.Write(b)
	}

	// prepare the number of the segments
	numSegments := t.determineNumSegments(total)
	if numSegments <= 1 {
		return t.Conn.Write(b)
	}

	// generate split points
	points := make([]int, numSegments-1)
	for i := range points {
		points[i] = t.mRand.Intn(total)
	}
	sort.Ints(points)

	// calculate the segment size
	sizes := make([]int, numSegments)
	prev := 0
	for i, p := range points {
		sizes[i] = p - prev
		prev = p
	}
	sizes[numSegments-1] = total - prev
	// shuffle segment size
	t.mRand.Shuffle(len(sizes), func(i, j int) {
		sizes[i], sizes[j] = sizes[j], sizes[i]
	})

	// merge the too small segment into the previous one
	merged := make([]int, 0, len(sizes))
	for _, size := range sizes {
		if len(merged) > 0 && size < minSegmentSize {
			merged[len(merged)-1] += size
		} else {
			merged = append(merged, size)
		}
	}
	// shuffle merged segments
	t.mRand.Shuffle(len(merged), func(i, j int) {
		merged[i], merged[j] = merged[j], merged[i]
	})

	// write segments
	offset := 0
	for _, size := range merged {
		_, err := t.Conn.Write(b[offset : offset+size])
		if err != nil {
			return 0, err
		}
		offset += size
	}
	return total, nil
}

func (t *tunnel) determineNumSegments(total int) int {
	if t.writeCtr == 1 {
		return 2 + t.mRand.Intn(6)
	}
	var numSegments int
	switch {
	case t.isHTTP1:
		numSegments = 2 + t.mRand.Intn(3+t.jit*(total/2048))
	case t.isTLS:
		numSegments = 1 + t.mRand.Intn(1+t.jit*(total/1024))
	default:
		numSegments = 1 + t.mRand.Intn(2+t.jit*(total/1024))
	}
	if !t.isHTTP2 {
		return 1 + numSegments
	}
	switch {
	case total > 12288:
		if t.mRand.Intn(10) > t.jit {
			return 1
		}
		return 2 + t.mRand.Intn(2)
	case total > 4096:
		if t.mRand.Intn(6) > t.jit {
			return 1
		}
		return 2 + t.mRand.Intn(2)
	case total > 1024:
		if t.mRand.Intn(4) > t.jit {
			return 1
		}
		return 1 + t.mRand.Intn(2)
	case total > 256:
		if t.mRand.Intn(3) > t.jit {
			return 1
		}
		return 2
	default:
		return 1
	}
}
