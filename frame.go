package h2tunnel

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"

	"github.com/pkg/errors"
)

const (
	frameTypePing = iota + 1
	frameTypeSetting
	frameTypeShaping
	frameTypeNewSessionRequest
	frameTypeNewSessionResponse
	frameTypeSessionData
)

const gcmNonceSize = 12

// frame is the be transported over the tunnel.
type frame interface {
	Encode(w io.Writer) error
	Decode(r io.Reader) error
}

// ---------------------------------------- ping ----------------------------------------

// total length is 17 byte, equal with HTTP/2 PING.
// +------+---------+
// | type | padding |
// +------+---------+
// | byte | 16 byte |
// +------+---------+

var pingPadding = bytes.Repeat([]byte{0}, 16)

type pingFrame struct {
	buffer []byte
}

func newPingFrame() *pingFrame {
	return &pingFrame{
		buffer: make([]byte, 1),
	}
}

func (f *pingFrame) Encode(w io.Writer) error {
	_, err := w.Write([]byte{frameTypePing})
	if err != nil {
		return err
	}
	_, err = w.Write(pingPadding)
	return err
}

func (f *pingFrame) Decode(r io.Reader) error {
	_, err := io.ReadFull(r, f.buffer)
	if err != nil {
		return errors.Wrap(err, "failed to read frame type")
	}
	if f.buffer[0] != frameTypePing {
		return errors.New("invalid frame type about ping")
	}
	_, err = io.CopyN(io.Discard, r, int64(len(pingPadding)))
	if err != nil {
		return errors.Wrap(err, "failed to read ping padding data")
	}
	return nil
}

// --------------------------------------- setting --------------------------------------

// total length is 9 byte, equal with HTTP/2 SETTING with ack.
// +------+---------+
// | type | padding |
// +------+---------+
// | byte | 8 byte  |
// +------+---------+

var settingPadding = bytes.Repeat([]byte{0}, 8)

type settingFrame struct {
	buffer []byte
}

func newSettingFrame() *settingFrame {
	return &settingFrame{
		buffer: make([]byte, 1),
	}
}

func (f *settingFrame) Encode(w io.Writer) error {
	_, err := w.Write([]byte{frameTypeSetting})
	if err != nil {
		return err
	}
	_, err = w.Write(settingPadding)
	return err
}

func (f *settingFrame) Decode(r io.Reader) error {
	_, err := io.ReadFull(r, f.buffer)
	if err != nil {
		return errors.Wrap(err, "failed to read frame type")
	}
	if f.buffer[0] != frameTypeSetting {
		return errors.New("invalid frame type about setting")
	}
	_, err = io.CopyN(io.Discard, r, int64(len(settingPadding)))
	if err != nil {
		return errors.Wrap(err, "failed to read setting padding data")
	}
	return nil
}

// --------------------------------------- shaping --------------------------------------

// +------+--------+---------+
// | type | length | padding |
// +------+--------+---------+
// | byte | uint16 |   var   |
// +------+--------+---------+

type shapingFrame struct {
	length uint16
	cache  []byte
	buffer []byte
}

func newShapingFrame(length uint16) *shapingFrame {
	if length < 4 {
		panic("shaping frame length too small")
	}
	return &shapingFrame{
		length: length - 3,
		buffer: make([]byte, 2),
	}
}

func (f *shapingFrame) Encode(w io.Writer) error {
	if f.cache != nil {
		_, err := w.Write(f.cache)
		return err
	}
	buf := bytes.NewBuffer(make([]byte, 0, 3+f.length))
	buf.WriteByte(frameTypeShaping)
	buf.Write(binary.BigEndian.AppendUint16(nil, f.length))
	buf.Write(bytes.Repeat([]byte{0}, int(f.length)))
	b := buf.Bytes()
	f.cache = b
	_, err := w.Write(b)
	return err
}

func (f *shapingFrame) Decode(r io.Reader) error {
	_, err := io.ReadFull(r, f.buffer[:1])
	if err != nil {
		return errors.Wrap(err, "failed to read frame type")
	}
	if f.buffer[0] != frameTypeShaping {
		return errors.New("invalid frame type about shaping")
	}
	_, err = io.ReadFull(r, f.buffer[:2])
	if err != nil {
		return errors.Wrap(err, "failed to read shaping padding length")
	}
	length := binary.BigEndian.Uint16(f.buffer[:2])
	_, err = io.CopyN(io.Discard, r, int64(length))
	if err != nil {
		return errors.Wrap(err, "failed to read shaping padding data")
	}
	return nil
}

// --------------------------------- new session request --------------------------------

// +------+------------+--------------+---------+----------------+---------+--------------+---------+
// | type | public key | network size | network |  address size  | address |  buffer size |  jitter |
// +------+------------+--------------+---------+----------------+---------+--------------+---------+
// | byte |  32 bytes  |    uint16    |   var   |     uint16     |   var   |    uint16    |  uint16 |
// +------+------------+--------------+---------+----------------+---------+--------------+---------+

type newSessionRequestFrame struct {
	buffer []byte

	PublicKey   []byte
	Network     string
	Address     string
	BufferSize  int
	JitterLevel int
}

func newNewSessionRequestFrame() *newSessionRequestFrame {
	return &newSessionRequestFrame{
		buffer: make([]byte, 2),
	}
}

func (f *newSessionRequestFrame) Encode(w io.Writer) error {
	netData := []byte(f.Network)
	addrData := []byte(f.Address)
	size := len(f.PublicKey) + 2 + len(netData) + 2 + len(addrData) + 2 + 2
	buffer := make([]byte, 1+size)
	buffer[0] = frameTypeNewSessionRequest
	offset := 1
	copy(buffer[offset:], f.PublicKey)
	offset += len(f.PublicKey)
	binary.BigEndian.PutUint16(buffer[offset:], uint16(len(netData)))
	offset += 2
	copy(buffer[offset:], netData)
	offset += len(netData)
	binary.BigEndian.PutUint16(buffer[offset:], uint16(len(addrData)))
	offset += 2
	copy(buffer[offset:], addrData)
	offset += len(addrData)
	binary.BigEndian.PutUint16(buffer[offset:], uint16(f.BufferSize)) // #nosec G115
	offset += 2
	binary.BigEndian.PutUint16(buffer[offset:], uint16(f.JitterLevel)) // #nosec G115
	_, err := w.Write(buffer)
	return err
}

func (f *newSessionRequestFrame) Decode(r io.Reader) error {
	_, err := io.ReadFull(r, f.buffer[:1])
	if err != nil {
		return errors.Wrap(err, "failed to read frame type")
	}
	if f.buffer[0] != frameTypeNewSessionRequest {
		return errors.New("invalid frame type about new session request")
	}
	f.PublicKey = make([]byte, 32)
	_, err = io.ReadFull(r, f.PublicKey)
	if err != nil {
		return errors.Wrap(err, "failed to read public key")
	}
	_, err = io.ReadFull(r, f.buffer[:2])
	if err != nil {
		return errors.Wrap(err, "failed to read network size")
	}
	netLen := binary.BigEndian.Uint16(f.buffer[:2])
	if netLen > 0 {
		netBuf := make([]byte, netLen)
		_, err = io.ReadFull(r, netBuf)
		if err != nil {
			return errors.Wrap(err, "failed to read network")
		}
		f.Network = string(netBuf)
	}
	_, err = io.ReadFull(r, f.buffer[:2])
	if err != nil {
		return errors.Wrap(err, "failed to read address size")
	}
	addrLen := binary.BigEndian.Uint16(f.buffer[:2])
	if addrLen > 0 {
		addrBuf := make([]byte, addrLen)
		_, err = io.ReadFull(r, addrBuf)
		if err != nil {
			return errors.Wrap(err, "failed to read address")
		}
		f.Address = string(addrBuf)
	}
	_, err = io.ReadFull(r, f.buffer[:2])
	if err != nil {
		return errors.Wrap(err, "failed to read buffer size")
	}
	f.BufferSize = int(binary.BigEndian.Uint16(f.buffer[:2]))
	_, err = io.ReadFull(r, f.buffer[:2])
	if err != nil {
		return errors.Wrap(err, "failed to read jitter level")
	}
	f.JitterLevel = int(binary.BigEndian.Uint16(f.buffer[:2]))
	return nil
}

// ------------------------------------ session data ------------------------------------

// +------+------------+--------+--------------+
// | type | session id | length | session data |
// +------+------------+--------+--------------+
// | byte |  16 byte   | uint16 |     var      |
// +------+------------+--------+--------------+

type sessionDataFrame struct {
	id     sessionID
	aead   cipher.AEAD
	buffer []byte

	Data []byte
}

func newSessionDataFrame(id sessionID, aead cipher.AEAD) *sessionDataFrame {
	return &sessionDataFrame{
		id:     id,
		aead:   aead,
		buffer: make([]byte, 2),
	}
}

func (f *sessionDataFrame) Encode(w io.Writer) error {
	size := gcmNonceSize + len(f.Data) + f.aead.Overhead()
	buffer := make([]byte, 1+len(f.id)+2+size)
	buffer[0] = frameTypeSessionData
	copy(buffer[1:], f.id[:])
	binary.BigEndian.PutUint16(buffer[1+len(f.id):], uint16(size)) // #nosec G115
	payload := buffer[1+len(f.id)+2:]
	dst := payload[gcmNonceSize:gcmNonceSize]
	nonce := payload[:gcmNonceSize]
	_, err := rand.Read(nonce)
	if err != nil {
		return errors.Wrap(err, "failed to generate nonce")
	}
	f.aead.Seal(dst, nonce, f.Data, nil)
	_, err = w.Write(buffer)
	return err
}

func (f *sessionDataFrame) Decode(r io.Reader) error {
	_, err := io.ReadFull(r, f.buffer[:1])
	if err != nil {
		return errors.Wrap(err, "failed to read frame type")
	}
	if f.buffer[0] != frameTypeSessionData {
		return errors.New("invalid frame type about session data")
	}
	_, err = io.ReadFull(r, f.id[:])
	if err != nil {
		return errors.Wrap(err, "failed to read session id")
	}
	_, err = io.ReadFull(r, f.buffer[:2])
	if err != nil {
		return errors.Wrap(err, "failed to read session data payload length")
	}
	length := binary.BigEndian.Uint16(f.buffer[:2])
	payload := make([]byte, length)
	_, err = io.ReadFull(r, payload)
	if err != nil {
		return errors.Wrap(err, "failed to read session data payload")
	}
	if len(payload) < gcmNonceSize {
		return errors.New("invalid session data payload length")
	}
	nonce := payload[:gcmNonceSize]
	ciphertext := payload[gcmNonceSize:]
	f.Data, err = f.aead.Open(ciphertext[:0], nonce, ciphertext, nil)
	if err != nil {
		return errors.Wrap(err, "failed to decrypt session data payload")
	}
	return nil
}
