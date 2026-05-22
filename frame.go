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
	framePing = iota + 1
	frameSetting
	frameShaping
	frameData
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
	_, err := w.Write([]byte{framePing})
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
	if f.buffer[0] != framePing {
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
	_, err := w.Write([]byte{frameSetting})
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
	if f.buffer[0] != frameSetting {
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
	buf.WriteByte(frameShaping)
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
	if f.buffer[0] != frameShaping {
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

// ---------------------------------------- data ----------------------------------------

// +------+------------+--------+--------------+
// | type | session id | length | session data |
// +------+------------+--------+--------------+
// | byte |  16 byte   | uint16 |     var      |
// +------+------------+--------+--------------+

type dataFrame struct {
	id     sessionID
	aead   cipher.AEAD
	buffer []byte

	Data []byte
}

func newDataFrame(id sessionID, aead cipher.AEAD) *dataFrame {
	return &dataFrame{
		id:     id,
		aead:   aead,
		buffer: make([]byte, 2),
	}
}

func (f *dataFrame) Encode(w io.Writer) error {
	size := gcmNonceSize + len(f.Data) + f.aead.Overhead()
	buffer := make([]byte, 1+len(f.id)+2+size)
	buffer[0] = frameData
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

func (f *dataFrame) Decode(r io.Reader) error {
	_, err := io.ReadFull(r, f.buffer[:1])
	if err != nil {
		return errors.Wrap(err, "failed to read frame type")
	}
	if f.buffer[0] != frameData {
		return errors.New("invalid frame type about data")
	}
	_, err = io.ReadFull(r, f.id[:])
	if err != nil {
		return errors.Wrap(err, "failed to read session id")
	}
	_, err = io.ReadFull(r, f.buffer[:2])
	if err != nil {
		return errors.Wrap(err, "failed to read data payload length")
	}
	length := binary.BigEndian.Uint16(f.buffer[:2])
	payload := make([]byte, length)
	_, err = io.ReadFull(r, payload)
	if err != nil {
		return errors.Wrap(err, "failed to read data payload")
	}
	if len(payload) < gcmNonceSize {
		return errors.New("invalid data payload length")
	}
	nonce := payload[:gcmNonceSize]
	ciphertext := payload[gcmNonceSize:]
	f.Data, err = f.aead.Open(ciphertext[:0], nonce, ciphertext, nil)
	if err != nil {
		return errors.Wrap(err, "failed to decrypt data payload")
	}
	return nil
}
