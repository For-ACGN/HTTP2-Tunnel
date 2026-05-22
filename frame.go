package h2tunnel

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/pkg/errors"
)

const (
	framePing = iota + 1
	frameSetting
	frameShaping
)

// frame is the be transported over the tunnel.
type frame interface {
	Encode(b *bytes.Buffer) error
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

type pingFrame struct{}

func newPingFrame() *pingFrame {
	return new(pingFrame)
}

func (p *pingFrame) Encode(b *bytes.Buffer) error {
	b.WriteByte(framePing)
	b.Write(pingPadding)
	return nil
}

func (p *pingFrame) Decode(r io.Reader) error {
	typ := make([]byte, 1)
	_, err := r.Read(typ)
	if err != nil {
		return errors.Wrap(err, "failed to read frame type")
	}
	if typ[0] != framePing {
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

type settingFrame struct{}

func newSettingFrame() *settingFrame {
	return new(settingFrame)
}

func (s *settingFrame) Encode(b *bytes.Buffer) error {
	b.WriteByte(frameSetting)
	b.Write(settingPadding)
	return nil
}

func (s *settingFrame) Decode(r io.Reader) error {
	typ := make([]byte, 1)
	_, err := r.Read(typ)
	if err != nil {
		return errors.Wrap(err, "failed to read frame type")
	}
	if typ[0] != frameSetting {
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
		buffer: make([]byte, 3),
	}
}

func (s *shapingFrame) Encode(b *bytes.Buffer) error {
	if s.cache != nil {
		b.Write(s.cache)
		return nil
	}
	buf := bytes.NewBuffer(make([]byte, 0, 3+s.length))
	buf.WriteByte(frameShaping)
	buf.Write(binary.BigEndian.AppendUint16(nil, s.length))
	buf.Write(bytes.Repeat([]byte{0}, int(s.length)))
	o := buf.Bytes()
	b.Write(o)
	s.cache = o
	return nil
}

func (s *shapingFrame) Decode(r io.Reader) error {
	_, err := io.ReadFull(r, s.buffer)
	if err != nil {
		return errors.Wrap(err, "failed to read shaping frame header")
	}
	if s.buffer[0] != frameShaping {
		return errors.New("invalid frame type about shaping")
	}
	length := binary.BigEndian.Uint16(s.buffer[1:3])
	_, err = io.CopyN(io.Discard, r, int64(length))
	if err != nil {
		return errors.Wrap(err, "failed to read shaping padding data")
	}
	return nil
}
