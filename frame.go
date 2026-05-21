package h2tunnel

import (
	"bytes"
	"io"

	"github.com/pkg/errors"
)

const (
	framePing = iota + 1
	frameSetting
)

// frame is the be transported over the tunnel.
type frame interface {
	Encode(b *bytes.Buffer) error
	Decode(r io.Reader) error
}

// total length is 17 byte, equal with HTTP/2 PING.
// +------+---------+
// | type | padding |
// +------+---------+
// | byte | 16 byte |
// +------+---------+

var pingPadding = bytes.Repeat([]byte{0}, 16)

type pingFrame struct{}

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

// total length is 9 byte, equal with HTTP/2 SETTING with ack.
// +------+---------+
// | type | padding |
// +------+---------+
// | byte | 8 byte  |
// +------+---------+

var settingPadding = bytes.Repeat([]byte{0}, 8)

type settingFrame struct{}

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
