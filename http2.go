package msocks

import (
	"bytes"
	"io"
	"net"

	"golang.org/x/net/http2"
)

const (
	settingFrameSize = 46
)

func simulateHTTP2Client(conn net.Conn, preface []byte) error {
	// rand := newMathRand()

	if len(preface) == 0 {
		preface = []byte(http2.ClientPreface)
	}

	// write preface and setting frame
	buf := bytes.NewBuffer(make([]byte, 0, len(preface)+64))
	buf.Write(preface)
	buf.Write(bytes.Repeat([]byte{0x00}, settingFrameSize))
	_, err := buf.WriteTo(conn)
	if err != nil {
		return err
	}

	// write the first request with header
	// buf.Reset()
	// buf.Write(bytes.Repeat([]byte{0x00}, rand))

	return nil
}

func simulateHTTP2Server(conn net.Conn) error {
	size := 0
	size += len(http2.ClientPreface)
	size += settingFrameSize
	_, err := io.CopyN(io.Discard, conn, int64(size))
	if err != nil {
		return err
	}
	return nil
}
