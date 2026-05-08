package msocks

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"

	"golang.org/x/net/http2"
)

const (
	settingFrameSize = 46
	srvPacket1       = 39 // TODO adjust ?
	srvPacket2       = 22 // TODO adjust ?
	cliPacket1       = 9  // TODO adjust ?
)

func simulateHTTP2Client(conn net.Conn, preface []byte) error {
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
	rand := newMathRand()
	size := 384 + int(binary.BigEndian.Uint32(preface)%256)
	if rand.Intn(4+rand.Intn(8)) == 0 {
		size += rand.Intn(128)
	}
	buf.Reset()
	buf.Write(binary.BigEndian.AppendUint16(nil, uint16(size)))
	buf.Write(bytes.Repeat([]byte{0x00}, size))
	_, err = buf.WriteTo(conn)
	if err != nil {
		return err
	}

	// discard server packet 1 and 2
	_, err = io.CopyN(io.Discard, conn, int64(srvPacket1+srvPacket2))
	if err != nil {
		return err
	}

	// send client packet 1
	_, err = conn.Write(bytes.Repeat([]byte{0x00}, cliPacket1))
	if err != nil {
		return err
	}
	return nil
}

func simulateHTTP2Server(conn net.Conn) error {
	// discard preface + setting
	size := int64(0)
	size += int64(len(http2.ClientPreface))
	size += settingFrameSize
	_, err := io.CopyN(io.Discard, conn, size)
	if err != nil {
		return err
	}

	// discard first request with header
	buf := make([]byte, 2)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return err
	}
	size = int64(binary.BigEndian.Uint16(buf))
	_, err = io.CopyN(io.Discard, conn, size)
	if err != nil {
		return err
	}

	// send server packet 1 and 2
	_, err = conn.Write(bytes.Repeat([]byte{0x00}, srvPacket1))
	if err != nil {
		return err
	}
	_, err = conn.Write(bytes.Repeat([]byte{0x00}, srvPacket2))
	if err != nil {
		return err
	}

	// discard client packet 1
	_, err = io.CopyN(io.Discard, conn, int64(cliPacket1))
	if err != nil {
		return err
	}
	return nil
}
