package h2tunnel

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"time"

	"golang.org/x/net/http2"
)

const (
	http2PrefaceSize = 24
	streamHeaderSize = 3 + 1 + 1 + 4

	cliSettingsSize     = streamHeaderSize + 24
	cliWindowUpdateSize = streamHeaderSize + 4
	cliAcknowledgeSize  = streamHeaderSize

	srvSettingsSize     = streamHeaderSize + 36
	srvAcknowledgeSize  = streamHeaderSize
	srvWindowUpdateSize = streamHeaderSize + 4
)

func simulateHTTP2Client(conn net.Conn, preface []byte) error {
	rand := newMathRand()

	if len(preface) == 0 {
		preface = []byte(http2.ClientPreface)
	}

	// simulate process preface and header
	time.Sleep(time.Duration(140+rand.Intn(10+rand.Intn(40))) * time.Microsecond)

	// write preface, settings, window update in one tls record
	buffer := bytes.NewBuffer(make([]byte, 0, len(preface)+64))
	buffer.Write(preface)
	buffer.Write(bytes.Repeat([]byte{0x00}, cliSettingsSize))
	buffer.Write(bytes.Repeat([]byte{0x00}, cliWindowUpdateSize))
	_, err := buffer.WriteTo(conn)
	if err != nil {
		return err
	}

	// simulate process header
	time.Sleep(time.Duration(48) * time.Microsecond)

	// write headers and window update
	size := 384 + int(binary.BigEndian.Uint32(preface)%256)
	if rand.Intn(8+rand.Intn(10)) == 0 {
		size += rand.Intn(128)
	}
	err = sendPaddingDataBlock(conn, size)
	if err != nil {
		return err
	}

	// discard server settings
	// # WARNING not use io.CopyN because of too large
	// under buffer that will receive the next frames.
	buf := make([]byte, srvSettingsSize)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return err
	}
	// send client acknowledge
	_, err = conn.Write(bytes.Repeat([]byte{0x00}, cliAcknowledgeSize))
	if err != nil {
		return err
	}
	// discard server acknowledge and window update
	_, err = io.CopyN(io.Discard, conn, srvAcknowledgeSize+srvWindowUpdateSize)
	if err != nil {
		return err
	}

	// discard processed header
	err = receivePaddingData(conn)
	if err != nil {
		return err
	}

	// discard the first data block
	err = receivePaddingData(conn)
	if err != nil {
		return err
	}
	return nil
}

func simulateHTTP2Server(conn net.Conn, preface []byte) error {
	rand := newMathRand()

	// discard preface + settings + window update
	size := 0
	size += http2PrefaceSize
	size += cliSettingsSize
	size += cliWindowUpdateSize
	_, err := io.CopyN(io.Discard, conn, int64(size))
	if err != nil {
		return err
	}

	// discard headers and window update
	err = receivePaddingData(conn)
	if err != nil {
		return err
	}

	// prepare data before write
	set := bytes.Repeat([]byte{0x00}, srvSettingsSize)
	acw := bytes.Repeat([]byte{0x00}, srvAcknowledgeSize+srvWindowUpdateSize)
	// send server settings
	_, err = conn.Write(set)
	if err != nil {
		return err
	}
	// send server acknowledge and window update
	_, err = conn.Write(acw)
	if err != nil {
		return err
	}

	// simulate process header
	time.Sleep(time.Duration(1200+rand.Intn(1000+rand.Intn(1000))) * time.Microsecond)

	// send processed header
	size = 64 + int(binary.BigEndian.Uint32(preface)%256)
	if rand.Intn(8+rand.Intn(10)) == 0 {
		size += rand.Intn(64)
	}
	err = sendPaddingDataBlock(conn, size)
	if err != nil {
		return err
	}

	// send the first data block
	size = 648 + int(binary.BigEndian.Uint32(preface)%256)
	if rand.Intn(8+rand.Intn(10)) == 0 {
		size += rand.Intn(512)
	}
	err = sendPaddingDataBlock(conn, size)
	if err != nil {
		return err
	}

	// discard client acknowledge
	_, err = io.CopyN(io.Discard, conn, cliAcknowledgeSize)
	if err != nil {
		return err
	}
	return nil
}

// +--------+---------+
// |  size  | padding |
// +--------+---------+
// | uint16 |   var   |
// +--------+---------+

func sendPaddingDataBlock(conn net.Conn, size int) error {
	buf := bytes.NewBuffer(make([]byte, 0, 2+size))
	buf.Write(binary.BigEndian.AppendUint16(nil, uint16(size))) // #nosec G115
	buf.Write(bytes.Repeat([]byte{0x00}, size))
	_, err := buf.WriteTo(conn)
	return err
}

func receivePaddingData(conn net.Conn) error {
	buf := make([]byte, 2)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return err
	}
	size := int(binary.BigEndian.Uint16(buf))
	_, err = io.CopyN(io.Discard, conn, int64(size))
	return err
}
