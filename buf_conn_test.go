package msocks

import (
	"bufio"
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBufConn(t *testing.T) {
	testdata := []byte{0x01, 0x02, 0x03, 0x04}

	client, server := net.Pipe()

	go func() {
		_, err := server.Write(testdata)
		require.NoError(t, err)
	}()

	reader := bufio.NewReader(client)

	data, err := reader.Peek(4)
	require.NoError(t, err)
	require.Equal(t, testdata, data)

	bConn := newBufConn(client, reader)
	buf := make([]byte, 4)
	_, err = io.ReadFull(bConn, buf)
	require.NoError(t, err)
	require.Equal(t, testdata, buf)
}
