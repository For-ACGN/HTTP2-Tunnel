package h2tunnel

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func testNewAEAD(t *testing.T) cipher.AEAD {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	return aead
}

func TestDataFrame(t *testing.T) {
	var id sessionID

	t.Run("common", func(t *testing.T) {
		aead := testNewAEAD(t)
		plaintext := []byte("hello, world! this is a secret message.")
		frame1 := newDataFrame(id, aead)
		frame1.Data = plaintext

		var buf bytes.Buffer
		err := frame1.Encode(&buf)
		require.NoError(t, err)

		frame2 := newDataFrame(id, aead)
		err = frame2.Decode(&buf)
		require.NoError(t, err)
		require.Equal(t, plaintext, frame2.Data)
	})

	t.Run("empty plaintext", func(t *testing.T) {
		aead := testNewAEAD(t)
		frame1 := newDataFrame(id, aead)
		frame1.Data = []byte{}

		var buf bytes.Buffer
		err := frame1.Encode(&buf)
		require.NoError(t, err)

		frame2 := newDataFrame(id, aead)
		err = frame2.Decode(&buf)
		require.NoError(t, err)
		require.Empty(t, frame2.Data)
	})

	t.Run("large payload", func(t *testing.T) {
		aead := testNewAEAD(t)
		plaintext := make([]byte, 16*1024)
		_, err := rand.Read(plaintext)
		require.NoError(t, err)

		frame1 := newDataFrame(id, aead)
		frame1.Data = plaintext

		var buf bytes.Buffer
		err = frame1.Encode(&buf)
		require.NoError(t, err)

		frame2 := newDataFrame(id, aead)
		err = frame2.Decode(&buf)
		require.NoError(t, err)
		require.Equal(t, plaintext, frame2.Data)
	})

	t.Run("tampered ciphertext", func(t *testing.T) {
		aead := testNewAEAD(t)
		frame1 := newDataFrame(id, aead)
		frame1.Data = []byte("integrity test")

		var buf bytes.Buffer
		err := frame1.Encode(&buf)
		require.NoError(t, err)

		data := buf.Bytes()
		data[len(data)-1]++

		frame2 := newDataFrame(id, aead)
		err = frame2.Decode(bytes.NewReader(data))
		require.Contains(t, err.Error(), "failed to decrypt")
	})

	t.Run("invalid frame type", func(t *testing.T) {
		aead := testNewAEAD(t)
		frame1 := newDataFrame(id, aead)

		var buf bytes.Buffer
		buf.WriteByte(framePing)
		buf.Write(id[:])
		buf.Write([]byte{0x00, 0x00})

		err := frame1.Decode(&buf)
		require.Contains(t, err.Error(), "invalid frame type")
	})
}
