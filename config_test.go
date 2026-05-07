package msocks

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/stretchr/testify/require"
)

var (
	testPassword = "test"
	testPassHash string
)

func init() {
	h := sha256.Sum256([]byte(testPassword))
	testPassHash = hex.EncodeToString(h[:])
	fmt.Println("pass hash:", testPassHash)
	// start pprof server
	go func() {
		_ = http.ListenAndServe("localhost:1234", nil)
	}()
}

type testDuration struct {
	Timeout duration `toml:"timeout"`
}

func TestDuration_MarshalText(t *testing.T) {
	d := testDuration{Timeout: duration(time.Second)}

	data, err := toml.Marshal(d)
	require.NoError(t, err)

	expected := "timeout = '1s'\n"
	require.Equal(t, expected, string(data))
}

func TestDuration_UnmarshalText(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		data := []byte("timeout = \"1s\"\n")

		var d testDuration
		err := toml.Unmarshal(data, &d)
		require.NoError(t, err)

		require.Equal(t, time.Second, time.Duration(d.Timeout))
	})

	t.Run("failed to parse duration", func(t *testing.T) {
		data := []byte("timeout = \"1as\"\n")

		var d testDuration
		err := toml.Unmarshal(data, &d)
		errStr := "toml: time: unknown unit \"as\" in duration \"1as\""
		require.EqualError(t, err, errStr)
	})
}
