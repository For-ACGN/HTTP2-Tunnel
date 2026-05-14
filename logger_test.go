package h2tunnel

import (
	"errors"
	"os"
	"testing"

	"github.com/For-ACGN/monkey"
	"github.com/stretchr/testify/require"
)

const testLogFile = "testdata/test.log"

func TestLogger(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		defer func() {
			err := os.Remove(testLogFile)
			require.NoError(t, err)
		}()

		lg, err := newLogger(testLogFile)
		require.NoError(t, err)

		lg.Info("info log")
		lg.Infof("%s", "infof log")

		lg.Warning("warning log")
		lg.Warningf("%s", "warningf log")

		lg.Error("error log")
		lg.Errorf("%s", "errorf log")

		lg.Fatal("test func", "fatal log")
		lg.Fatalf("test func", "%s", "fatalf log")

		err = lg.Close()
		require.NoError(t, err)
	})

	t.Run("no file path", func(t *testing.T) {
		lg, err := newLogger("")
		require.NoError(t, err)

		lg.Info("info log")
		lg.Infof("%s", "infof log")

		lg.Warning("warning log")
		lg.Warningf("%s", "warningf log")

		lg.Error("error log")
		lg.Errorf("%s", "errorf log")

		lg.Fatal("test func", "fatal log")
		lg.Fatalf("test func", "%s", "fatalf log")

		err = lg.Close()
		require.NoError(t, err)
	})

	t.Run("failed to make directory", func(t *testing.T) {
		patch := func(string, os.FileMode) error {
			return errors.New("monkey error")
		}
		pg := monkey.Patch(os.MkdirAll, patch)
		defer pg.Unpatch()

		lg, err := newLogger(testLogFile)
		require.EqualError(t, err, "monkey error")
		require.Nil(t, lg)
	})

	t.Run("failed to open file", func(t *testing.T) {
		patch := func(string, int, os.FileMode) (*os.File, error) {
			return nil, errors.New("monkey error")
		}
		pg := monkey.Patch(os.OpenFile, patch)
		defer pg.Unpatch()

		lg, err := newLogger(testLogFile)
		require.EqualError(t, err, "monkey error")
		require.Nil(t, lg)
	})

	t.Run("failed to close file", func(t *testing.T) {
		defer func() {
			err := os.Remove(testLogFile)
			require.NoError(t, err)
		}()

		var file *os.File
		patch := func() error {
			return errors.New("monkey error")
		}
		pg := monkey.PatchMethod(file, "Close", patch)
		defer pg.Unpatch()

		lg, err := newLogger(testLogFile)
		require.NoError(t, err)

		err = lg.Close()
		require.EqualError(t, err, "monkey error")

		pg.Unpatch()
		err = lg.Close()
		require.NoError(t, err)
	})
}
