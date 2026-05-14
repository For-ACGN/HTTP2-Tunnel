package h2tunnel

import (
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"math/rand"
	"os"
	"runtime"
	"time"
)

type mathRand = rand.Rand

func newMathRand() *mathRand {
	buf := make([]byte, 8)
	_, err := crand.Read(buf)
	if err != nil {
		hash := sha256.New()
		binary.BigEndian.PutUint64(buf, uint64(time.Now().UnixNano())) // #nosec G115
		hash.Write(buf)
		binary.BigEndian.PutUint64(buf, uint64(os.Getpid())) // #nosec G115
		hash.Write(buf)
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		binary.BigEndian.PutUint64(buf, m.HeapAlloc)
		hash.Write(buf)
		binary.BigEndian.PutUint64(buf, m.NextGC)
		hash.Write(buf)
		binary.BigEndian.PutUint64(buf, uint64(m.NumGC))
		hash.Write(buf)
		buf = hash.Sum(nil)[:8]
	}
	seed := binary.BigEndian.Uint64(buf)
	return rand.New(rand.NewSource(int64(seed))) // #nosec
}
