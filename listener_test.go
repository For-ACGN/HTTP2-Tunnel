package msocks

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"testing"
	"time"
)

func TestCovertDigest(t *testing.T) {
	rd := rand.New(rand.NewSource(time.Now().Unix()))
	buf := make([]byte, 32)
	h := sha256.New()
	for i := 0; i < 10000000; i++ {
		rd.Read(buf)
		h.Write(buf)
		h.Write(buf)
		digest := h.Sum(nil)
		if isCovertDigest(digest) {
			fmt.Println(hex.EncodeToString(digest))
		}
		h.Reset()
	}
}
