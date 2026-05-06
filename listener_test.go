package msocks

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestCovertDigest(t *testing.T) {
	secret := []byte("secret")

	rand := newMathRand()
	buf := make([]byte, 32)
	hash := sha256.New()
	var num int
	for i := 0; i < 10000000; i++ {
		rand.Read(buf)
		hash.Write(buf)
		hash.Write(secret)
		digest := hash.Sum(nil)
		if isCovertDigest(digest) {
			fmt.Println(hex.EncodeToString(digest))
			num++
		}
		hash.Reset()
	}
	fmt.Println("num:", num)
}
