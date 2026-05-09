package msocks

import (
	"bytes"
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
		hash.Reset()
		hash.Write(buf)
		hash.Write(secret)
		digest := hash.Sum(nil)
		if isCovertDigest(digest) {
			fmt.Println(hex.EncodeToString(digest))
			num++
		}
	}
	fmt.Println("num:", num)
}

func TestRandomBitDistribution(t *testing.T) {
	const numSample = 1000

	rand := newMathRand()
	buf := make([]byte, 32)
	hash := sha256.New()
	random := make([][]byte, 0, numSample)
	var num int
	for {
		rand.Read(buf)
		hash.Reset()
		hash.Write(buf)
		hash.Write([]byte("secret"))
		digest := hash.Sum(nil)
		if isCovertDigest(digest) {
			random = append(random, bytes.Clone(buf))
			num++
		}
		if num >= numSample {
			break
		}
	}

	var bitCount [256][2]uint64
	for _, value := range random {
		for i := 0; i < 32; i++ {
			b := value[i]
			for bit := 0; bit < 8; bit++ {
				bitIdx := i*8 + bit
				v := (b >> (7 - bit)) & 1
				if v == 0 {
					bitCount[bitIdx][0]++
				} else {
					bitCount[bitIdx][1]++
				}
			}
		}
	}

	for i := 0; i < 256; i++ {
		zero := bitCount[i][0]
		one := bitCount[i][1]
		ratio := float64(one) / float64(zero+one) * 100
		format := "bit[%03d]  0=%-8d 1=%-8d  ratio=%.2f%%\n"
		fmt.Printf(format, i, zero, one, ratio)
	}
}
