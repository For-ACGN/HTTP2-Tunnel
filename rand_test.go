package h2tunnel

import (
	"fmt"
	"testing"
)

func TestNewMathRand(t *testing.T) {
	rand := newMathRand()
	fmt.Println(rand.Int())
}
