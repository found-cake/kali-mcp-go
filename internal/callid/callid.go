package callid

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
)

const (
	prefix       = "call_"
	randomBytes  = 16
	encodedBytes = randomBytes * 2
)

func New() (string, error) {
	raw := make([]byte, randomBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(raw), nil
}

func Valid(value string) bool {
	if len(value) != len(prefix)+encodedBytes || !strings.HasPrefix(value, prefix) {
		return false
	}
	var decoded [randomBytes]byte
	_, err := hex.Decode(decoded[:], []byte(value[len(prefix):]))
	return err == nil
}
