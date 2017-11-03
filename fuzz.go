// +build gofuzz

package fernet

import (
	"encoding/binary"
	"time"
)

// See https://github.com/dvyukov/go-fuzz
func Fuzz(data []byte) int {
	const (
		timestampLen = 8
		secretOffset = timestampLen
		secretLen    = ((4 * 32 / 3) + 3) &^ 3
		tokenOffset  = timestampLen + secretLen
		minBytes     = timestampLen + secretLen + 1
		ttl          = 24 * 30 * time.Hour
	)
	if len(data) < minBytes {
		return -1 // don't bother
	}
	var (
		now    = time.Unix(int64(binary.BigEndian.Uint64(data)), 0)
		secret = string(data[secretOffset : secretOffset+secretLen])
		token  = string(data[tokenOffset:])
	)
	_, err := Decrypt(token, secret, now, ttl)
	if err != nil {
		return 0 // reject
	}
	return 1 // explore
}
