// Package fernet implements the Fernet spec (see
// https://github.com/fernet/spec).
package fernet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	version      = 0x80
	keyLen       = 16
	tsOffset     = 1
	tsLen        = 8
	ivOffset     = tsOffset + tsLen
	msgOffset    = ivOffset + aes.BlockSize
	fixedLen     = 1 + tsLen + aes.BlockSize + sha256.Size
	maxClockSkew = time.Hour
)

// Encrypt uses secret to encrypt and sign msg. Use Decrypt to recover
// the original message from the token. secret must be a base64-encoded
// slice of 32 bytes, where the first sixteen bytes are used to sign the
// token and the second sixteen are used to encrypt the message. now
// should generally be set to the current time except during testing.
func Encrypt(msg, secret string, now time.Time) (string, error) {
	return encrypt(msg, secret, now, randomIV)
}

// Accepts a func to set the IV so we can test with a specific vector.
func encrypt(msg, secret string, now time.Time, genIV func([]byte) error) (string, error) {
	// Extract keys from the secret.
	signingKey, encryptionKey, err := extractKeys(secret)
	if err != nil {
		return "", err
	}
	// Allocate the token buffer and fill in version and time.
	tok := make([]byte, paddedLen(len(msg))+fixedLen)
	tok[0] = version
	binary.BigEndian.PutUint64(tok[tsOffset:], uint64(now.Unix()))
	// Generate the IV.
	if err := genIV(tok[ivOffset:]); err != nil {
		return "", fmt.Errorf("fernet: failed to generate IV: %v", err)
	}
	iv := tok[ivOffset : ivOffset+aes.BlockSize]
	// Pad the plaintext and encrypt it in place.
	text := pad(tok[msgOffset:], []byte(msg))
	block, _ := aes.NewCipher(encryptionKey)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(text, text)
	// Compute the HMAC and write to the token.
	macOffset := len(tok) - sha256.Size
	hash := hmac.New(sha256.New, signingKey)
	_, _ = hash.Write(tok[:macOffset])
	hash.Sum(tok[macOffset:macOffset])
	// Base64 encode.
	return base64.URLEncoding.EncodeToString(tok), nil
}

// Decrypt is the reverse of encrypt. Given a token returned by Encrypt,
// the same secret, the current time, and a TTL, returns the original
// message unless either of the following is true: the token has been
// tampered with, or the TTL has elapsed since the token was generated.
func Decrypt(token, secret string, now time.Time, ttl time.Duration) (string, error) {
	// Base64-decode the token.
	tok, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return "", fmt.Errorf("fernet: failed to decode token: %v", err)
	}
	// Extract keys from the secret.
	signingKey, encryptionKey, err := extractKeys(secret)
	if err != nil {
		return "", err
	}
	// To simplify bounds checking, make sure we have enough data.
	if minLen := fixedLen + aes.BlockSize; len(tok) < minLen {
		return "", errors.New("fernet: token is too short")
	}
	// Check the version.
	if tok[0] != version {
		return "", errors.New("fernet: wrong version")
	}
	// Extract the timestamp and ensure token has not expired. The
	// timestamp is a 64-bit big-endian integer.
	t := time.Unix(int64(binary.BigEndian.Uint64(tok[tsOffset:])), 0)
	switch tdiff := now.Sub(t); {
	case tdiff > ttl:
		return "", errors.New("fernet: token has expired")
	case tdiff < -maxClockSkew:
		return "", errors.New("fernet: clock skew")
	}
	var (
		n          = len(tok)
		iv         = tok[ivOffset : ivOffset+aes.BlockSize]
		ciphertext = tok[msgOffset : n-sha256.Size]
		macOffset  = n - sha256.Size
		msgMAC     = tok[macOffset:]
	)
	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		return "", errors.New("fernet: ciphertext is not a multiple of the block size")
	}
	// Verify the HMAC signature.
	var expectedMAC [sha256.Size]byte
	hash := hmac.New(sha256.New, signingKey)
	_, _ = hash.Write(tok[:macOffset])
	hash.Sum(expectedMAC[:0])
	if !hmac.Equal(msgMAC, expectedMAC[0:]) {
		return "", errors.New("fernet: wrong HMAC")
	}
	// Decrypt the ciphertext and return the unpadded message.
	plaintext := make([]byte, len(ciphertext))
	block, _ := aes.NewCipher(encryptionKey)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)
	if p := unpad(plaintext); p != nil {
		return string(p), nil
	}
	return "", errors.New("fernet: invalid padding")
}

// RandomSecret generates a secret suitable for use with Encrypt.
func RandomSecret() (string, error) {
	var b [2 * keyLen]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("fernet: failed to read from rand source: %v", err)
	}
	return base64.URLEncoding.EncodeToString(b[0:]), nil
}

// Pads p using PKCS #7 standard block padding. (See
// http://tools.ietf.org/html/rfc5652#section-6.3)
func pad(q, p []byte) []byte {
	const k = aes.BlockSize
	copy(q, p)
	n := paddedLen(len(p))
	c := byte(n - len(p))
	for i := len(p); i < n; i++ {
		q[i] = c
	}
	return q[:n]
}

// Returns len(pad(p)) when len(p) is n.
func paddedLen(n int) int {
	const k = aes.BlockSize
	return k*(n/k) + k
}

// Reverses pad. Returns nil if any padding bytes are invalid.
func unpad(p []byte) []byte {
	c := p[len(p)-1]
	if int(c) > len(p) {
		return nil
	}
	for i := len(p) - int(c); i < len(p); i++ {
		if p[i] != c {
			return nil
		}
	}
	return p[:len(p)-int(c)]
}

// secret must be base64 encoded and 32 bytes long when decoded. Divides
// it into two 16-byte blocks containing the signing and encrytion keys.
func extractKeys(secret string) (signing, encryption []byte, err error) {
	keys, err := base64.URLEncoding.DecodeString(secret)
	if err != nil {
		return nil, nil, fmt.Errorf("fernet: failed to decode secret: %v", err)
	}
	if len(keys) != 2*keyLen {
		return nil, nil, errors.New("fernet: secret must be 32 bytes")
	}
	return keys[:keyLen], keys[keyLen:], nil
}

// Generates a random initialization vector and writes it to p.
func randomIV(p []byte) error {
	_, err := io.ReadFull(rand.Reader, p[:aes.BlockSize])
	return err
}
