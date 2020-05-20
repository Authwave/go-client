package authwave

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/nacl/secretbox"
)

type InitVector [24]byte

func NewInitVector() (InitVector, error) {
	var iv InitVector
	_, err := rand.Read(iv[:])
	return iv, err
}
func (iv InitVector) String() string   { return base64.StdEncoding.EncodeToString(iv[:]) }
func (iv InitVector) GetBytes() []byte { return append([]byte(nil), iv[:]...) }
func (iv InitVector) WithBytes(value []byte) (InitVector, error) {
	if len(value) != 24 {
		return InitVector{}, fmt.Errorf("authwave: IV must contain 24 bytes")
	}
	copy(iv[:], value)
	return iv, nil
}

type CipherText []byte

func (c CipherText) String() string   { return base64.StdEncoding.EncodeToString(c) }
func (c CipherText) GetBytes() []byte { return append([]byte(nil), c...) }
func Encrypt(data string, iv InitVector, secret string) (CipherText, error) {
	if len(secret) != 32 {
		return nil, ErrEncryptionFailure
	}
	var key [32]byte
	copy(key[:], secret)
	return CipherText(secretbox.Seal(nil, []byte(data), (*[24]byte)(&iv), &key)), nil
}
func Decrypt(data string, iv InitVector, secret string) (string, error) {
	if len(secret) != 32 {
		return "", ErrDecryptionFailure
	}
	cipher, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", ErrDecryptionFailure
	}
	var key [32]byte
	copy(key[:], secret)
	plain, ok := secretbox.Open(nil, cipher, (*[24]byte)(&iv), &key)
	if !ok {
		return "", ErrDecryptionFailure
	}
	return string(plain), nil
}
