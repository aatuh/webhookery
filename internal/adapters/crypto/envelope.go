package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

type Envelope struct {
	aead cipher.AEAD
}

func NewEnvelope(base64Key string) (Envelope, error) {
	key, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return Envelope{}, fmt.Errorf("decode master key: %w", err)
	}
	if len(key) != 32 {
		return Envelope{}, errors.New("master key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return Envelope{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{aead: aead}, nil
}

func (e Envelope) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	out := append([]byte("v1:"), nonce...)
	out = e.aead.Seal(out, nonce, plaintext, nil)
	return out, nil
}

func (e Envelope) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 3 || string(ciphertext[:3]) != "v1:" {
		return nil, errors.New("unsupported ciphertext version")
	}
	blob := ciphertext[3:]
	if len(blob) < e.aead.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce := blob[:e.aead.NonceSize()]
	sealed := blob[e.aead.NonceSize():]
	return e.aead.Open(nil, nonce, sealed, nil)
}
