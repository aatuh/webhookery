package crypto

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestEnvelopeEncryptsAndDecrypts(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	box, err := NewEnvelope(key)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := box.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte("secret")) {
		t.Fatal("ciphertext contains plaintext")
	}
	plain, err := box.Decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != "secret" {
		t.Fatalf("unexpected plaintext: %q", plain)
	}
}
