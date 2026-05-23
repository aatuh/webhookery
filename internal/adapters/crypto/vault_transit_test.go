package crypto

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVaultTransitEnvelopeEncryptsAndDecrypts(t *testing.T) {
	var sawToken bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") == "vault-token" {
			sawToken = true
		}
		var req map[string]string
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		switch r.URL.Path {
		case "/v1/transit/encrypt/webhookery":
			plain, err := base64.StdEncoding.DecodeString(req["plaintext"])
			if err != nil {
				t.Fatal(err)
			}
			if string(plain) != "secret" {
				t.Fatalf("unexpected plaintext sent to vault: %q", string(plain))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"ciphertext": "vault:v1:cipher"}})
		case "/v1/transit/decrypt/webhookery":
			if req["ciphertext"] != "vault:v1:cipher" {
				t.Fatalf("unexpected ciphertext sent to vault: %q", req["ciphertext"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"plaintext": base64.StdEncoding.EncodeToString([]byte("secret"))}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	box, err := NewVaultTransitEnvelope(VaultTransitConfig{Address: server.URL, Token: "vault-token", KeyName: "webhookery", Client: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := box.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if string(ciphertext) != "vault-transit:vault:v1:cipher" {
		t.Fatalf("unexpected ciphertext wrapper: %q", string(ciphertext))
	}
	plain, err := box.Decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != "secret" || !sawToken {
		t.Fatalf("unexpected decrypt result=%q sawToken=%v", string(plain), sawToken)
	}
}

func TestVaultTransitEnvelopeErrorsDoNotLeakToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "vault-token appeared in provider body", http.StatusForbidden)
	}))
	defer server.Close()

	box, err := NewVaultTransitEnvelope(VaultTransitConfig{Address: server.URL, Token: "vault-token", KeyName: "webhookery", Client: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = box.Encrypt([]byte("secret"))
	if err == nil {
		t.Fatal("expected vault error")
	}
	if strings.Contains(err.Error(), "vault-token") {
		t.Fatalf("error leaked token: %v", err)
	}
}
