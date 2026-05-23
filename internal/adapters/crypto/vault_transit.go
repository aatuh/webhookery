package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const vaultTransitPrefix = "vault-transit:"

type VaultTransitConfig struct {
	Address string
	Token   string
	KeyName string
	Client  *http.Client
}

type VaultTransitEnvelope struct {
	address string
	token   string
	keyName string
	client  *http.Client
}

func NewVaultTransitEnvelope(cfg VaultTransitConfig) (VaultTransitEnvelope, error) {
	address := strings.TrimRight(strings.TrimSpace(cfg.Address), "/")
	token := strings.TrimSpace(cfg.Token)
	keyName := strings.TrimSpace(cfg.KeyName)
	if address == "" || token == "" || keyName == "" {
		return VaultTransitEnvelope{}, errors.New("vault transit address, token, and key name are required")
	}
	parsed, err := url.Parse(address)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return VaultTransitEnvelope{}, errors.New("vault transit address must be an http or https URL")
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return VaultTransitEnvelope{address: address, token: token, keyName: keyName, client: client}, nil
}

func (e VaultTransitEnvelope) Encrypt(plaintext []byte) ([]byte, error) {
	resp, err := e.call("encrypt", map[string]string{
		"plaintext": base64.StdEncoding.EncodeToString(plaintext),
	})
	if err != nil {
		return nil, err
	}
	if resp.Data.Ciphertext == "" {
		return nil, errors.New("vault transit encrypt response missing ciphertext")
	}
	return []byte(vaultTransitPrefix + resp.Data.Ciphertext), nil
}

func (e VaultTransitEnvelope) Decrypt(ciphertext []byte) ([]byte, error) {
	wrapped := string(ciphertext)
	if !strings.HasPrefix(wrapped, vaultTransitPrefix) {
		return nil, errors.New("unsupported vault transit ciphertext version")
	}
	resp, err := e.call("decrypt", map[string]string{
		"ciphertext": strings.TrimPrefix(wrapped, vaultTransitPrefix),
	})
	if err != nil {
		return nil, err
	}
	if resp.Data.Plaintext == "" {
		return nil, errors.New("vault transit decrypt response missing plaintext")
	}
	plaintext, err := base64.StdEncoding.DecodeString(resp.Data.Plaintext)
	if err != nil {
		return nil, errors.New("vault transit decrypt response contained invalid plaintext")
	}
	return plaintext, nil
}

type vaultTransitResponse struct {
	Data struct {
		Ciphertext string `json:"ciphertext"`
		Plaintext  string `json:"plaintext"`
	} `json:"data"`
}

func (e VaultTransitEnvelope) call(operation string, payload map[string]string) (vaultTransitResponse, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return vaultTransitResponse{}, err
	}
	endpoint := e.address + "/v1/transit/" + operation + "/" + url.PathEscape(e.keyName)
	// #nosec G107,G704 -- Vault address is operator configuration validated for scheme and host; response bodies are not included in errors.
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return vaultTransitResponse{}, errors.New("build vault transit request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Token", e.token)
	res, err := e.client.Do(req)
	if err != nil {
		return vaultTransitResponse{}, fmt.Errorf("vault transit %s request failed", operation)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return vaultTransitResponse{}, fmt.Errorf("vault transit %s failed with status %d", operation, res.StatusCode)
	}
	var out vaultTransitResponse
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&out); err != nil {
		return vaultTransitResponse{}, fmt.Errorf("decode vault transit %s response", operation)
	}
	return out, nil
}
