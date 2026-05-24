package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

const awsKMSPrefix = "aws-kms:v1:"

type AWSKMSClient interface {
	GenerateDataKey(ctx context.Context, params *kms.GenerateDataKeyInput, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error)
	Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

type AWSKMSEnvelope struct {
	keyID  string
	client AWSKMSClient
}

type AWSKMSEnvelopeConfig struct {
	KeyID  string
	Client AWSKMSClient
}

type awsKMSBlob struct {
	KeyID            string            `json:"key_id"`
	EncryptedDataKey string            `json:"encrypted_data_key"`
	Nonce            string            `json:"nonce"`
	Ciphertext       string            `json:"ciphertext"`
	Context          map[string]string `json:"context,omitempty"`
}

func NewAWSKMSEnvelope(cfg AWSKMSEnvelopeConfig) (AWSKMSEnvelope, error) {
	keyID := strings.TrimSpace(cfg.KeyID)
	if keyID == "" || cfg.Client == nil {
		return AWSKMSEnvelope{}, errors.New("aws kms key id and client are required")
	}
	return AWSKMSEnvelope{keyID: keyID, client: cfg.Client}, nil
}

func (e AWSKMSEnvelope) Encrypt(plaintext []byte) ([]byte, error) {
	return e.EncryptWithContext(context.Background(), "", "", plaintext)
}

func (e AWSKMSEnvelope) Decrypt(ciphertext []byte) ([]byte, error) {
	return e.DecryptWithContext(context.Background(), "", "", ciphertext)
}

func (e AWSKMSEnvelope) EncryptWithContext(ctx context.Context, tenantID, purpose string, plaintext []byte) ([]byte, error) {
	encCtx := encryptionContext(tenantID, purpose)
	dataKey, err := e.client.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId:             aws.String(e.keyID),
		KeySpec:           types.DataKeySpecAes256,
		EncryptionContext: encCtx,
	})
	if err != nil {
		return nil, errors.New("aws kms generate data key failed")
	}
	if len(dataKey.Plaintext) != 32 || len(dataKey.CiphertextBlob) == 0 {
		return nil, errors.New("aws kms generate data key returned invalid key material")
	}
	defer zeroBytes(dataKey.Plaintext)
	block, err := aes.NewCipher(dataKey.Plaintext)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	blob := awsKMSBlob{
		KeyID:            e.keyID,
		EncryptedDataKey: base64.StdEncoding.EncodeToString(dataKey.CiphertextBlob),
		Nonce:            base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:       base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, plaintext, nil)),
		Context:          encCtx,
	}
	body, err := json.Marshal(blob)
	if err != nil {
		return nil, err
	}
	return []byte(awsKMSPrefix + base64.StdEncoding.EncodeToString(body)), nil
}

func (e AWSKMSEnvelope) DecryptWithContext(ctx context.Context, tenantID, purpose string, ciphertext []byte) ([]byte, error) {
	wrapped := string(ciphertext)
	if !strings.HasPrefix(wrapped, awsKMSPrefix) {
		return nil, errors.New("unsupported aws kms ciphertext version")
	}
	body, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(wrapped, awsKMSPrefix))
	if err != nil {
		return nil, errors.New("invalid aws kms ciphertext encoding")
	}
	var blob awsKMSBlob
	if err := json.Unmarshal(body, &blob); err != nil {
		return nil, errors.New("invalid aws kms ciphertext metadata")
	}
	encryptedDataKey, err := base64.StdEncoding.DecodeString(blob.EncryptedDataKey)
	if err != nil {
		return nil, errors.New("invalid aws kms encrypted data key")
	}
	nonce, err := base64.StdEncoding.DecodeString(blob.Nonce)
	if err != nil {
		return nil, errors.New("invalid aws kms nonce")
	}
	sealed, err := base64.StdEncoding.DecodeString(blob.Ciphertext)
	if err != nil {
		return nil, errors.New("invalid aws kms payload")
	}
	encCtx := blob.Context
	if len(encCtx) == 0 {
		encCtx = encryptionContext(tenantID, purpose)
	}
	dataKey, err := e.client.Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob:    encryptedDataKey,
		EncryptionContext: encCtx,
	})
	if err != nil {
		return nil, errors.New("aws kms decrypt failed")
	}
	if len(dataKey.Plaintext) != 32 {
		return nil, errors.New("aws kms decrypt returned invalid key material")
	}
	defer zeroBytes(dataKey.Plaintext)
	block, err := aes.NewCipher(dataKey.Plaintext)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, errors.New("invalid aws kms nonce size")
	}
	plain, err := aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, errors.New("aws kms payload decrypt failed")
	}
	return plain, nil
}

func encryptionContext(tenantID, purpose string) map[string]string {
	out := map[string]string{"service": "webhookery"}
	if strings.TrimSpace(tenantID) != "" {
		out["tenant_id"] = strings.TrimSpace(tenantID)
	}
	if strings.TrimSpace(purpose) != "" {
		out["purpose"] = strings.TrimSpace(purpose)
	}
	return out
}

func zeroBytes(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}
