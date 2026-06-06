package crypto

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

func TestAWSKMSEnvelopeEncryptsWithContextAndDecrypts(t *testing.T) {
	client := &fakeKMSClient{plain: bytes.Repeat([]byte{7}, 32)}
	box, err := NewAWSKMSEnvelope(AWSKMSEnvelopeConfig{KeyID: "arn:aws:kms:test:key/1234", Client: client})
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := box.EncryptWithContext(context.Background(), "ten_1", "source_secret", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(ciphertext, []byte(awsKMSPrefix)) {
		t.Fatalf("missing aws kms prefix: %q", ciphertext)
	}
	if client.generateContext["tenant_id"] != "ten_1" || client.generateContext["purpose"] != "source_secret" {
		t.Fatalf("missing encryption context: %+v", client.generateContext)
	}
	plain, err := box.DecryptWithContext(context.Background(), "ten_1", "source_secret", ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != "secret" {
		t.Fatalf("plaintext=%q", plain)
	}
	if client.decryptContext["tenant_id"] != "ten_1" || client.decryptContext["purpose"] != "source_secret" {
		t.Fatalf("missing decrypt context: %+v", client.decryptContext)
	}
}

func TestAWSKMSEnvelopeDefaultMethodsUseServiceContext(t *testing.T) {
	client := &fakeKMSClient{plain: bytes.Repeat([]byte{8}, 32)}
	box, err := NewAWSKMSEnvelope(AWSKMSEnvelopeConfig{KeyID: "key", Client: client})
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := box.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := box.Decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != "secret" {
		t.Fatalf("plaintext=%q", plain)
	}
	if client.generateContext["service"] != "webhookery" || client.generateContext["tenant_id"] != "" || client.generateContext["purpose"] != "" {
		t.Fatalf("unexpected default generate context: %+v", client.generateContext)
	}
	if client.decryptContext["service"] != "webhookery" || client.decryptContext["tenant_id"] != "" || client.decryptContext["purpose"] != "" {
		t.Fatalf("unexpected default decrypt context: %+v", client.decryptContext)
	}
}

func TestAWSKMSEnvelopeErrorsDoNotLeakPlaintext(t *testing.T) {
	client := &fakeKMSClient{err: assertErr{}}
	box, err := NewAWSKMSEnvelope(AWSKMSEnvelopeConfig{KeyID: "key", Client: client})
	if err != nil {
		t.Fatal(err)
	}
	_, err = box.EncryptWithContext(context.Background(), "ten_1", "source_secret", []byte("top-secret"))
	if err == nil {
		t.Fatal("expected kms error")
	}
	if bytes.Contains([]byte(err.Error()), []byte("top-secret")) {
		t.Fatalf("error leaked plaintext: %v", err)
	}
}

func TestAWSKMSEnvelopeRejectsInvalidCiphertextMetadata(t *testing.T) {
	client := &fakeKMSClient{plain: bytes.Repeat([]byte{7}, 32)}
	box, err := NewAWSKMSEnvelope(AWSKMSEnvelopeConfig{KeyID: "key", Client: client})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		ciphertext []byte
		want       string
	}{
		{name: "version", ciphertext: []byte("v0:not-aws-kms"), want: "unsupported aws kms ciphertext version"},
		{name: "wrapper encoding", ciphertext: []byte(awsKMSPrefix + "%%%"), want: "invalid aws kms ciphertext encoding"},
		{name: "json metadata", ciphertext: []byte(awsKMSPrefix + base64.StdEncoding.EncodeToString([]byte("{"))), want: "invalid aws kms ciphertext metadata"},
		{name: "data key", ciphertext: wrapAWSKMSBlob(t, awsKMSBlob{EncryptedDataKey: "!", Nonce: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 12)), Ciphertext: base64.StdEncoding.EncodeToString([]byte("sealed"))}), want: "invalid aws kms encrypted data key"},
		{name: "nonce", ciphertext: wrapAWSKMSBlob(t, awsKMSBlob{EncryptedDataKey: base64.StdEncoding.EncodeToString([]byte("edk")), Nonce: "!", Ciphertext: base64.StdEncoding.EncodeToString([]byte("sealed"))}), want: "invalid aws kms nonce"},
		{name: "payload", ciphertext: wrapAWSKMSBlob(t, awsKMSBlob{EncryptedDataKey: base64.StdEncoding.EncodeToString([]byte("edk")), Nonce: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 12)), Ciphertext: "!"}), want: "invalid aws kms payload"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := box.DecryptWithContext(context.Background(), "ten_1", "source_secret", tt.ciphertext)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected %q, got %v", tt.want, err)
			}
			if strings.Contains(err.Error(), "source_secret") || strings.Contains(err.Error(), "ten_1") {
				t.Fatalf("error leaked context detail: %v", err)
			}
		})
	}
}

func TestAWSKMSEnvelopeRejectsInvalidKeyMaterial(t *testing.T) {
	shortKeyClient := &fakeKMSClient{plain: bytes.Repeat([]byte{7}, 31)}
	box, err := NewAWSKMSEnvelope(AWSKMSEnvelopeConfig{KeyID: "key", Client: shortKeyClient})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := box.EncryptWithContext(context.Background(), "ten_1", "source_secret", []byte("top-secret")); err == nil || !strings.Contains(err.Error(), "invalid key material") || strings.Contains(err.Error(), "top-secret") {
		t.Fatalf("expected redacted invalid generate key material error, got %v", err)
	}

	goodClient := &fakeKMSClient{plain: bytes.Repeat([]byte{9}, 32)}
	goodBox, err := NewAWSKMSEnvelope(AWSKMSEnvelopeConfig{KeyID: "key", Client: goodClient})
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := goodBox.EncryptWithContext(context.Background(), "ten_1", "source_secret", []byte("top-secret"))
	if err != nil {
		t.Fatal(err)
	}
	badDecryptBox, err := NewAWSKMSEnvelope(AWSKMSEnvelopeConfig{KeyID: "key", Client: shortKeyClient})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := badDecryptBox.DecryptWithContext(context.Background(), "ten_1", "source_secret", ciphertext); err == nil || !strings.Contains(err.Error(), "invalid key material") || strings.Contains(err.Error(), "top-secret") {
		t.Fatalf("expected redacted invalid decrypt key material error, got %v", err)
	}
}

func wrapAWSKMSBlob(t *testing.T, blob awsKMSBlob) []byte {
	t.Helper()
	raw, err := json.Marshal(blob)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(awsKMSPrefix + base64.StdEncoding.EncodeToString(raw))
}

type fakeKMSClient struct {
	plain           []byte
	err             error
	generateContext map[string]string
	decryptContext  map[string]string
}

func (f *fakeKMSClient) GenerateDataKey(_ context.Context, params *kms.GenerateDataKeyInput, _ ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.generateContext = params.EncryptionContext
	return &kms.GenerateDataKeyOutput{Plaintext: append([]byte(nil), f.plain...), CiphertextBlob: []byte("encrypted-data-key"), KeyId: aws.String("key")}, nil
}

func (f *fakeKMSClient) Decrypt(_ context.Context, params *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.decryptContext = params.EncryptionContext
	return &kms.DecryptOutput{Plaintext: append([]byte(nil), f.plain...), KeyId: aws.String("key")}, nil
}

type assertErr struct{}

func (assertErr) Error() string { return "kms unavailable" }
