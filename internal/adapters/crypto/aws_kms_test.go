package crypto

import (
	"bytes"
	"context"
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
