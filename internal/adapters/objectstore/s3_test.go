package objectstore

import "testing"

func TestNewS3StoreRequiresDurableConfiguration(t *testing.T) {
	tests := []S3Config{
		{},
		{Endpoint: "localhost:9000"},
		{Endpoint: "localhost:9000", Bucket: "webhookery"},
	}

	for _, cfg := range tests {
		if _, err := NewS3Store(cfg); err == nil {
			t.Fatalf("expected config error for %+v", cfg)
		}
	}
}

func TestNewS3StoreTrimsBucketAndAcceptsCompleteConfiguration(t *testing.T) {
	store, err := NewS3Store(S3Config{
		Endpoint:  " localhost:9000 ",
		AccessKey: "access",
		SecretKey: "secret",
		Bucket:    " webhookery-raw ",
		Region:    " us-east-1 ",
		UseSSL:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if store.Bucket() != "webhookery-raw" {
		t.Fatalf("bucket was not trimmed: %q", store.Bucket())
	}
}
