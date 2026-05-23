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
