package objectstore

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"webhookery/internal/blobstore"
)

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

func TestS3StorePutGetDeleteUsesDefaultBucketAndMetadata(t *testing.T) {
	var seen []string
	var putBody string
	var putSHA string
	var putContentType string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.URL.Query()["location"]; ok {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(`<LocationConstraint></LocationConstraint>`))
			return
		}
		seen = append(seen, r.Method+" "+r.URL.Path)
		switch r.Method {
		case http.MethodPut:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			putBody = string(body)
			putSHA = r.Header.Get("X-Amz-Meta-Webhookery-Sha256")
			putContentType = r.Header.Get("Content-Type")
			w.Header().Set("ETag", `"etag"`)
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			w.Header().Set("Last-Modified", "Thu, 28 May 2026 09:00:00 GMT")
			w.Header().Set("ETag", `"etag"`)
			_, _ = w.Write([]byte("stored raw body"))
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		case http.MethodHead:
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected method %s", r.Method)
		}
	}))
	defer server.Close()

	store, err := NewS3Store(S3Config{
		Endpoint:  strings.TrimPrefix(server.URL, "http://"),
		AccessKey: "access",
		SecretKey: "secret",
		Bucket:    "default-bucket",
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if err := store.Put(ctx, blobstore.Object{Key: "raw/event.bin", ContentType: "application/json", SHA256: "sha256:test"}, []byte(`{"ok":true}`)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(putBody, `{"ok":true}`) || putSHA != "sha256:test" || putContentType != "application/json" {
		t.Fatalf("unexpected put request body=%q sha=%q content-type=%q", putBody, putSHA, putContentType)
	}
	body, err := store.Get(ctx, "", "raw/event.bin")
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "stored raw body" {
		t.Fatalf("unexpected get body %q", string(body))
	}
	if err := store.Delete(ctx, "", "raw/event.bin"); err != nil {
		t.Fatal(err)
	}

	want := []string{
		"PUT /default-bucket/raw/event.bin",
		"GET /default-bucket/raw/event.bin",
		"DELETE /default-bucket/raw/event.bin",
	}
	if strings.Join(seen, "\n") != strings.Join(want, "\n") {
		t.Fatalf("unexpected S3 requests:\ngot:\n%s\nwant:\n%s", strings.Join(seen, "\n"), strings.Join(want, "\n"))
	}
}

func TestS3StoreUsesObjectBucketOverrideAndMapsNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.URL.Query()["location"]; ok {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(`<LocationConstraint></LocationConstraint>`))
			return
		}
		if r.Method == http.MethodPut {
			if r.URL.Path != "/override-bucket/raw/event.bin" {
				t.Fatalf("expected explicit bucket path, got %s", r.URL.Path)
			}
			w.Header().Set("ETag", `"etag"`)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>NoSuchKey</Code><Message>missing</Message></Error>`))
	}))
	defer server.Close()

	store, err := NewS3Store(S3Config{
		Endpoint:  strings.TrimPrefix(server.URL, "http://"),
		AccessKey: "access",
		SecretKey: "secret",
		Bucket:    "default-bucket",
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if err := store.Put(ctx, blobstore.Object{Bucket: "override-bucket", Key: "raw/event.bin"}, []byte("raw")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, "", "missing.bin"); !errors.Is(err, blobstore.ErrNotFound) {
		t.Fatalf("expected get not found mapping, got %v", err)
	}
	if err := store.Delete(ctx, "", "missing.bin"); !errors.Is(err, blobstore.ErrNotFound) {
		t.Fatalf("expected delete not found mapping, got %v", err)
	}
}
