package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"

	"webhookery/internal/blobstore"
	"webhookery/internal/domain"
)

func TestPrepareRawPayloadStorageWritesObjectInS3Mode(t *testing.T) {
	store := &Store{
		rawStorageMode: domain.RawStorageS3,
		objectStore:    &fakeObjectStore{},
		objectBucket:   "webhookery-test",
	}
	raw := domain.RawPayload{
		SHA256:      domain.HashSHA256([]byte("payload")),
		ContentType: "application/json",
		SizeBytes:   int64(len("payload")),
		Body:        []byte("payload"),
	}

	storage, bodyForDB, err := store.prepareRawPayloadStorage(context.Background(), "ten_1", "raw_1", raw)
	if err != nil {
		t.Fatal(err)
	}
	if storage.backend != domain.RawStorageS3 || storage.bucket != "webhookery-test" || storage.key == "" {
		t.Fatalf("unexpected storage metadata: %+v", storage)
	}
	if len(bodyForDB) != 0 {
		t.Fatalf("s3 mode must not persist raw body in postgres, got %d bytes", len(bodyForDB))
	}
}

func TestPrepareRawPayloadStoragePropagatesObjectWriteFailure(t *testing.T) {
	putErr := errors.New("put failed with whsec_secret and evt_body_secret")
	store := &Store{
		rawStorageMode: domain.RawStorageS3,
		objectStore:    &fakeObjectStore{putErr: putErr},
		objectBucket:   "webhookery-test",
	}
	raw := domain.RawPayload{SHA256: domain.HashSHA256([]byte("payload")), Body: []byte("payload")}

	_, _, err := store.prepareRawPayloadStorage(context.Background(), "ten_1", "raw_1", raw)
	if !errors.Is(err, putErr) {
		t.Fatalf("expected put error, got %v", err)
	}
	if strings.Contains(err.Error(), "whsec_secret") || strings.Contains(err.Error(), "evt_body_secret") {
		t.Fatalf("storage error leaked sensitive backend detail: %v", err)
	}
}

func TestPrepareRawPayloadStorageKeepsBodyInPostgresMode(t *testing.T) {
	store := &Store{rawStorageMode: domain.RawStoragePostgres}
	raw := domain.RawPayload{Body: []byte("payload")}

	storage, bodyForDB, err := store.prepareRawPayloadStorage(context.Background(), "ten_1", "raw_1", raw)
	if err != nil {
		t.Fatal(err)
	}
	if storage.backend != domain.RawStoragePostgres {
		t.Fatalf("backend=%q want postgres", storage.backend)
	}
	if string(bodyForDB) != "payload" {
		t.Fatalf("bodyForDB=%q want payload", string(bodyForDB))
	}
}

type fakeObjectStore struct {
	putErr    error
	getErr    error
	deleteErr error
	objects   map[string][]byte
}

func (f *fakeObjectStore) Put(_ context.Context, object blobstore.Object, body []byte) error {
	if f.putErr != nil {
		return f.putErr
	}
	if f.objects == nil {
		f.objects = map[string][]byte{}
	}
	f.objects[object.Bucket+"/"+object.Key] = append([]byte(nil), body...)
	return nil
}

func (f *fakeObjectStore) Get(_ context.Context, bucket, key string) ([]byte, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	body, ok := f.objects[bucket+"/"+key]
	if !ok {
		return nil, blobstore.ErrNotFound
	}
	return append([]byte(nil), body...), nil
}

func (f *fakeObjectStore) Delete(_ context.Context, bucket, key string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	delete(f.objects, bucket+"/"+key)
	return nil
}
