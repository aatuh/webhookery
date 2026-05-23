package blobstore

import (
	"context"
	"errors"
	"path"
	"regexp"
	"strings"
)

var ErrNotFound = errors.New("object not found")

type Object struct {
	Bucket      string
	Key         string
	ContentType string
	SHA256      string
	SizeBytes   int64
}

type Store interface {
	Put(ctx context.Context, object Object, body []byte) error
	Get(ctx context.Context, bucket, key string) ([]byte, error)
	Delete(ctx context.Context, bucket, key string) error
}

var safeSegmentPattern = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

func RawPayloadKey(tenantID, rawPayloadID, hash string) string {
	hash = strings.TrimPrefix(hash, "sha256:")
	hash = safeSegment(hash)
	if len(hash) > 16 {
		hash = hash[:16]
	}
	return path.Join("raw-payloads", safeSegment(tenantID), safeSegment(rawPayloadID)+"-"+hash+".bin")
}

func ExportKey(tenantID, exportID string) string {
	return path.Join("evidence-exports", safeSegment(tenantID), safeSegment(exportID)+".tar.gz")
}

func safeSegment(value string) string {
	value = strings.TrimSpace(value)
	value = safeSegmentPattern.ReplaceAllString(value, "_")
	value = strings.Trim(value, "._-/")
	if value == "" {
		return "unknown"
	}
	return value
}
