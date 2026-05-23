package objectstore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"webhookery/internal/blobstore"
)

type S3Config struct {
	Endpoint  string
	AccessKey string
	SecretKey string
	Bucket    string
	Region    string
	UseSSL    bool
}

type S3Store struct {
	client *minio.Client
	bucket string
}

func NewS3Store(cfg S3Config) (*S3Store, error) {
	if strings.TrimSpace(cfg.Endpoint) == "" {
		return nil, errors.New("object storage endpoint is required")
	}
	if strings.TrimSpace(cfg.Bucket) == "" {
		return nil, errors.New("object storage bucket is required")
	}
	if cfg.AccessKey == "" || cfg.SecretKey == "" {
		return nil, errors.New("object storage access key and secret key are required")
	}
	client, err := minio.New(strings.TrimSpace(cfg.Endpoint), &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseSSL,
		Region: strings.TrimSpace(cfg.Region),
	})
	if err != nil {
		return nil, err
	}
	return &S3Store{client: client, bucket: strings.TrimSpace(cfg.Bucket)}, nil
}

func (s *S3Store) Bucket() string {
	return s.bucket
}

func (s *S3Store) Put(ctx context.Context, object blobstore.Object, body []byte) error {
	bucket := object.Bucket
	if bucket == "" {
		bucket = s.bucket
	}
	opts := minio.PutObjectOptions{
		ContentType: object.ContentType,
		UserMetadata: map[string]string{
			"webhookery-sha256": object.SHA256,
		},
	}
	_, err := s.client.PutObject(ctx, bucket, object.Key, bytes.NewReader(body), int64(len(body)), opts)
	return err
}

func (s *S3Store) Get(ctx context.Context, bucket, key string) ([]byte, error) {
	if bucket == "" {
		bucket = s.bucket
	}
	obj, err := s.client.GetObject(ctx, bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	defer func() { _ = obj.Close() }()
	body, err := io.ReadAll(obj)
	if err != nil {
		resp := minio.ToErrorResponse(err)
		if resp.Code == "NoSuchKey" || resp.Code == "NoSuchBucket" {
			return nil, blobstore.ErrNotFound
		}
		return nil, err
	}
	return body, nil
}

func (s *S3Store) Delete(ctx context.Context, bucket, key string) error {
	if bucket == "" {
		bucket = s.bucket
	}
	err := s.client.RemoveObject(ctx, bucket, key, minio.RemoveObjectOptions{})
	if err != nil {
		resp := minio.ToErrorResponse(err)
		if resp.Code == "NoSuchKey" || resp.Code == "NoSuchBucket" {
			return blobstore.ErrNotFound
		}
	}
	return err
}
