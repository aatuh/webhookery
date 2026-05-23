package evidence

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"
)

type Manifest struct {
	ExportID             string         `json:"export_id"`
	TenantID             string         `json:"tenant_id"`
	CreatedAt            time.Time      `json:"created_at"`
	From                 time.Time      `json:"from,omitempty"`
	To                   time.Time      `json:"to,omitempty"`
	IncludeRawPayloads   bool           `json:"include_raw_payloads"`
	IncludeTimelines     bool           `json:"include_timelines"`
	IncludePayloadBodies bool           `json:"include_payload_bodies"`
	Files                []ManifestFile `json:"files"`
}

type ManifestFile struct {
	Name      string `json:"name"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

type Bundle struct {
	Bytes          []byte
	Manifest       []byte
	ManifestSHA256 string
	BundleSHA256   string
	Files          []ManifestFile
}

func JSONLines(items []any) ([]byte, error) {
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	for _, item := range items {
		if err := enc.Encode(item); err != nil {
			return nil, err
		}
	}
	return out.Bytes(), nil
}

func BuildTarGzipBundle(manifest Manifest, files map[string][]byte) (Bundle, error) {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	manifest.Files = make([]ManifestFile, 0, len(names))
	for _, name := range names {
		file := files[name]
		manifest.Files = append(manifest.Files, ManifestFile{
			Name:      name,
			SHA256:    SHA256(file),
			SizeBytes: int64(len(file)),
		})
	}

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return Bundle{}, err
	}
	manifestBytes = append(manifestBytes, '\n')

	var out bytes.Buffer
	gz, err := gzip.NewWriterLevel(&out, gzip.BestCompression)
	if err != nil {
		return Bundle{}, err
	}
	gz.Name = "webhookery-evidence-export.tar"
	gz.ModTime = time.Unix(0, 0).UTC()
	tw := tar.NewWriter(gz)
	if err := writeTarFile(tw, "manifest.json", manifestBytes); err != nil {
		return Bundle{}, err
	}
	for _, name := range names {
		if err := writeTarFile(tw, name, files[name]); err != nil {
			return Bundle{}, err
		}
	}
	if err := tw.Close(); err != nil {
		return Bundle{}, err
	}
	if err := gz.Close(); err != nil {
		return Bundle{}, err
	}
	return Bundle{
		Bytes:          out.Bytes(),
		Manifest:       manifestBytes,
		ManifestSHA256: SHA256(manifestBytes),
		BundleSHA256:   SHA256(out.Bytes()),
		Files:          manifest.Files,
	}, nil
}

func SHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func writeTarFile(tw *tar.Writer, name string, data []byte) error {
	if name == "" {
		return fmt.Errorf("tar entry name is required")
	}
	if err := tw.WriteHeader(&tar.Header{
		Name:    name,
		Mode:    0o600,
		Size:    int64(len(data)),
		ModTime: time.Unix(0, 0).UTC(),
	}); err != nil {
		return err
	}
	if _, err := io.Copy(tw, bytes.NewReader(data)); err != nil {
		return err
	}
	return nil
}
