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
	"strings"
	"time"

	"webhookery/internal/auditchain"
	"webhookery/internal/domain"
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
	AuditChain           *AuditChain    `json:"audit_chain,omitempty"`
	Files                []ManifestFile `json:"files"`
}

type AuditChain struct {
	FromSequence   int64              `json:"from_sequence"`
	ToSequence     int64              `json:"to_sequence"`
	StartChainHash string             `json:"start_chain_hash,omitempty"`
	EndChainHash   string             `json:"end_chain_hash,omitempty"`
	Anchors        []AuditChainAnchor `json:"anchors,omitempty"`
}

type AuditChainAnchor struct {
	ID             string `json:"id"`
	FromSequence   int64  `json:"from_sequence"`
	ToSequence     int64  `json:"to_sequence"`
	ChainHash      string `json:"chain_hash"`
	ManifestSHA256 string `json:"manifest_sha256"`
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

type BundleVerification struct {
	Valid               bool     `json:"valid"`
	ManifestSHA256      string   `json:"manifest_sha256"`
	CheckedFiles        int      `json:"checked_files"`
	CheckedChainEntries int      `json:"checked_chain_entries"`
	Failures            []string `json:"failures"`
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

func VerifyTarGzipBundle(body []byte) (BundleVerification, error) {
	result := BundleVerification{Valid: true}
	files, err := readTarGzipFiles(body)
	if err != nil {
		return BundleVerification{}, err
	}
	manifestBytes, ok := files["manifest.json"]
	if !ok {
		result.Valid = false
		result.Failures = append(result.Failures, "manifest.json is missing")
		return result, nil
	}
	result.ManifestSHA256 = SHA256(manifestBytes)
	var manifest Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return BundleVerification{}, err
	}
	for _, file := range manifest.Files {
		body, ok := files[file.Name]
		if !ok {
			result.Valid = false
			result.Failures = append(result.Failures, "missing file: "+file.Name)
			continue
		}
		result.CheckedFiles++
		if got := SHA256(body); got != file.SHA256 {
			result.Valid = false
			result.Failures = append(result.Failures, "hash mismatch: "+file.Name)
		}
		if int64(len(body)) != file.SizeBytes {
			result.Valid = false
			result.Failures = append(result.Failures, "size mismatch: "+file.Name)
		}
	}
	if proof, ok := files["audit_chain_proof.jsonl"]; ok {
		failures, checked, err := verifyAuditChainProof(proof)
		if err != nil {
			return BundleVerification{}, err
		}
		result.CheckedChainEntries = checked
		if len(failures) > 0 {
			result.Valid = false
			result.Failures = append(result.Failures, failures...)
		}
	}
	return result, nil
}

func SHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func readTarGzipFiles(body []byte) (map[string][]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	files := map[string][]byte{}
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		if header.Name == "" || strings.HasPrefix(header.Name, "/") || strings.Contains(header.Name, "..") {
			return nil, fmt.Errorf("unsafe tar entry name: %s", header.Name)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		files[header.Name] = data
	}
	return files, nil
}

func verifyAuditChainProof(raw []byte) ([]string, int, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var failures []string
	var previous string
	var expectedSequence int64
	checked := 0
	for {
		var entry domain.AuditChainEntry
		if err := dec.Decode(&entry); err != nil {
			if err == io.EOF {
				break
			}
			return nil, checked, err
		}
		if expectedSequence == 0 {
			expectedSequence = entry.Sequence
		}
		if entry.Sequence != expectedSequence {
			failures = append(failures, fmt.Sprintf("chain proof missing sequence %d", expectedSequence))
			expectedSequence = entry.Sequence
		}
		if entry.PreviousChainHash != auditchain.PreviousHashForSequence(entry.Sequence, previous) {
			failures = append(failures, fmt.Sprintf("chain proof previous hash mismatch at %d", entry.Sequence))
		}
		if got := auditchain.ChainHash(entry.PreviousChainHash, entry.EventHash); got != entry.ChainHash {
			failures = append(failures, fmt.Sprintf("chain proof hash mismatch at %d", entry.Sequence))
		}
		previous = entry.ChainHash
		expectedSequence++
		checked++
	}
	return failures, checked, nil
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
