package evidence

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"webhookery/internal/auditchain"
	"webhookery/internal/domain"
)

const ManifestSchemaV1 = "webhookery.evidence_bundle.v1"

type Manifest struct {
	SchemaVersion        string                  `json:"schema_version"`
	GeneratedAt          time.Time               `json:"generated_at"`
	TenantIDHash         string                  `json:"tenant_id_hash"`
	BundleID             string                  `json:"bundle_id"`
	ExportID             string                  `json:"export_id,omitempty"`
	TenantID             string                  `json:"-"`
	CreatedAt            time.Time               `json:"-"`
	From                 *time.Time              `json:"from,omitempty"`
	To                   *time.Time              `json:"to,omitempty"`
	IncludedEvents       []string                `json:"included_events"`
	IncludedIncidents    []string                `json:"included_incidents"`
	Hashes               map[string]string       `json:"hashes"`
	IncludeRawPayloads   bool                    `json:"include_raw_payloads"`
	IncludeTimelines     bool                    `json:"include_timelines"`
	IncludePayloadBodies bool                    `json:"include_payload_bodies"`
	RedactionPolicy      ManifestRedactionPolicy `json:"redaction_policy"`
	AuditChain           *AuditChain             `json:"audit_chain,omitempty"`
	NonClaims            []string                `json:"non_claims"`
	Files                []ManifestFile          `json:"files"`
}

type ManifestRedactionPolicy struct {
	TenantIdentifiers string `json:"tenant_identifiers"`
	Secrets           string `json:"secrets"`
	RawPayloadBodies  string `json:"raw_payload_bodies"`
	PayloadBodies     string `json:"payload_bodies"`
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
	manifest = normalizeManifest(manifest)

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
	validateManifest(manifest, &result)
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
		if want, ok := manifest.Hashes[file.Name]; !ok {
			result.Valid = false
			result.Failures = append(result.Failures, "manifest hash missing: "+file.Name)
		} else if want != file.SHA256 {
			result.Valid = false
			result.Failures = append(result.Failures, "manifest hash mismatch: "+file.Name)
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

func normalizeManifest(manifest Manifest) Manifest {
	if manifest.SchemaVersion == "" {
		manifest.SchemaVersion = ManifestSchemaV1
	}
	if manifest.GeneratedAt.IsZero() {
		manifest.GeneratedAt = manifest.CreatedAt
	}
	if manifest.GeneratedAt.IsZero() {
		manifest.GeneratedAt = time.Now().UTC()
	} else {
		manifest.GeneratedAt = manifest.GeneratedAt.UTC()
	}
	if manifest.BundleID == "" {
		manifest.BundleID = manifest.ExportID
	}
	if manifest.TenantIDHash == "" && manifest.TenantID != "" {
		manifest.TenantIDHash = domain.HashSHA256([]byte(manifest.TenantID))
	}
	if manifest.From != nil {
		from := manifest.From.UTC()
		manifest.From = &from
	}
	if manifest.To != nil {
		to := manifest.To.UTC()
		manifest.To = &to
	}
	manifest.IncludedEvents = normalizedStringSet(manifest.IncludedEvents)
	manifest.IncludedIncidents = normalizedStringSet(manifest.IncludedIncidents)
	manifest.Hashes = make(map[string]string, len(manifest.Files))
	for _, file := range manifest.Files {
		manifest.Hashes[file.Name] = file.SHA256
	}
	if manifest.RedactionPolicy == (ManifestRedactionPolicy{}) {
		manifest.RedactionPolicy = defaultRedactionPolicy(manifest.IncludeRawPayloads, manifest.IncludePayloadBodies)
	}
	if len(manifest.NonClaims) == 0 {
		manifest.NonClaims = DefaultNonClaims()
	}
	return manifest
}

func validateManifest(manifest Manifest, result *BundleVerification) {
	if manifest.SchemaVersion != ManifestSchemaV1 {
		result.Valid = false
		result.Failures = append(result.Failures, "unsupported manifest schema_version: "+manifest.SchemaVersion)
	}
	if manifest.BundleID == "" {
		result.Valid = false
		result.Failures = append(result.Failures, "bundle_id is missing")
	}
	if manifest.TenantIDHash == "" {
		result.Valid = false
		result.Failures = append(result.Failures, "tenant_id_hash is missing")
	}
	if len(manifest.NonClaims) == 0 {
		result.Valid = false
		result.Failures = append(result.Failures, "non_claims are missing")
	}
	if manifest.RedactionPolicy == (ManifestRedactionPolicy{}) {
		result.Valid = false
		result.Failures = append(result.Failures, "redaction_policy is missing")
	}
	if manifest.Hashes == nil {
		result.Valid = false
		result.Failures = append(result.Failures, "hashes are missing")
	}
}

func defaultRedactionPolicy(includeRawPayloads, includePayloadBodies bool) ManifestRedactionPolicy {
	rawPayloadBodies := "omitted"
	if includeRawPayloads {
		rawPayloadBodies = "included only when explicitly requested with elevated raw-payload permission"
	}
	payloadBodies := "omitted"
	if includePayloadBodies {
		payloadBodies = "included only when explicitly requested with elevated raw-payload permission"
	}
	return ManifestRedactionPolicy{
		TenantIdentifiers: "tenant identifiers are represented by tenant_id_hash",
		Secrets:           "webhook secrets, provider signatures, bearer tokens, private keys, and credentials are excluded",
		RawPayloadBodies:  rawPayloadBodies,
		PayloadBodies:     payloadBodies,
	}
}

func DefaultNonClaims() []string {
	return []string{
		"Inbound capture does not prove downstream business success.",
		"Webhookery records at-least-once delivery evidence and does not claim exactly-once delivery.",
		"The bundle proves Webhookery evidence observed locally; it does not prove provider-side completeness.",
		"The bundle is not compliance certification, legal evidentiary certification, or managed-service availability evidence.",
	}
}

func normalizedStringSet(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
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
		if errors.Is(err, io.EOF) {
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
			if errors.Is(err, io.EOF) {
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
