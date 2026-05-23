package verifier

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	EncodingHex    = "hex"
	EncodingBase64 = "base64"

	ReasonOK               = "ok"
	ReasonMissingSignature = "missing_signature"
	ReasonMalformedHeader  = "malformed_header"
	ReasonExpiredTimestamp = "expired_timestamp"
	ReasonInvalidSignature = "invalid_signature"
	ReasonUnsupportedAlg   = "unsupported_algorithm"
)

type VerifyTimestampedHMACInput struct {
	Secret          []byte
	RawBody         []byte
	Header          string
	Now             time.Time
	Tolerance       time.Duration
	ExpectedVersion string
	Encoding        string
}

type VerificationResult struct {
	Valid            bool
	Reason           string
	Timestamp        time.Time
	Age              time.Duration
	SignatureVersion string
}

func SignHMACSHA256Hex(secret, payload []byte) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func SignHMACSHA256Base64(secret, payload []byte) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(payload)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func VerifyHMACSHA256Hex(secret, payload []byte, signature string) bool {
	expected := SignHMACSHA256Hex(secret, payload)
	got, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(expected)
	if err != nil {
		return false
	}
	return hmac.Equal(got, want)
}

func VerifyHMACSHA256Base64(secret, payload []byte, signature string) bool {
	expected := SignHMACSHA256Base64(secret, payload)
	got, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false
	}
	want, err := base64.StdEncoding.DecodeString(expected)
	if err != nil {
		return false
	}
	return hmac.Equal(got, want)
}

func TimestampedHeader(version string, ts time.Time, secret, raw []byte) string {
	payload := []byte(fmt.Sprintf("%d.%s", ts.Unix(), raw))
	return fmt.Sprintf("t=%d,%s=%s", ts.Unix(), version, SignHMACSHA256Hex(secret, payload))
}

func VerifyTimestampedHMAC(input VerifyTimestampedHMACInput) VerificationResult {
	values := parseKVHeader(input.Header)
	tsRaw := values["t"]
	if tsRaw == "" {
		return VerificationResult{Reason: ReasonMalformedHeader}
	}
	unix, err := strconv.ParseInt(tsRaw, 10, 64)
	if err != nil {
		return VerificationResult{Reason: ReasonMalformedHeader}
	}
	ts := time.Unix(unix, 0)
	age := input.Now.Sub(ts)
	if age < 0 {
		age = -age
	}
	if input.Tolerance > 0 && age > input.Tolerance {
		return VerificationResult{Reason: ReasonExpiredTimestamp, Timestamp: ts, Age: age}
	}

	version := input.ExpectedVersion
	signature := values[version]
	if signature == "" {
		return VerificationResult{Reason: ReasonMissingSignature, Timestamp: ts, Age: age, SignatureVersion: version}
	}

	payload := []byte(fmt.Sprintf("%d.%s", unix, input.RawBody))
	valid := false
	switch input.Encoding {
	case "", EncodingHex:
		valid = VerifyHMACSHA256Hex(input.Secret, payload, signature)
	case EncodingBase64:
		valid = VerifyHMACSHA256Base64(input.Secret, payload, signature)
	default:
		return VerificationResult{Reason: ReasonUnsupportedAlg, Timestamp: ts, Age: age, SignatureVersion: version}
	}
	if !valid {
		return VerificationResult{Reason: ReasonInvalidSignature, Timestamp: ts, Age: age, SignatureVersion: version}
	}
	return VerificationResult{Valid: true, Reason: ReasonOK, Timestamp: ts, Age: age, SignatureVersion: version}
}

func parseKVHeader(header string) map[string]string {
	values := make(map[string]string)
	for _, part := range strings.Split(header, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || k == "" {
			continue
		}
		values[strings.ToLower(k)] = v
	}
	return values
}
