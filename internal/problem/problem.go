package problem

type Problem struct {
	Type       string  `json:"type"`
	Title      string  `json:"title"`
	Status     int     `json:"status"`
	Detail     string  `json:"detail,omitempty"`
	Code       string  `json:"code"`
	StableCode string  `json:"stable_code"`
	RequestID  string  `json:"request_id"`
	Fields     []Field `json:"fields,omitempty"`
	Retryable  bool    `json:"retryable"`
}

type Field struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

func New(status int, code, title, detail, requestID string, retryable bool) Problem {
	return Problem{
		Type:       "https://docs.webhookery.local/errors/" + code,
		Title:      title,
		Status:     status,
		Detail:     detail,
		Code:       code,
		StableCode: StableCodeFor(code),
		RequestID:  requestID,
		Retryable:  retryable,
	}
}

const (
	CodeAuthenticationRequired         = "WEBHOOKERY_AUTHENTICATION_REQUIRED"
	CodeDurableCaptureUnavailable      = "WEBHOOKERY_DURABLE_CAPTURE_UNAVAILABLE"
	CodeHeadersTooLarge                = "WEBHOOKERY_HEADERS_TOO_LARGE"
	CodeInternalError                  = "WEBHOOKERY_INTERNAL_ERROR"
	CodePayloadTooLarge                = "WEBHOOKERY_PAYLOAD_TOO_LARGE"
	CodeProviderSignatureInvalid       = "WEBHOOKERY_PROVIDER_SIGNATURE_INVALID"
	CodeRawPayloadRetainedMetadataOnly = "WEBHOOKERY_RAW_PAYLOAD_RETAINED_METADATA_ONLY"
	CodeResourceNotFound               = "WEBHOOKERY_RESOURCE_NOT_FOUND"
	CodeSSRFBlockedDestination         = "WEBHOOKERY_SSRF_BLOCKED_DESTINATION"
	CodeTenantAccessDenied             = "WEBHOOKERY_TENANT_ACCESS_DENIED"
	CodeValidationFailed               = "WEBHOOKERY_VALIDATION_FAILED"
	CodeUnknownError                   = "WEBHOOKERY_UNKNOWN_ERROR"
)

func StableCodeFor(code string) string {
	switch code {
	case "authentication_error":
		return CodeAuthenticationRequired
	case "authorization_error":
		return CodeTenantAccessDenied
	case "headers_too_large":
		return CodeHeadersTooLarge
	case "internal_error":
		return CodeInternalError
	case "invalid_signature":
		return CodeProviderSignatureInvalid
	case "not_found":
		return CodeResourceNotFound
	case "not_ready", "storage_unavailable":
		return CodeDurableCaptureUnavailable
	case "payload_expired":
		return CodeRawPayloadRetainedMetadataOnly
	case "payload_too_large":
		return CodePayloadTooLarge
	case "notification_channel_url_blocked", "siem_sink_url_blocked":
		return CodeSSRFBlockedDestination
	case "invalid_json", "invalid_request", "unsupported_grant_type", "validation_error":
		return CodeValidationFailed
	default:
		return CodeUnknownError
	}
}

func Internal(requestID string) Problem {
	return New(500, "internal_error", "Internal server error", "The request could not be completed.", requestID, true)
}

func Unauthorized(requestID string) Problem {
	return New(401, "authentication_error", "Authentication required", "A valid bearer token is required.", requestID, false)
}

func Forbidden(requestID string) Problem {
	return New(403, "authorization_error", "Forbidden", "The authenticated actor is not allowed to perform this action.", requestID, false)
}

func BadRequest(requestID, code, detail string) Problem {
	return New(400, code, "Bad request", detail, requestID, false)
}
