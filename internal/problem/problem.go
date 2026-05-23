package problem

type Problem struct {
	Type      string  `json:"type"`
	Title     string  `json:"title"`
	Status    int     `json:"status"`
	Detail    string  `json:"detail,omitempty"`
	Code      string  `json:"code"`
	RequestID string  `json:"request_id"`
	Fields    []Field `json:"fields,omitempty"`
	Retryable bool    `json:"retryable"`
}

type Field struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

func New(status int, code, title, detail, requestID string, retryable bool) Problem {
	return Problem{
		Type:      "https://docs.webhookery.local/errors/" + code,
		Title:     title,
		Status:    status,
		Detail:    detail,
		Code:      code,
		RequestID: requestID,
		Retryable: retryable,
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
