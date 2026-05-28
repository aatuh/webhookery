package problem

import (
	"encoding/json"
	"testing"
)

func TestProblemDoesNotExposeInternalDetail(t *testing.T) {
	p := Internal("req_123")
	body, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) == "" || contains(string(body), "sql:") || contains(string(body), "panic") {
		t.Fatalf("internal problem leaked unsafe detail: %s", body)
	}
	if p.Status != 500 || p.Code != "internal_error" || p.RequestID != "req_123" {
		t.Fatalf("unexpected internal problem: %+v", p)
	}
}

func TestProblemConstructorsSetStableStatusCodesAndRequestIDs(t *testing.T) {
	tests := []struct {
		name    string
		problem Problem
		status  int
		code    string
		title   string
		detail  string
	}{
		{
			name:    "unauthorized",
			problem: Unauthorized("req_auth"),
			status:  401,
			code:    "authentication_error",
			title:   "Authentication required",
			detail:  "A valid bearer token is required.",
		},
		{
			name:    "forbidden",
			problem: Forbidden("req_forbidden"),
			status:  403,
			code:    "authorization_error",
			title:   "Forbidden",
			detail:  "The authenticated actor is not allowed to perform this action.",
		},
		{
			name:    "bad request",
			problem: BadRequest("req_bad", "invalid_json", "body must be JSON"),
			status:  400,
			code:    "invalid_json",
			title:   "Bad request",
			detail:  "body must be JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.problem.Status != tt.status || tt.problem.Code != tt.code || tt.problem.Title != tt.title || tt.problem.Detail != tt.detail {
				t.Fatalf("unexpected problem: %+v", tt.problem)
			}
			if tt.problem.Type != "https://docs.webhookery.local/errors/"+tt.code {
				t.Fatalf("unexpected type URI %q", tt.problem.Type)
			}
			if tt.problem.RequestID == "" {
				t.Fatal("request id should be preserved")
			}
			if tt.problem.Retryable {
				t.Fatal("client error constructors must not mark problems retryable")
			}
		})
	}
}

func contains(s, needle string) bool {
	for i := 0; i+len(needle) <= len(s); i++ {
		if s[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
