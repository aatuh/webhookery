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

func contains(s, needle string) bool {
	for i := 0; i+len(needle) <= len(s); i++ {
		if s[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
