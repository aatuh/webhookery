package httpui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIndexAvoidsPersistentTokenStorage(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	Index().ServeHTTP(rec, req)
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status %d", rec.Code)
	}
	if strings.Contains(body, "localStorage") || strings.Contains(body, "sessionStorage") {
		t.Fatal("operator UI must not persist API keys in browser storage")
	}
	if !strings.Contains(body, "/v1/replay-jobs") || !strings.Contains(body, "/v1/ops/metrics") || !strings.Contains(body, "/v1/audit-chain/head") || !strings.Contains(body, "/v1/notification-channels") || !strings.Contains(body, "/v1/siem-sinks") {
		t.Fatal("operator UI should expose replay, ops, audit chain, and signal egress surfaces")
	}
	for _, want := range []string{"/v1/incidents", "/timeline", "renderEventSearchControls", "showIncidentReport"} {
		if !strings.Contains(body, want) {
			t.Fatalf("operator UI missing investigation surface %q", want)
		}
	}
	if strings.Contains(body, "report_markdown.innerHTML") || strings.Contains(body, "markdown.innerHTML") {
		t.Fatal("incident markdown must not be injected as HTML")
	}
}
