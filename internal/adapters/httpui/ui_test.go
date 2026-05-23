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
	if !strings.Contains(body, "/v1/replay-jobs") || !strings.Contains(body, "/v1/ops/metrics") {
		t.Fatal("operator UI should expose replay and ops surfaces")
	}
}
