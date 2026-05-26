package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestSensitiveActionsDoNotIgnoreAuditWriteFailures(t *testing.T) {
	body, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	actions := []string{
		"api_key.revoked",
		"delivery.retry_requested",
		"delivery.canceled",
		"audit_export.downloaded",
		"dead_letter.released",
		"quarantine.approved",
		"quarantine.rejected",
		"replay.paused",
		"replay.resumed",
		"replay.canceled",
	}
	for _, action := range actions {
		for _, line := range strings.Split(source, "\n") {
			if strings.Contains(line, "_ = s.recordAuditEvent(ctx, auditEventInput{") && strings.Contains(line, `Action: "`+action+`"`) {
				t.Fatalf("sensitive action %s must return or transactionally persist audit failures", action)
			}
		}
	}
}
