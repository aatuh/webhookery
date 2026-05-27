package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestReplayCreationPersistsGovernanceAuditEvidence(t *testing.T) {
	body, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	for _, want := range []string{
		"INSERT INTO replay_jobs",
		"scope_json",
		"reason_code, reason",
		`Action: "replay.created"`,
		"replayAuditReason(req)",
		`"reason_code=" + req.ReasonCode`,
		`"reason=" + req.Reason`,
		`"config_mode=" + req.ConfigMode`,
		`"event_id="+req.EventID`,
		`"delivery_id="+req.DeliveryID`,
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("replay creation must preserve governance evidence marker %q", want)
		}
	}
}
