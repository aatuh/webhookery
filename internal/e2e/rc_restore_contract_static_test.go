package e2e

import (
	"os"
	"strings"
	"testing"
)

func TestRCRestoreDrillPreservesEvidenceAuthorityChecks(t *testing.T) {
	rcBody, err := os.ReadFile("rc_e2e_test.go")
	if err != nil {
		t.Fatal(err)
	}
	rcTest := string(rcBody)
	required := map[string]string{
		"restore before migration":               "runRestoreCommand(t, drillCtx, restoreDatabaseURL, dumpFile)",
		"migrate restored database":              "postgres.MigrateUp(drillCtx, restoreDatabaseURL",
		"read restored event evidence":           "restoredControl.GetEvent(drillCtx, actor, result.EventID)",
		"download restored evidence export":      "restoredControl.DownloadAuditExport(drillCtx, actor, export.ID)",
		"verify restored evidence export bundle": "evidence.VerifyTarGzipBundle(download.Body)",
		"prove audit chain entries in bundle":    "verification.CheckedChainEntries == 0",
		"verify restored audit chain":            "restoredControl.VerifyAuditChain(drillCtx, actor, app.AuditChainVerifyRequest{})",
		"compare restored audit chain hash":      "after.EndChainHash != before.EndChainHash",
	}
	for name, want := range required {
		if !strings.Contains(rcTest, want) {
			t.Fatalf("RC restore drill no longer proves %s with %q", name, want)
		}
	}

	rcScript, err := os.ReadFile("../../scripts/rc_acceptance.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(rcScript)
	for _, want := range []string{
		"WEBHOOKERY_RC_RESTORE_DATABASE_URL",
		"WEBHOOKERY_RESTORE_DRILL_DATABASE_URL=\"$WEBHOOKERY_RC_RESTORE_DATABASE_URL\" go test ./internal/e2e -run TestRCRestoreDrill -count=1",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("rc-check no longer wires the restore drill through %q", want)
		}
	}
}
