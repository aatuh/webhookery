package app

import (
	"testing"

	"webhookery/internal/domain"
)

func TestAdapterTransitionStateMapsGovernedActions(t *testing.T) {
	tests := map[string]string{
		"submit_tests":    domain.AdapterStateAutomatedTests,
		"request_review":  domain.AdapterStateSecurityReview,
		"approve_staging": domain.AdapterStateStagingApproved,
		"activate":        domain.AdapterStateActive,
		"deprecate":       domain.AdapterStateDeprecated,
		"retire":          domain.AdapterStateRetired,
	}
	for action, want := range tests {
		t.Run(action, func(t *testing.T) {
			got, ok := adapterTransitionState(action)
			if !ok || got != want {
				t.Fatalf("adapterTransitionState(%q)=%q,%v want %q,true", action, got, ok, want)
			}
		})
	}
	if got, ok := adapterTransitionState("skip_review"); ok || got != "" {
		t.Fatalf("unexpected unsupported action mapping: %q %v", got, ok)
	}
}
