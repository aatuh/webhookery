package random

import "testing"

func TestTokenHasPrefixAndLength(t *testing.T) {
	token, err := Token("whcp", 24)
	if err != nil {
		t.Fatal(err)
	}
	if len(token) < len("whcp_")+24 {
		t.Fatalf("token too short: %q", token)
	}
	if token[:5] != "whcp_" {
		t.Fatalf("missing prefix: %q", token)
	}
}
