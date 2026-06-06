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

func TestTokenWithoutPrefixReturnsOpaqueToken(t *testing.T) {
	token, err := Token("", 16)
	if err != nil {
		t.Fatal(err)
	}
	if token == "" {
		t.Fatal("expected token without prefix")
	}
	if len(token) > 0 && token[0] == '_' {
		t.Fatalf("token without prefix should not add separator: %q", token)
	}
}
