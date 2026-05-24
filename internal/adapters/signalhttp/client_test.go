package signalhttp

import (
	"net/netip"
	"testing"
	"time"

	"webhookery/internal/ssrf"
	"webhookery/pkg/verifier"
)

func TestBuildRequestSignsExactSignalBytes(t *testing.T) {
	client := Client{
		SSRF: ssrf.Validator{Resolver: ssrf.StaticResolver{
			"signals.example": {netip.MustParseAddr("93.184.216.34")},
		}},
		Now: func() time.Time { return time.Unix(1710000000, 0).UTC() },
	}
	body := []byte(`{"type":"alert.opened","value":"snowman"}`)
	req, err := client.BuildRequest("https://signals.example/hook", body, []byte("0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	expected := "t=1710000000,v1=" + verifier.SignHMACSHA256Hex([]byte("0123456789abcdef"), []byte("1710000000."+string(body)))
	if got := req.Header.Get("Webhookery-Signal-Signature"); got != expected {
		t.Fatalf("unexpected signature: got %q want %q", got, expected)
	}
	if got := req.Header.Get("Webhookery-Signal-Timestamp"); got != "1710000000" {
		t.Fatalf("unexpected timestamp: %q", got)
	}
}

func TestBuildRequestBlocksSSRFUnsafeURLs(t *testing.T) {
	client := Client{}
	if _, err := client.BuildRequest("http://169.254.169.254/latest", []byte("{}"), []byte("secret")); err == nil {
		t.Fatal("expected unsafe signal URL to be blocked")
	}
}
