package transform

import "testing"

func TestApplyDeterministicOperations(t *testing.T) {
	input := []byte(`{"id":"evt_1","data":{"email":"a@example.com","amount":42},"metadata":{"source":"stripe"}}`)
	operations := []Operation{
		{Op: "copy", From: "/data/amount", Path: "/data/total"},
		{Op: "redact", Path: "/data/email"},
		{Op: "set", Path: "/metadata/tenant_visible", Value: mustRaw(`true`)},
		{Op: "drop", Path: "/metadata/source"},
	}

	out, err := Apply(input, operations)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"data":{"amount":42,"email":"[REDACTED]","total":42},"id":"evt_1","metadata":{"tenant_visible":true}}`
	if string(out) != want {
		t.Fatalf("unexpected transformed payload:\nwant %s\n got %s", want, out)
	}
}

func TestValidateRejectsProtectedEvidenceFields(t *testing.T) {
	tests := []string{
		`[{"op":"drop","path":"/signature_verified"}]`,
		`[{"op":"drop","path":"/metadata/raw_payload_hash"}]`,
		`[{"op":"set","path":"/metadata/data_sha256","value":"x"}]`,
	}
	for _, raw := range tests {
		if _, err := ParseOperations([]byte(raw)); err == nil {
			t.Fatalf("expected protected field rejection for %s", raw)
		}
	}
}

func TestValidateAllowsPayloadDataIDs(t *testing.T) {
	if _, err := ParseOperations([]byte(`[{"op":"set","path":"/data/id","value":"customer_1"}]`)); err != nil {
		t.Fatalf("data ids should remain transformable: %v", err)
	}
}

func TestApplyDropsArrayElementsDeterministically(t *testing.T) {
	input := []byte(`{"data":{"items":["a","b","c"]}}`)
	operations := []Operation{{Op: "drop", Path: "/data/items/1"}}

	out, err := Apply(input, operations)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"data":{"items":["a","c"]}}`
	if string(out) != want {
		t.Fatalf("unexpected transformed payload: want %s got %s", want, out)
	}
}

func TestApplyRejectsUnknownOperation(t *testing.T) {
	_, err := ParseOperations([]byte(`[{"op":"eval","path":"/data"}]`))
	if err == nil {
		t.Fatal("expected unknown operation rejection")
	}
}

func mustRaw(value string) []byte {
	return []byte(value)
}
