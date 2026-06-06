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

func TestApplySetsNestedObjectsAndArrayValues(t *testing.T) {
	input := []byte(`{"data":{"items":["a","b"]}}`)
	operations := []Operation{
		{Op: "set", Path: "/data/nested/customer/id", Value: mustRaw(`"cus_1"`)},
		{Op: "set", Path: "/data/items/1", Value: mustRaw(`"updated"`)},
	}

	out, err := Apply(input, operations)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"data":{"items":["a","updated"],"nested":{"customer":{"id":"cus_1"}}}}`
	if string(out) != want {
		t.Fatalf("unexpected transformed payload: want %s got %s", want, out)
	}
}

func TestApplyCanReplaceDocumentRoot(t *testing.T) {
	out, err := Apply([]byte(`{"data":{"old":true}}`), []Operation{{Op: "set", Path: "/", Value: mustRaw(`{"data":{"new":true}}`)}})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"data":{"new":true}}`
	if string(out) != want {
		t.Fatalf("unexpected root replacement: want %s got %s", want, out)
	}
}

func TestApplyCopiesArraysAndObjectsByValue(t *testing.T) {
	input := []byte(`{"data":{"customer":{"email":"a@example.com"},"items":[{"sku":"sku_1"}]}}`)
	operations := []Operation{
		{Op: "copy", From: "/data/customer", Path: "/metadata/customer_snapshot"},
		{Op: "copy", From: "/data/items/0", Path: "/metadata/item_snapshot"},
		{Op: "set", Path: "/data/customer/email", Value: mustRaw(`"changed@example.com"`)},
		{Op: "set", Path: "/data/items/0/sku", Value: mustRaw(`"sku_2"`)},
	}

	out, err := Apply(input, operations)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"data":{"customer":{"email":"changed@example.com"},"items":[{"sku":"sku_2"}]},"metadata":{"customer_snapshot":{"email":"a@example.com"},"item_snapshot":{"sku":"sku_1"}}}`
	if string(out) != want {
		t.Fatalf("unexpected copied payload: want %s got %s", want, out)
	}
}

func TestApplyRejectsUnknownOperation(t *testing.T) {
	_, err := ParseOperations([]byte(`[{"op":"eval","path":"/data"}]`))
	if err == nil {
		t.Fatal("expected unknown operation rejection")
	}
}

func TestParseOperationsRejectsMalformedInputs(t *testing.T) {
	tooMany := "["
	for i := 0; i < 101; i++ {
		if i > 0 {
			tooMany += ","
		}
		tooMany += `{"op":"drop","path":"/data/x"}`
	}
	tooMany += "]"

	tests := []string{
		`{"op":"drop","path":"/data"}`,
		`[]`,
		tooMany,
		`[{"op":"drop","path":"data"}]`,
		`[{"op":"copy","from":"data/source","path":"/data/dest"}]`,
		`[{"op":"copy","from":"/audit","path":"/data/dest"}]`,
	}
	for _, raw := range tests {
		t.Run(raw[:min(len(raw), 40)], func(t *testing.T) {
			if _, err := ParseOperations([]byte(raw)); err == nil {
				t.Fatalf("expected parse rejection for %s", raw)
			}
		})
	}
}

func TestApplyRejectsInvalidInputsAndPaths(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		ops   []Operation
	}{
		{
			name:  "input must be json",
			input: []byte(`not-json`),
			ops:   []Operation{{Op: "drop", Path: "/data"}},
		},
		{
			name:  "set value required",
			input: []byte(`{"data":{}}`),
			ops:   []Operation{{Op: "set", Path: "/data/name"}},
		},
		{
			name:  "set value must be json",
			input: []byte(`{"data":{}}`),
			ops:   []Operation{{Op: "set", Path: "/data/name", Value: mustRaw(`not-json`)}},
		},
		{
			name:  "copy source missing",
			input: []byte(`{"data":{}}`),
			ops:   []Operation{{Op: "copy", From: "/data/missing", Path: "/metadata/copy"}},
		},
		{
			name:  "copy array source missing",
			input: []byte(`{"data":{"items":["a"]}}`),
			ops:   []Operation{{Op: "copy", From: "/data/items/3", Path: "/metadata/copy"}},
		},
		{
			name:  "copy source parent not addressable",
			input: []byte(`{"data":"value"}`),
			ops:   []Operation{{Op: "copy", From: "/data/name", Path: "/metadata/copy"}},
		},
		{
			name:  "set array index missing",
			input: []byte(`{"data":{"items":["a"]}}`),
			ops:   []Operation{{Op: "set", Path: "/data/items/3", Value: mustRaw(`"b"`)}},
		},
		{
			name:  "set parent not addressable",
			input: []byte(`{"data":"value"}`),
			ops:   []Operation{{Op: "set", Path: "/data/name", Value: mustRaw(`"b"`)}},
		},
		{
			name:  "drop root rejected",
			input: []byte(`{"data":{}}`),
			ops:   []Operation{{Op: "drop", Path: "/"}},
		},
		{
			name:  "drop missing nested path",
			input: []byte(`{"data":{}}`),
			ops:   []Operation{{Op: "drop", Path: "/data/missing/name"}},
		},
		{
			name:  "drop array index missing",
			input: []byte(`{"data":{"items":["a"]}}`),
			ops:   []Operation{{Op: "drop", Path: "/data/items/3"}},
		},
		{
			name:  "drop parent not addressable",
			input: []byte(`{"data":"value"}`),
			ops:   []Operation{{Op: "drop", Path: "/data/name"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Apply(tt.input, tt.ops); err == nil {
				t.Fatal("expected transform rejection")
			}
		})
	}
}

func mustRaw(value string) []byte {
	return []byte(value)
}
