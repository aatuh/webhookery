package app

import (
	"strings"
	"testing"
)

func TestValidateJSONPayloadCoversNestedTypesAndRequiredFields(t *testing.T) {
	schema := `{
		"type":"object",
		"required":["id","items"],
		"properties":{
			"id":{"type":"string"},
			"count":{"type":"integer"},
			"enabled":{"type":"boolean"},
			"items":{"type":"array","items":{"type":"object","required":["sku"],"properties":{"sku":{"type":"string"},"price":{"type":"number"}}}},
			"note":{"type":["null","string"]}
		}
	}`

	valid, err := ValidateJSONPayload(schema, `{"id":"evt_1","count":2,"enabled":true,"items":[{"sku":"sku_1","price":12.5}],"note":"ok"}`)
	if err != nil {
		t.Fatal(err)
	}
	if !valid.Valid || len(valid.Errors) != 0 {
		t.Fatalf("expected valid payload, got %+v", valid)
	}

	invalid, err := ValidateJSONPayload(schema, `{"id":123,"count":2.5,"items":[{"price":"free"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if invalid.Valid {
		t.Fatal("expected invalid payload")
	}
	for _, want := range []string{"$.id: expected string", "$.count: expected integer", "$.items[0].sku: required property is missing", "$.items[0].price: expected number"} {
		if !containsString(invalid.Errors, want) {
			t.Fatalf("validation errors %+v did not contain %q", invalid.Errors, want)
		}
	}
}

func TestValidateJSONPayloadRejectsMalformedInputsAndSchemaNodes(t *testing.T) {
	tests := []struct {
		name    string
		schema  string
		payload string
		wantErr string
	}{
		{name: "schema json", schema: `{`, payload: `{}`, wantErr: "schema must be valid JSON"},
		{name: "payload json", schema: `{}`, payload: `{`, wantErr: "payload must be valid JSON"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ValidateJSONPayload(tt.schema, tt.payload); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected %q error, got %v", tt.wantErr, err)
			}
		})
	}

	result, err := ValidateJSONPayload(`{"type":"object","properties":{"bad":true}}`, `{"bad":"value"}`)
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid || !containsString(result.Errors, "$.bad: schema node is not an object") {
		t.Fatalf("expected schema node error, got %+v", result)
	}

	unknown, err := ValidateJSONPayload(`{"type":"custom"}`, `"anything"`)
	if err != nil {
		t.Fatal(err)
	}
	if !unknown.Valid {
		t.Fatalf("unknown schema type should be treated as pass-through, got %+v", unknown)
	}
}

func TestCheckJSONSchemaCompatibilityDetectsBreakingChanges(t *testing.T) {
	oldSchema := `{"type":"object","required":["id"],"properties":{"id":{"type":"string"},"amount":{"type":"number"},"customer":{"type":"object","properties":{"email":{"type":"string"}}}}}`
	compatible, err := CheckJSONSchemaCompatibility(oldSchema, `{"type":"object","required":["id"],"properties":{"id":{"type":"string"},"amount":{"type":"number"},"customer":{"type":"object","properties":{"email":{"type":"string"},"name":{"type":"string"}}},"optional":{"type":"boolean"}}}`)
	if err != nil {
		t.Fatal(err)
	}
	if !compatible.Compatible || len(compatible.Errors) != 0 {
		t.Fatalf("expected compatible schema, got %+v", compatible)
	}

	breaking, err := CheckJSONSchemaCompatibility(oldSchema, `{"type":"array","required":["id","new_required"],"properties":{"id":{"type":"integer"},"customer":{"type":"object","properties":{"email":{"type":"number"}}}}}`)
	if err != nil {
		t.Fatal(err)
	}
	if breaking.Compatible {
		t.Fatal("expected incompatible schema")
	}
	for _, want := range []string{
		"$: type changed from object to array",
		"$.new_required: new required property is not backward compatible",
		"$.amount: existing property was removed",
		"$.id: type changed from string to integer",
		"$.customer.email: type changed from string to number",
	} {
		if !containsString(breaking.Errors, want) {
			t.Fatalf("compatibility errors %+v did not contain %q", breaking.Errors, want)
		}
	}
}

func TestCheckJSONSchemaCompatibilityRejectsMalformedInputsAndNodes(t *testing.T) {
	if _, err := CheckJSONSchemaCompatibility(`{`, `{}`); err == nil || !strings.Contains(err.Error(), "current schema must be valid JSON") {
		t.Fatalf("expected current schema JSON error, got %v", err)
	}
	if _, err := CheckJSONSchemaCompatibility(`{}`, `{`); err == nil || !strings.Contains(err.Error(), "new_schema must be valid JSON") {
		t.Fatalf("expected new schema JSON error, got %v", err)
	}
	result, err := CheckJSONSchemaCompatibility(`{"type":"object","properties":{"bad":true}}`, `{"type":"object","properties":{"bad":{}}}`)
	if err != nil {
		t.Fatal(err)
	}
	if result.Compatible || !containsString(result.Errors, "$.bad: current schema node is not an object") {
		t.Fatalf("expected current schema node error, got %+v", result)
	}
	result, err = CheckJSONSchemaCompatibility(`{"type":"object","properties":{"bad":{}}}`, `{"type":"object","properties":{"bad":true}}`)
	if err != nil {
		t.Fatal(err)
	}
	if result.Compatible || !containsString(result.Errors, "$.bad: new schema node is not an object") {
		t.Fatalf("expected new schema node error, got %+v", result)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
