package canonicaljson

import "testing"

func TestMarshalProducesStableObjectOrdering(t *testing.T) {
	left, err := Marshal(map[string]any{"b": 2, "a": 1})
	if err != nil {
		t.Fatal(err)
	}
	right, err := Marshal(map[string]any{"a": 1, "b": 2})
	if err != nil {
		t.Fatal(err)
	}
	if string(left) != string(right) {
		t.Fatalf("expected stable JSON, got %q and %q", left, right)
	}
	if string(left) != `{"a":1,"b":2}` {
		t.Fatalf("unexpected canonical JSON: %s", left)
	}
}

func TestMarshalReturnsJSONErrors(t *testing.T) {
	if _, err := Marshal(func() {}); err == nil {
		t.Fatal("expected JSON marshal error")
	}
}
