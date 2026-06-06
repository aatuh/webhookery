package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLoadCollectAndRenderOpenAPIReference(t *testing.T) {
	input := filepath.Join(t.TempDir(), "openapi.yaml")
	raw := []byte(`
openapi: 3.1.0
info:
  title: Webhookery <API>
  version: "2026.06"
  description: Evidence & delivery control plane.
paths:
  /v1/widgets:
    parameters:
      - name: tenant_id
        in: path
    post:
      tags: [Widgets]
      operationId: createWidget
      summary: Create | widget
      security:
        - bearerAuth: []
          apiKeyAuth: []
        - bearerAuth: []
      parameters:
        - name: tenant_id
          in: path
        - $ref: '#/components/parameters/Limit'
      requestBody:
        content:
          application/json: {}
      responses:
        "201": {}
        "400": {}
        default: {}
    get:
      tags: [Widgets]
      summary: List widgets
      responses:
        "200": {}
  /v1/raw:
    x-internal: true
    patch:
      operationId: patchRaw
      responses: {}
`)
	if err := os.WriteFile(input, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	doc, err := loadOpenAPI(input)
	if err != nil {
		t.Fatal(err)
	}
	ops := collectOperations(doc)
	gotIDs := make([]string, 0, len(ops))
	for _, op := range ops {
		gotIDs = append(gotIDs, op.ID)
	}
	if want := []string{"patchRaw", "-", "createWidget"}; !reflect.DeepEqual(gotIDs, want) {
		t.Fatalf("operation order/ids=%v want %v", gotIDs, want)
	}

	post := ops[2]
	if post.Method != "POST" || post.Path != "/v1/widgets" || post.Tag != "Widgets" {
		t.Fatalf("unexpected post operation: %+v", post)
	}
	if post.Auth != "apiKeyAuth, bearerAuth" {
		t.Fatalf("auth summary=%q", post.Auth)
	}
	if post.Parameters != "path:tenant_id, ref:Limit" {
		t.Fatalf("parameter summary=%q", post.Parameters)
	}
	if post.Request != "application/json" {
		t.Fatalf("request summary=%q", post.Request)
	}
	if post.Responses != "201, 400, default" {
		t.Fatalf("responses summary=%q", post.Responses)
	}

	html := renderHTML(doc, ops)
	for _, want := range []string{"Webhookery &lt;API&gt; Reference", "Evidence &amp; delivery control plane.", "<td class=\"method\">POST</td>"} {
		if !bytes.Contains(html, []byte(want)) {
			t.Fatalf("HTML output missing %q:\n%s", want, html)
		}
	}
	matrix := string(renderMatrix(ops))
	if !strings.Contains(matrix, "Total operations: `3`.") || !strings.Contains(matrix, "| `POST` | `/v1/widgets` | `createWidget` |") {
		t.Fatalf("matrix output missing operation count or POST row:\n%s", matrix)
	}
	summary := string(renderSummary(doc, ops))
	for _, want := range []string{"version `2026.06`", "| Widgets | 2 |", "| - | 1 |"} {
		if !strings.Contains(summary, want) {
			t.Fatalf("summary output missing %q:\n%s", want, summary)
		}
	}
}

func TestOpenAPIReferenceHelpersHandleFallbacksAndEscaping(t *testing.T) {
	if got := extractAuth(map[string]any{}); got != "none" {
		t.Fatalf("auth without security=%q", got)
	}
	if got := extractRequest(map[string]any{"requestBody": map[string]any{}}); got != "-" {
		t.Fatalf("empty request body=%q", got)
	}
	if got := extractRequest(map[string]any{"requestBody": map[string]any{"content": map[string]any{}}}); got != "present" {
		t.Fatalf("request body without content types=%q", got)
	}
	if got := extractParameters(map[string]any{"parameters": []any{map[string]any{"name": "", "in": "query"}}}); got != "-" {
		t.Fatalf("nameless parameter summary=%q", got)
	}
	if got := extractResponses(map[string]any{"responses": map[string]any{"default": map[string]any{}, "2XX": map[string]any{}, "204": map[string]any{}}}); got != "204, 2XX, default" {
		t.Fatalf("response ordering=%q", got)
	}
	if got := firstString([]any{12, "", "tag"}, "-"); got != "tag" {
		t.Fatalf("firstString=%q", got)
	}
	if got := fallback("", "fallback"); got != "fallback" {
		t.Fatalf("fallback=%q", got)
	}
	if got := unique([]string{"a", "a", "b", "b", "a"}); !reflect.DeepEqual(got, []string{"a", "b", "a"}) {
		t.Fatalf("unique preserves adjacent uniqueness only, got %v", got)
	}
	if got := lastRef("#/components/schemas/Event"); got != "Event" {
		t.Fatalf("lastRef=%q", got)
	}
	if got := md("a|b\nc"); got != "a\\|b c" {
		t.Fatalf("markdown escaped value=%q", got)
	}
	if got := md(""); got != "-" {
		t.Fatalf("empty markdown value=%q", got)
	}
	if len(asMap("not a map")) != 0 || asSlice("not a slice") != nil || asString(123) != "" {
		t.Fatal("type conversion helpers should return empty values for mismatched inputs")
	}
}

func TestOpenAPIReferenceFileIO(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "nested", "openapi.md")
	if err := writeFile(output, []byte("generated")); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "generated" {
		t.Fatalf("output body=%q", string(body))
	}

	invalid := filepath.Join(dir, "invalid.yaml")
	if err := os.WriteFile(invalid, []byte("openapi: ["), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOpenAPI(invalid); err == nil {
		t.Fatal("expected invalid YAML to fail")
	}
}
