package main

import (
	"bytes"
	"flag"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

type operation struct {
	Method     string
	Path       string
	ID         string
	Summary    string
	Tag        string
	Auth       string
	Parameters string
	Request    string
	Responses  string
}

func main() {
	input := flag.String("input", "openapi.yaml", "OpenAPI source file")
	htmlOut := flag.String("html", "docs/openapi/index.html", "rendered HTML output")
	matrixOut := flag.String("matrix", "docs/reference/api-contract-matrix.md", "contract matrix markdown output")
	summaryOut := flag.String("summary", "docs/reference/openapi.md", "OpenAPI summary markdown output")
	flag.Parse()

	doc, err := loadOpenAPI(*input)
	if err != nil {
		fatal(err)
	}
	ops := collectOperations(doc)
	if len(ops) == 0 {
		fatal(fmt.Errorf("no OpenAPI operations found in %s", *input))
	}

	if err := writeFile(*htmlOut, renderHTML(doc, ops)); err != nil {
		fatal(err)
	}
	if err := writeFile(*matrixOut, renderMatrix(ops)); err != nil {
		fatal(err)
	}
	if err := writeFile(*summaryOut, renderSummary(doc, ops)); err != nil {
		fatal(err)
	}
}

func loadOpenAPI(path string) (map[string]any, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- repository generator reads an explicit maintainer-provided input path.
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	return doc, nil
}

func collectOperations(doc map[string]any) []operation {
	paths := asMap(doc["paths"])
	pathNames := sortedKeys(paths)
	methodOrder := map[string]int{
		"get": 0, "post": 1, "put": 2, "patch": 3, "delete": 4,
		"options": 5, "head": 6, "trace": 7,
	}

	var ops []operation
	for _, pathName := range pathNames {
		pathItem := asMap(paths[pathName])
		methods := sortedKeys(pathItem)
		sort.SliceStable(methods, func(i, j int) bool {
			ai, aok := methodOrder[methods[i]]
			bi, bok := methodOrder[methods[j]]
			switch {
			case aok && bok:
				return ai < bi
			case aok:
				return true
			case bok:
				return false
			default:
				return methods[i] < methods[j]
			}
		})
		for _, method := range methods {
			if _, ok := methodOrder[method]; !ok {
				continue
			}
			opMap := asMap(pathItem[method])
			if len(opMap) == 0 {
				continue
			}
			ops = append(ops, operation{
				Method:     strings.ToUpper(method),
				Path:       pathName,
				ID:         fallback(asString(opMap["operationId"]), "-"),
				Summary:    fallback(asString(opMap["summary"]), "-"),
				Tag:        firstString(asSlice(opMap["tags"]), "-"),
				Auth:       extractAuth(opMap),
				Parameters: extractParameters(opMap),
				Request:    extractRequest(opMap),
				Responses:  extractResponses(opMap),
			})
		}
	}
	return ops
}

func renderHTML(doc map[string]any, ops []operation) []byte {
	info := asMap(doc["info"])
	title := fallback(asString(info["title"]), "OpenAPI")
	description := fallback(asString(info["description"]), "")
	version := fallback(asString(info["version"]), "")

	var b bytes.Buffer
	b.WriteString("<!doctype html>\n<html lang=\"en\">\n<head>\n")
	b.WriteString("  <meta charset=\"utf-8\">\n")
	b.WriteString("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
	fmt.Fprintf(&b, "  <title>%s Reference</title>\n", html.EscapeString(title))
	b.WriteString("  <style>\n")
	b.WriteString("    :root { color-scheme: light; --ink: #172033; --muted: #5f6b7a; --line: #d8dee8; --soft: #f6f8fb; --accent: #0f766e; }\n")
	b.WriteString("    body { margin: 0; font: 15px/1.5 system-ui, -apple-system, Segoe UI, sans-serif; color: var(--ink); background: #fff; }\n")
	b.WriteString("    header { padding: 32px max(24px, calc((100vw - 1180px) / 2)); border-bottom: 1px solid var(--line); background: var(--soft); }\n")
	b.WriteString("    main { max-width: 1180px; margin: 0 auto; padding: 28px 24px 48px; }\n")
	b.WriteString("    h1 { margin: 0 0 8px; font-size: 32px; line-height: 1.15; }\n")
	b.WriteString("    p { margin: 0 0 14px; color: var(--muted); }\n")
	b.WriteString("    .meta { display: flex; gap: 12px; flex-wrap: wrap; margin-top: 16px; }\n")
	b.WriteString("    .pill { border: 1px solid var(--line); background: #fff; border-radius: 999px; padding: 5px 10px; color: var(--ink); }\n")
	b.WriteString("    table { width: 100%; border-collapse: collapse; border: 1px solid var(--line); }\n")
	b.WriteString("    th, td { padding: 10px 12px; border-bottom: 1px solid var(--line); vertical-align: top; text-align: left; }\n")
	b.WriteString("    th { position: sticky; top: 0; background: #eef3f8; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }\n")
	b.WriteString("    tr:nth-child(even) td { background: #fbfcfe; }\n")
	b.WriteString("    code { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 13px; }\n")
	b.WriteString("    .method { font-weight: 700; color: var(--accent); }\n")
	b.WriteString("  </style>\n</head>\n<body>\n")
	b.WriteString("  <header>\n")
	fmt.Fprintf(&b, "    <h1>%s Reference</h1>\n", html.EscapeString(title))
	if description != "" {
		fmt.Fprintf(&b, "    <p>%s</p>\n", html.EscapeString(description))
	}
	b.WriteString("    <div class=\"meta\">\n")
	fmt.Fprintf(&b, "      <span class=\"pill\">Version %s</span>\n", html.EscapeString(version))
	fmt.Fprintf(&b, "      <span class=\"pill\">%d operations</span>\n", len(ops))
	b.WriteString("      <span class=\"pill\">Generated from openapi.yaml</span>\n")
	b.WriteString("    </div>\n")
	b.WriteString("  </header>\n  <main>\n")
	b.WriteString("    <table>\n")
	b.WriteString("      <thead><tr><th>Method</th><th>Path</th><th>Operation</th><th>Tag</th><th>Auth</th><th>Request</th><th>Responses</th></tr></thead>\n")
	b.WriteString("      <tbody>\n")
	for _, op := range ops {
		b.WriteString("        <tr>")
		fmt.Fprintf(&b, "<td class=\"method\">%s</td>", html.EscapeString(op.Method))
		fmt.Fprintf(&b, "<td><code>%s</code></td>", html.EscapeString(op.Path))
		fmt.Fprintf(&b, "<td><code>%s</code><br>%s</td>", html.EscapeString(op.ID), html.EscapeString(op.Summary))
		fmt.Fprintf(&b, "<td>%s</td>", html.EscapeString(op.Tag))
		fmt.Fprintf(&b, "<td>%s</td>", html.EscapeString(op.Auth))
		fmt.Fprintf(&b, "<td>%s</td>", html.EscapeString(op.Request))
		fmt.Fprintf(&b, "<td>%s</td>", html.EscapeString(op.Responses))
		b.WriteString("</tr>\n")
	}
	b.WriteString("      </tbody>\n    </table>\n  </main>\n</body>\n</html>\n")
	return b.Bytes()
}

func renderMatrix(ops []operation) []byte {
	var b bytes.Buffer
	b.WriteString("# Webhookery API Contract Matrix\n\n")
	b.WriteString("Generated from `openapi.yaml`. Do not edit operation rows manually; run `make openapi-reference-generate`.\n\n")
	fmt.Fprintf(&b, "Total operations: `%d`.\n\n", len(ops))
	b.WriteString("| Method | Path | Operation ID | Tag | Auth | Parameters | Request | Responses |\n")
	b.WriteString("| --- | --- | --- | --- | --- | --- | --- | --- |\n")
	for _, op := range ops {
		fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | %s | %s | %s | %s | %s |\n",
			md(op.Method), md(op.Path), md(op.ID), md(op.Tag), md(op.Auth),
			md(op.Parameters), md(op.Request), md(op.Responses))
	}
	return b.Bytes()
}

func renderSummary(doc map[string]any, ops []operation) []byte {
	info := asMap(doc["info"])
	title := fallback(asString(info["title"]), "Webhookery API")
	version := fallback(asString(info["version"]), "")
	description := fallback(asString(info["description"]), "")
	counts := map[string]int{}
	for _, op := range ops {
		counts[op.Tag]++
	}
	tags := sortedKeysAnyCount(counts)

	var b bytes.Buffer
	b.WriteString("# OpenAPI Reference\n\n")
	fmt.Fprintf(&b, "`openapi.yaml` is the canonical REST API contract for %s", title)
	if version != "" {
		fmt.Fprintf(&b, " version `%s`", version)
	}
	b.WriteString(".\n\n")
	if description != "" {
		fmt.Fprintf(&b, "%s\n\n", description)
	}
	fmt.Fprintf(&b, "- Rendered HTML reference: [`docs/openapi/index.html`](../openapi/index.html)\n")
	fmt.Fprintf(&b, "- API contract matrix: [`docs/reference/api-contract-matrix.md`](api-contract-matrix.md)\n")
	fmt.Fprintf(&b, "- Total operations: `%d`\n\n", len(ops))
	b.WriteString("## Operations By Tag\n\n")
	b.WriteString("| Tag | Operations |\n| --- | ---: |\n")
	for _, tag := range tags {
		fmt.Fprintf(&b, "| %s | %d |\n", md(tag), counts[tag])
	}
	b.WriteString("\n## Maintenance\n\n")
	b.WriteString("When `openapi.yaml` changes, run `make openapi-reference-generate` and commit the regenerated reference artifacts with the contract change. `make openapi-reference-check` verifies that the generated files are current.\n")
	return b.Bytes()
}

func extractAuth(op map[string]any) string {
	security, ok := op["security"]
	if !ok {
		return "none"
	}
	items := asSlice(security)
	if len(items) == 0 {
		return "none"
	}
	var schemes []string
	for _, item := range items {
		for name := range asMap(item) {
			schemes = append(schemes, name)
		}
	}
	sort.Strings(schemes)
	if len(schemes) == 0 {
		return "none"
	}
	return strings.Join(unique(schemes), ", ")
}

func extractParameters(op map[string]any) string {
	params := asSlice(op["parameters"])
	if len(params) == 0 {
		return "-"
	}
	var out []string
	for _, param := range params {
		p := asMap(param)
		if ref := asString(p["$ref"]); ref != "" {
			out = append(out, "ref:"+lastRef(ref))
			continue
		}
		name := asString(p["name"])
		in := asString(p["in"])
		if name == "" {
			continue
		}
		if in != "" {
			out = append(out, in+":"+name)
		} else {
			out = append(out, name)
		}
	}
	if len(out) == 0 {
		return "-"
	}
	return strings.Join(out, ", ")
}

func extractRequest(op map[string]any) string {
	requestBody := asMap(op["requestBody"])
	if len(requestBody) == 0 {
		return "-"
	}
	content := asMap(requestBody["content"])
	if len(content) == 0 {
		return "present"
	}
	return strings.Join(sortedKeys(content), ", ")
}

func extractResponses(op map[string]any) string {
	responses := asMap(op["responses"])
	if len(responses) == 0 {
		return "-"
	}
	keys := sortedKeys(responses)
	sort.SliceStable(keys, func(i, j int) bool {
		return responseRank(keys[i]) < responseRank(keys[j])
	})
	return strings.Join(keys, ", ")
}

func responseRank(code string) string {
	if len(code) == 3 && code[0] >= '0' && code[0] <= '9' {
		return code
	}
	return "999" + code
}

func asMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func asSlice(v any) []any {
	if s, ok := v.([]any); ok {
		return s
	}
	return nil
}

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func firstString(items []any, fallbackValue string) string {
	for _, item := range items {
		if s := asString(item); s != "" {
			return s
		}
	}
	return fallbackValue
}

func fallback(value, fallbackValue string) string {
	if value == "" {
		return fallbackValue
	}
	return value
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedKeysAnyCount(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func unique(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := values[:0]
	var last string
	for i, value := range values {
		if i == 0 || value != last {
			out = append(out, value)
			last = value
		}
	}
	return out
}

func lastRef(ref string) string {
	parts := strings.Split(ref, "/")
	return parts[len(parts)-1]
}

func md(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\n", " ")
	if value == "" {
		return "-"
	}
	return value
}

func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644) // #nosec G304,G306 -- repository generator writes explicit public documentation artifact paths.
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
