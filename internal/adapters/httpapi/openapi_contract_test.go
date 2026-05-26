package httpapi

import (
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"go.yaml.in/yaml/v3"
)

var openAPIMethods = map[string]struct{}{
	"get":    {},
	"post":   {},
	"put":    {},
	"patch":  {},
	"delete": {},
}

type openAPIContract struct {
	Paths map[string]map[string]openAPIOperation `yaml:"paths"`
}

type openAPIOperation struct {
	RequestBody *openAPIRequestBody        `yaml:"requestBody"`
	Responses   map[string]openAPIResponse `yaml:"responses"`
}

type openAPIRequestBody struct {
	Content map[string]openAPIMediaType `yaml:"content"`
}

type openAPIResponse struct {
	Content map[string]openAPIMediaType `yaml:"content"`
}

type openAPIMediaType struct {
	Example  any            `yaml:"example"`
	Examples map[string]any `yaml:"examples"`
}

func TestRouteTableMatchesOpenAPI(t *testing.T) {
	doc := loadOpenAPIContract(t)
	routerRoutes := registeredRouteMethods(t)
	openAPIRoutes := openAPIRouteMethods(doc)

	var missing []string
	for route, methods := range routerRoutes {
		for method := range methods {
			if !openAPIRoutes[route][method] {
				missing = append(missing, strings.ToUpper(method)+" "+route)
			}
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("registered routes missing from openapi.yaml:\n%s", strings.Join(missing, "\n"))
	}

	var undocumented []string
	for route, methods := range openAPIRoutes {
		for method := range methods {
			if routerRoutes[route][method] {
				continue
			}
			if documentedProviderAliasIsCovered(route, method, routerRoutes) {
				continue
			}
			undocumented = append(undocumented, strings.ToUpper(method)+" "+route)
		}
	}
	if len(undocumented) > 0 {
		sort.Strings(undocumented)
		t.Fatalf("openapi.yaml paths not registered by router:\n%s", strings.Join(undocumented, "\n"))
	}
}

func TestHighRiskOpenAPIOperationsHaveExamples(t *testing.T) {
	doc := loadOpenAPIContract(t)
	checks := []struct {
		name     string
		path     string
		method   string
		request  bool
		response bool
	}{
		{name: "ingest", path: "/v1/ingest/{tenant_id}/{source_id}", method: "post", request: true, response: true},
		{name: "raw read", path: "/v1/events/{event_id}/raw", method: "get", response: true},
		{name: "replay", path: "/v1/replay-jobs", method: "post", request: true, response: true},
		{name: "export", path: "/v1/audit-events:export", method: "post", request: true, response: true},
		{name: "auth", path: "/v1/auth/session", method: "get", response: true},
		{name: "alert", path: "/v1/alerts", method: "post", request: true, response: true},
		{name: "notification", path: "/v1/notification-channels", method: "post", request: true, response: true},
		{name: "siem", path: "/v1/siem-sinks", method: "post", request: true, response: true},
		{name: "producer token", path: "/v1/oauth/token", method: "post", request: true, response: true},
	}

	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			op := openAPIOperationFor(t, doc, check.path, check.method)
			if check.request && !requestBodyHasExample(op) {
				t.Fatalf("%s %s must include a request example", strings.ToUpper(check.method), check.path)
			}
			if check.response && !successResponseHasExample(op) {
				t.Fatalf("%s %s must include a success response example", strings.ToUpper(check.method), check.path)
			}
		})
	}
}

func loadOpenAPIContract(t *testing.T) openAPIContract {
	t.Helper()
	body, err := os.ReadFile("../../../openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc openAPIContract
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func registeredRouteMethods(t *testing.T) map[string]map[string]bool {
	t.Helper()
	routes, ok := NewServer(ServerConfig{}).Routes().(chi.Routes)
	if !ok {
		t.Fatal("server routes do not expose chi route metadata")
	}
	out := map[string]map[string]bool{}
	if err := chi.Walk(routes, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		method = strings.ToLower(method)
		if _, ok := openAPIMethods[method]; !ok {
			return nil
		}
		addRouteMethod(out, route, method)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func openAPIRouteMethods(doc openAPIContract) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for path, pathItem := range doc.Paths {
		for method := range pathItem {
			method = strings.ToLower(method)
			if _, ok := openAPIMethods[method]; ok {
				addRouteMethod(out, path, method)
			}
		}
	}
	return out
}

func addRouteMethod(routes map[string]map[string]bool, path, method string) {
	if routes[path] == nil {
		routes[path] = map[string]bool{}
	}
	routes[path][method] = true
}

func documentedProviderAliasIsCovered(route, method string, routerRoutes map[string]map[string]bool) bool {
	if !routerRoutes["/v1/ingest/{tenant_id}/{source_id}"][method] {
		return false
	}
	switch route {
	case "/v1/ingest/stripe/{source_id}",
		"/v1/ingest/github/{source_id}",
		"/v1/ingest/shopify/{source_id}",
		"/v1/ingest/slack/{source_id}",
		"/v1/ingest/cloudevents/{source_id}",
		"/v1/ingest/generic-jwt/{source_id}":
		return true
	default:
		return false
	}
}

func openAPIOperationFor(t *testing.T, doc openAPIContract, path, method string) openAPIOperation {
	t.Helper()
	pathItem, ok := doc.Paths[path]
	if !ok {
		t.Fatalf("openapi path missing: %s", path)
	}
	op, ok := pathItem[strings.ToLower(method)]
	if !ok {
		t.Fatalf("openapi operation missing: %s %s", strings.ToUpper(method), path)
	}
	return op
}

func requestBodyHasExample(op openAPIOperation) bool {
	if op.RequestBody == nil {
		return false
	}
	for _, media := range op.RequestBody.Content {
		if mediaHasExample(media) {
			return true
		}
	}
	return false
}

func successResponseHasExample(op openAPIOperation) bool {
	for status, response := range op.Responses {
		if !strings.HasPrefix(status, "2") {
			continue
		}
		for _, media := range response.Content {
			if mediaHasExample(media) {
				return true
			}
		}
	}
	return false
}

func mediaHasExample(media openAPIMediaType) bool {
	return media.Example != nil || len(media.Examples) > 0
}
