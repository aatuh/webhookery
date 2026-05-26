package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"webhookery/internal/domain"
	"webhookery/internal/provider"
)

func runSchemas(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp schemas <event-type-create|event-type-list|event-type-get|event-type-update|event-type-delete|schema-create|schema-list|schema-get|schema-update|schema-delete|validate|check-compat>")
	}
	fs := flag.NewFlagSet("schemas "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	name := fs.String("name", "", "event type name")
	description := fs.String("description", "", "event type description")
	state := fs.String("state", "", "event type or schema state")
	reason := fs.String("reason", "", "operator reason")
	version := fs.String("version", "", "schema version")
	schemaPath := fs.String("schema-file", "", "JSON schema file")
	payloadPath := fs.String("payload-file", "", "JSON payload file")
	newSchemaPath := fs.String("new-schema-file", "", "candidate JSON schema file")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "event-type-create":
		return postJSON(*baseURL, *apiKey, "/v1/event-types", map[string]string{"name": *name, "description": *description})
	case "event-type-list":
		return getJSON(*baseURL, *apiKey, "/v1/event-types")
	case "event-type-get":
		if strings.TrimSpace(*name) == "" {
			return fmt.Errorf("name is required")
		}
		return getJSON(*baseURL, *apiKey, "/v1/event-types/"+url.PathEscape(*name))
	case "event-type-update":
		if strings.TrimSpace(*name) == "" {
			return fmt.Errorf("name is required")
		}
		body := map[string]any{"reason": *reason}
		if strings.TrimSpace(*description) != "" {
			body["description"] = *description
		}
		if strings.TrimSpace(*state) != "" {
			body["state"] = *state
		}
		return patchJSON(*baseURL, *apiKey, "/v1/event-types/"+url.PathEscape(*name), body)
	case "event-type-delete":
		if strings.TrimSpace(*name) == "" {
			return fmt.Errorf("name is required")
		}
		return deleteJSON(*baseURL, *apiKey, "/v1/event-types/"+url.PathEscape(*name), map[string]string{"reason": *reason})
	case "schema-create":
		body, err := os.ReadFile(*schemaPath) // #nosec G304,G703 -- CLI reads an operator-selected schema file.
		if err != nil {
			return err
		}
		return postJSON(*baseURL, *apiKey, "/v1/event-types/"+url.PathEscape(*name)+"/schemas", map[string]string{"version": *version, "schema": string(body)})
	case "schema-list":
		if strings.TrimSpace(*name) == "" {
			return fmt.Errorf("name is required")
		}
		return getJSON(*baseURL, *apiKey, "/v1/event-types/"+url.PathEscape(*name)+"/schemas")
	case "schema-get":
		if strings.TrimSpace(*name) == "" || strings.TrimSpace(*version) == "" {
			return fmt.Errorf("name and version are required")
		}
		return getJSON(*baseURL, *apiKey, "/v1/event-types/"+url.PathEscape(*name)+"/schemas/"+url.PathEscape(*version))
	case "schema-update":
		if strings.TrimSpace(*name) == "" || strings.TrimSpace(*version) == "" {
			return fmt.Errorf("name and version are required")
		}
		return patchJSON(*baseURL, *apiKey, "/v1/event-types/"+url.PathEscape(*name)+"/schemas/"+url.PathEscape(*version), map[string]string{"state": *state, "reason": *reason})
	case "schema-delete":
		if strings.TrimSpace(*name) == "" || strings.TrimSpace(*version) == "" {
			return fmt.Errorf("name and version are required")
		}
		return deleteJSON(*baseURL, *apiKey, "/v1/event-types/"+url.PathEscape(*name)+"/schemas/"+url.PathEscape(*version), map[string]string{"reason": *reason})
	case "validate":
		body, err := os.ReadFile(*payloadPath) // #nosec G304,G703 -- CLI reads an operator-selected payload file.
		if err != nil {
			return err
		}
		return postJSON(*baseURL, *apiKey, "/v1/event-types/"+url.PathEscape(*name)+"/schemas/"+url.PathEscape(*version)+":validate", map[string]string{"payload": string(body)})
	case "check-compat":
		body, err := os.ReadFile(*newSchemaPath) // #nosec G304,G703 -- CLI reads an operator-selected schema file.
		if err != nil {
			return err
		}
		return postJSON(*baseURL, *apiKey, "/v1/event-types/"+url.PathEscape(*name)+"/schemas/"+url.PathEscape(*version)+":check-compatibility", map[string]string{"new_schema": string(body)})
	default:
		return fmt.Errorf("usage: whcp schemas <event-type-create|event-type-list|event-type-get|event-type-update|event-type-delete|schema-create|schema-list|schema-get|schema-update|schema-delete|validate|check-compat>")
	}
}

func runAdapters(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp adapters <list|get|create|versions|version-create|vector-create|transition>")
	}
	fs := flag.NewFlagSet("adapters "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	adapterID := fs.String("adapter-id", "", "adapter id")
	versionID := fs.String("version-id", "", "adapter version id")
	name := fs.String("name", "", "adapter name")
	kind := fs.String("kind", domain.AdapterKindDeclarative, "adapter kind")
	version := fs.String("version", "", "adapter version")
	definitionPath := fs.String("definition-file", "", "declarative adapter definition JSON file")
	requestPath := fs.String("request-file", "", "adapter test-vector request JSON file")
	expectedPath := fs.String("expected-file", "", "adapter test-vector expected JSON file")
	action := fs.String("action", "", "transition action")
	reason := fs.String("reason", "", "audit reason")
	riskLevel := fs.String("risk-level", "", "risk level")
	packageSHA := fs.String("package-sha256", "", "plugin package sha256")
	packageSignature := fs.String("package-signature", "", "plugin package signature")
	sbomSHA := fs.String("sbom-sha256", "", "plugin SBOM sha256")
	provenanceURL := fs.String("provenance-url", "", "provenance URL")
	description := fs.String("description", "", "description")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		return getJSON(*baseURL, *apiKey, "/v1/adapters")
	case "get":
		return getJSON(*baseURL, *apiKey, "/v1/adapters/"+url.PathEscape(*adapterID))
	case "create":
		return postJSON(*baseURL, *apiKey, "/v1/adapters", map[string]any{"name": *name, "kind": *kind, "description": *description, "risk_level": *riskLevel, "provenance_url": *provenanceURL})
	case "versions":
		return getJSON(*baseURL, *apiKey, "/v1/adapters/"+url.PathEscape(*adapterID)+"/versions")
	case "version-create":
		definition, err := readOptionalOperatorFile(*definitionPath)
		if err != nil {
			return err
		}
		body := map[string]any{"version": *version, "reason": *reason, "risk_level": *riskLevel, "package_sha256": *packageSHA, "package_signature": *packageSignature, "sbom_sha256": *sbomSHA, "provenance_url": *provenanceURL}
		if definition != "" {
			body["definition"] = json.RawMessage(definition)
		}
		return postJSON(*baseURL, *apiKey, "/v1/adapters/"+url.PathEscape(*adapterID)+"/versions", body)
	case "vector-create":
		requestBody, err := readRequiredOperatorFile(*requestPath, "request-file")
		if err != nil {
			return err
		}
		expectedBody, err := readRequiredOperatorFile(*expectedPath, "expected-file")
		if err != nil {
			return err
		}
		return postJSON(*baseURL, *apiKey, "/v1/adapters/"+url.PathEscape(*adapterID)+"/versions/"+url.PathEscape(*versionID)+"/test-vectors", map[string]any{"name": *name, "request": json.RawMessage(requestBody), "expected": json.RawMessage(expectedBody)})
	case "transition":
		return postJSON(*baseURL, *apiKey, "/v1/adapters/"+url.PathEscape(*adapterID)+"/versions/"+url.PathEscape(*versionID)+":transition", map[string]string{"action": *action, "reason": *reason})
	default:
		return fmt.Errorf("usage: whcp adapters <list|get|create|versions|version-create|vector-create|transition>")
	}
}

func runSignatures(args []string) error {
	if len(args) == 0 || args[0] != "verify" {
		return fmt.Errorf("usage: whcp signatures verify --provider PROVIDER --secret SECRET --body FILE --header 'Name: value'")
	}
	fs := flag.NewFlagSet("signatures verify", flag.ContinueOnError)
	providerName := fs.String("provider", "", "provider")
	secret := fs.String("secret", "", "secret")
	bodyPath := fs.String("body", "", "body file")
	header := fs.String("header", "", "header as 'Name: value'")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	body, err := os.ReadFile(*bodyPath)
	if err != nil {
		return err
	}
	name, value, ok := strings.Cut(*header, ":")
	if !ok {
		return fmt.Errorf("header must be formatted as 'Name: value'")
	}
	adapter, ok := provider.BuiltInRegistry().Adapter(*providerName)
	if !ok {
		return fmt.Errorf("unknown provider %q", *providerName)
	}
	result := adapter.Verify(provider.VerifyInput{
		RawBody: body,
		Headers: map[string][]string{strings.ToLower(strings.TrimSpace(name)): {strings.TrimSpace(value)}},
		Secret:  []byte(*secret),
		Now:     time.Now().UTC(),
	})
	out := json.NewEncoder(os.Stdout)
	out.SetIndent("", "  ")
	return out.Encode(result)
}
