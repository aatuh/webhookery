package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"

	apppkg "webhookery/internal/app"
	"webhookery/internal/config"
)

func runAdmin(args []string) error {
	if len(args) != 2 || args[0] != "hash-key" {
		return fmt.Errorf("usage: whcp admin hash-key <api-key>")
	}
	fmt.Println(apppkg.HashToken(args[1]))
	return nil
}

func runAPIKeys(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp api-keys <create|list|revoke>")
	}
	fs := flag.NewFlagSet("api-keys "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	name := fs.String("name", "", "API key name")
	userID := fs.String("user-id", "", "user id")
	email := fs.String("email", "", "user email")
	role := fs.String("role", "operator", "membership role")
	scopes := fs.String("scopes", "events:read,deliveries:read", "comma-separated scopes")
	keyID := fs.String("key-id", "", "API key id")
	reason := fs.String("reason", "", "revocation reason")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "create":
		return postJSON(*baseURL, *apiKey, "/v1/api-keys", map[string]any{"name": *name, "user_id": *userID, "email": *email, "role": *role, "scopes": splitCSV(*scopes)})
	case "list":
		return getJSON(*baseURL, *apiKey, "/v1/api-keys")
	case "revoke":
		return postJSON(*baseURL, *apiKey, "/v1/api-keys/"+url.PathEscape(*keyID)+":revoke", map[string]string{"reason": *reason})
	default:
		return fmt.Errorf("usage: whcp api-keys <create|list|revoke>")
	}
}

func runProducerClients(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp producer-clients <list|get|create|update|disable|rotate-secret>")
	}
	fs := flag.NewFlagSet("producer-clients "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	clientID := fs.String("client-id", "", "producer client id")
	name := fs.String("name", "", "producer client name")
	sourceID := fs.String("source-id", "", "optional bound source id")
	scopes := fs.String("scopes", "events:write", "comma-separated scopes")
	ttl := fs.Int("token-ttl-seconds", 900, "producer access token TTL in seconds")
	state := fs.String("state", "", "active or disabled")
	reason := fs.String("reason", "", "operator reason")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		return getJSON(*baseURL, *apiKey, "/v1/producer-clients")
	case "get":
		if strings.TrimSpace(*clientID) == "" {
			return fmt.Errorf("client-id is required")
		}
		return getJSON(*baseURL, *apiKey, "/v1/producer-clients/"+url.PathEscape(*clientID))
	case "create":
		return postJSON(*baseURL, *apiKey, "/v1/producer-clients", map[string]any{
			"name":              *name,
			"source_id":         *sourceID,
			"scopes":            splitCSV(*scopes),
			"token_ttl_seconds": *ttl,
		})
	case "update":
		if strings.TrimSpace(*clientID) == "" {
			return fmt.Errorf("client-id is required")
		}
		body := map[string]any{"reason": *reason}
		if strings.TrimSpace(*name) != "" {
			body["name"] = *name
		}
		if strings.TrimSpace(*sourceID) != "" {
			body["source_id"] = *sourceID
		}
		if strings.TrimSpace(*scopes) != "" {
			body["scopes"] = splitCSV(*scopes)
		}
		if *ttl != 900 {
			body["token_ttl_seconds"] = *ttl
		}
		if strings.TrimSpace(*state) != "" {
			body["state"] = *state
		}
		return patchJSON(*baseURL, *apiKey, "/v1/producer-clients/"+url.PathEscape(*clientID), body)
	case "disable":
		if strings.TrimSpace(*clientID) == "" {
			return fmt.Errorf("client-id is required")
		}
		return deleteJSON(*baseURL, *apiKey, "/v1/producer-clients/"+url.PathEscape(*clientID), map[string]string{"reason": *reason})
	case "rotate-secret":
		if strings.TrimSpace(*clientID) == "" {
			return fmt.Errorf("client-id is required")
		}
		return postJSON(*baseURL, *apiKey, "/v1/producer-clients/"+url.PathEscape(*clientID)+"/secrets:rotate", map[string]string{"reason": *reason})
	default:
		return fmt.Errorf("usage: whcp producer-clients <list|get|create|update|disable|rotate-secret>")
	}
}

func runProducerMTLSIdentities(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp producer-mtls-identities <list|get|create|update|disable|verify>")
	}
	fs := flag.NewFlagSet("producer-mtls-identities "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	identityID := fs.String("identity-id", "", "producer mTLS identity id")
	name := fs.String("name", "", "identity name")
	sourceID := fs.String("source-id", "", "optional bound source id")
	certFile := fs.String("cert-file", "", "PEM certificate file")
	state := fs.String("state", "", "active or disabled")
	reason := fs.String("reason", "", "operator reason")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	certBody := func() (string, error) {
		if strings.TrimSpace(*certFile) == "" {
			return "", fmt.Errorf("cert-file is required")
		}
		body, err := readSmallFile(*certFile, 1<<20)
		if err != nil {
			return "", err
		}
		return string(body), nil
	}
	switch args[0] {
	case "list":
		return getJSON(*baseURL, *apiKey, "/v1/producer-mtls-identities")
	case "get":
		if strings.TrimSpace(*identityID) == "" {
			return fmt.Errorf("identity-id is required")
		}
		return getJSON(*baseURL, *apiKey, "/v1/producer-mtls-identities/"+url.PathEscape(*identityID))
	case "create":
		certPEM, err := certBody()
		if err != nil {
			return err
		}
		return postJSON(*baseURL, *apiKey, "/v1/producer-mtls-identities", map[string]any{"name": *name, "source_id": *sourceID, "certificate_pem": certPEM})
	case "update":
		if strings.TrimSpace(*identityID) == "" {
			return fmt.Errorf("identity-id is required")
		}
		body := map[string]any{"reason": *reason}
		if strings.TrimSpace(*name) != "" {
			body["name"] = *name
		}
		if strings.TrimSpace(*sourceID) != "" {
			body["source_id"] = *sourceID
		}
		if strings.TrimSpace(*state) != "" {
			body["state"] = *state
		}
		return patchJSON(*baseURL, *apiKey, "/v1/producer-mtls-identities/"+url.PathEscape(*identityID), body)
	case "disable":
		if strings.TrimSpace(*identityID) == "" {
			return fmt.Errorf("identity-id is required")
		}
		return deleteJSON(*baseURL, *apiKey, "/v1/producer-mtls-identities/"+url.PathEscape(*identityID), map[string]string{"reason": *reason})
	case "verify":
		if strings.TrimSpace(*identityID) == "" {
			return fmt.Errorf("identity-id is required")
		}
		certPEM, err := certBody()
		if err != nil {
			return err
		}
		return postJSON(*baseURL, *apiKey, "/v1/producer-mtls-identities/"+url.PathEscape(*identityID)+":verify", map[string]string{"certificate_pem": certPEM})
	default:
		return fmt.Errorf("usage: whcp producer-mtls-identities <list|get|create|update|disable|verify>")
	}
}

func runKeyCustody(args []string) error {
	if len(args) == 0 || args[0] != "test" {
		return fmt.Errorf("usage: whcp key-custody test")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	box, err := secretBoxFromConfig(context.Background(), cfg)
	if err != nil {
		return err
	}
	const marker = "webhookery-key-custody-test"
	ciphertext, err := box.Encrypt([]byte(marker))
	if err != nil {
		return fmt.Errorf("key custody encrypt test failed")
	}
	plaintext, err := box.Decrypt(ciphertext)
	if err != nil {
		return fmt.Errorf("key custody decrypt test failed")
	}
	if string(plaintext) != marker {
		return fmt.Errorf("key custody decrypt test returned unexpected plaintext")
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"mode":       cfg.SecretBoxMode,
		"configured": true,
		"ok":         true,
		"key_ref":    keyCustodyKeyRef(cfg),
	})
}

func runIdentityProviders(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp identity-providers <list|get|create|update|disable|test>")
	}
	fs := flag.NewFlagSet("identity-providers "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	providerID := fs.String("provider-id", "", "identity provider id")
	name := fs.String("name", "", "identity provider name")
	issuerURL := fs.String("issuer-url", "", "OIDC issuer URL")
	authURL := fs.String("authorization-url", "", "OIDC authorization endpoint override")
	tokenURL := fs.String("token-url", "", "OIDC token endpoint override")
	jwksURL := fs.String("jwks-url", "", "OIDC JWKS endpoint override")
	clientID := fs.String("client-id", "", "OIDC client id")
	clientSecret := fs.String("client-secret", "", "OIDC client secret")
	redirectURI := fs.String("redirect-uri", "", "OIDC callback redirect URI")
	allowedDomains := fs.String("allowed-email-domains", "", "comma-separated allowed email domains")
	state := fs.String("state", "", "active or disabled")
	reason := fs.String("reason", "", "operator reason")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		return getJSON(*baseURL, *apiKey, "/v1/identity-providers")
	case "get":
		if strings.TrimSpace(*providerID) == "" {
			return fmt.Errorf("provider-id is required")
		}
		return getJSON(*baseURL, *apiKey, "/v1/identity-providers/"+url.PathEscape(*providerID))
	case "create":
		return postJSON(*baseURL, *apiKey, "/v1/identity-providers", map[string]any{
			"name":                   *name,
			"provider_type":          "oidc",
			"issuer_url":             *issuerURL,
			"authorization_endpoint": *authURL,
			"token_endpoint":         *tokenURL,
			"jwks_uri":               *jwksURL,
			"client_id":              *clientID,
			"client_secret":          *clientSecret,
			"redirect_uri":           *redirectURI,
			"allowed_email_domains":  splitCSV(*allowedDomains),
		})
	case "update":
		if strings.TrimSpace(*providerID) == "" {
			return fmt.Errorf("provider-id is required")
		}
		body := map[string]any{"reason": *reason}
		if strings.TrimSpace(*name) != "" {
			body["name"] = *name
		}
		if strings.TrimSpace(*issuerURL) != "" {
			body["issuer_url"] = *issuerURL
		}
		if strings.TrimSpace(*authURL) != "" {
			body["authorization_endpoint"] = *authURL
		}
		if strings.TrimSpace(*tokenURL) != "" {
			body["token_endpoint"] = *tokenURL
		}
		if strings.TrimSpace(*jwksURL) != "" {
			body["jwks_uri"] = *jwksURL
		}
		if strings.TrimSpace(*clientID) != "" {
			body["client_id"] = *clientID
		}
		if strings.TrimSpace(*clientSecret) != "" {
			body["client_secret"] = *clientSecret
		}
		if strings.TrimSpace(*redirectURI) != "" {
			body["redirect_uri"] = *redirectURI
		}
		if strings.TrimSpace(*allowedDomains) != "" {
			body["allowed_email_domains"] = splitCSV(*allowedDomains)
		}
		if strings.TrimSpace(*state) != "" {
			body["state"] = *state
		}
		return patchJSON(*baseURL, *apiKey, "/v1/identity-providers/"+url.PathEscape(*providerID), body)
	case "disable":
		if strings.TrimSpace(*providerID) == "" {
			return fmt.Errorf("provider-id is required")
		}
		return deleteJSON(*baseURL, *apiKey, "/v1/identity-providers/"+url.PathEscape(*providerID), map[string]string{"reason": *reason})
	case "test":
		if strings.TrimSpace(*providerID) == "" {
			return fmt.Errorf("provider-id is required")
		}
		return postJSON(*baseURL, *apiKey, "/v1/identity-providers/"+url.PathEscape(*providerID)+":test", map[string]string{"reason": *reason})
	default:
		return fmt.Errorf("usage: whcp identity-providers <list|get|create|update|disable|test>")
	}
}

func runSCIMTokens(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp scim-tokens <list|create|revoke>")
	}
	fs := flag.NewFlagSet("scim-tokens "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	name := fs.String("name", "", "SCIM token name")
	tokenID := fs.String("token-id", "", "SCIM token id")
	reason := fs.String("reason", "", "operator reason")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		return getJSON(*baseURL, *apiKey, "/v1/scim-tokens")
	case "create":
		return postJSON(*baseURL, *apiKey, "/v1/scim-tokens", map[string]string{"name": *name})
	case "revoke":
		if strings.TrimSpace(*tokenID) == "" {
			return fmt.Errorf("token-id is required")
		}
		return deleteJSON(*baseURL, *apiKey, "/v1/scim-tokens/"+url.PathEscape(*tokenID), map[string]string{"reason": *reason})
	default:
		return fmt.Errorf("usage: whcp scim-tokens <list|create|revoke>")
	}
}

func runRoleBindings(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp role-bindings <list|create|update|disable>")
	}
	fs := flag.NewFlagSet("role-bindings "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	bindingID := fs.String("binding-id", "", "role binding id")
	principalType := fs.String("principal-type", "user", "user or group")
	principalID := fs.String("principal-id", "", "principal id")
	role := fs.String("role", "support", "role")
	resourceFamily := fs.String("resource-family", "*", "resource family")
	resourceID := fs.String("resource-id", "*", "resource id")
	environment := fs.String("environment", "*", "environment")
	state := fs.String("state", "", "active or disabled")
	reason := fs.String("reason", "", "operator reason")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		return getJSON(*baseURL, *apiKey, "/v1/role-bindings")
	case "create":
		return postJSON(*baseURL, *apiKey, "/v1/role-bindings", map[string]any{"principal_type": *principalType, "principal_id": *principalID, "role": *role, "resource_family": *resourceFamily, "resource_id": *resourceID, "environment": *environment, "reason": *reason})
	case "update":
		if strings.TrimSpace(*bindingID) == "" {
			return fmt.Errorf("binding-id is required")
		}
		body := map[string]any{"reason": *reason}
		if strings.TrimSpace(*role) != "" {
			body["role"] = *role
		}
		if strings.TrimSpace(*resourceFamily) != "" {
			body["resource_family"] = *resourceFamily
		}
		if strings.TrimSpace(*resourceID) != "" {
			body["resource_id"] = *resourceID
		}
		if strings.TrimSpace(*environment) != "" {
			body["environment"] = *environment
		}
		if strings.TrimSpace(*state) != "" {
			body["state"] = *state
		}
		return patchJSON(*baseURL, *apiKey, "/v1/role-bindings/"+url.PathEscape(*bindingID), body)
	case "disable":
		if strings.TrimSpace(*bindingID) == "" {
			return fmt.Errorf("binding-id is required")
		}
		return deleteJSON(*baseURL, *apiKey, "/v1/role-bindings/"+url.PathEscape(*bindingID), map[string]string{"reason": *reason})
	default:
		return fmt.Errorf("usage: whcp role-bindings <list|create|update|disable>")
	}
}

func runAccessPolicies(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: whcp access-policies <list|create|update|disable>")
	}
	fs := flag.NewFlagSet("access-policies "+args[0], flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	policyID := fs.String("policy-id", "", "access policy id")
	name := fs.String("name", "", "policy name")
	action := fs.String("action", "", "action")
	effect := fs.String("effect", "deny", "allow or deny")
	resourceFamily := fs.String("resource-family", "*", "resource family")
	environment := fs.String("environment", "*", "environment")
	conditions := fs.String("conditions", "{}", "JSON policy conditions")
	state := fs.String("state", "", "active or disabled")
	reason := fs.String("reason", "", "operator reason")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		return getJSON(*baseURL, *apiKey, "/v1/access-policies")
	case "create":
		return postJSON(*baseURL, *apiKey, "/v1/access-policies", map[string]any{"name": *name, "action": *action, "effect": *effect, "resource_family": *resourceFamily, "environment": *environment, "conditions": json.RawMessage(*conditions), "reason": *reason})
	case "update":
		if strings.TrimSpace(*policyID) == "" {
			return fmt.Errorf("policy-id is required")
		}
		body := map[string]any{"reason": *reason}
		if strings.TrimSpace(*name) != "" {
			body["name"] = *name
		}
		if strings.TrimSpace(*action) != "" {
			body["action"] = *action
		}
		if strings.TrimSpace(*effect) != "" {
			body["effect"] = *effect
		}
		if strings.TrimSpace(*resourceFamily) != "" {
			body["resource_family"] = *resourceFamily
		}
		if strings.TrimSpace(*environment) != "" {
			body["environment"] = *environment
		}
		if strings.TrimSpace(*conditions) != "" {
			body["conditions"] = json.RawMessage(*conditions)
		}
		if strings.TrimSpace(*state) != "" {
			body["state"] = *state
		}
		return patchJSON(*baseURL, *apiKey, "/v1/access-policies/"+url.PathEscape(*policyID), body)
	case "disable":
		if strings.TrimSpace(*policyID) == "" {
			return fmt.Errorf("policy-id is required")
		}
		return deleteJSON(*baseURL, *apiKey, "/v1/access-policies/"+url.PathEscape(*policyID), map[string]string{"reason": *reason})
	default:
		return fmt.Errorf("usage: whcp access-policies <list|create|update|disable>")
	}
}

func runAuthz(args []string) error {
	if len(args) == 0 || args[0] != "explain" {
		return fmt.Errorf("usage: whcp authz explain")
	}
	fs := flag.NewFlagSet("authz explain", flag.ContinueOnError)
	baseURL := fs.String("base-url", "http://localhost:8080", "API base URL")
	apiKey := fs.String("api-key", os.Getenv("WEBHOOKERY_API_KEY"), "API key")
	actorID := fs.String("actor-id", "", "actor id to explain")
	action := fs.String("action", "", "action")
	resourceFamily := fs.String("resource-family", "", "resource family")
	resourceID := fs.String("resource-id", "", "resource id")
	environment := fs.String("environment", "", "environment")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	return postJSON(*baseURL, *apiKey, "/v1/authz:explain", map[string]any{"actor_id": *actorID, "action": *action, "resource_family": *resourceFamily, "resource_id": *resourceID, "environment": *environment})
}
