package app

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
)

type schemaNode struct {
	Type       any                        `json:"type"`
	Required   []string                   `json:"required"`
	Properties map[string]json.RawMessage `json:"properties"`
	Items      json.RawMessage            `json:"items"`
}

func ValidateJSONPayload(schemaRaw, payloadRaw string) (SchemaValidationResult, error) {
	var schema json.RawMessage
	if err := json.Unmarshal([]byte(schemaRaw), &schema); err != nil {
		return SchemaValidationResult{}, fmt.Errorf("%w: schema must be valid JSON", ErrInvalidInput)
	}
	var payload any
	if err := json.Unmarshal([]byte(payloadRaw), &payload); err != nil {
		return SchemaValidationResult{}, fmt.Errorf("%w: payload must be valid JSON", ErrInvalidInput)
	}
	errors := validateAgainstSchema(payload, schema, "$")
	return SchemaValidationResult{Valid: len(errors) == 0, Errors: errors}, nil
}

func CheckJSONSchemaCompatibility(oldRaw, newRaw string) (SchemaCompatibilityResult, error) {
	var oldSchema, newSchema json.RawMessage
	if err := json.Unmarshal([]byte(oldRaw), &oldSchema); err != nil {
		return SchemaCompatibilityResult{}, fmt.Errorf("%w: current schema must be valid JSON", ErrInvalidInput)
	}
	if err := json.Unmarshal([]byte(newRaw), &newSchema); err != nil {
		return SchemaCompatibilityResult{}, fmt.Errorf("%w: new_schema must be valid JSON", ErrInvalidInput)
	}
	errors := compareSchemaCompatibility(oldSchema, newSchema, "$")
	return SchemaCompatibilityResult{Compatible: len(errors) == 0, Errors: errors}, nil
}

func validateAgainstSchema(value any, schemaRaw json.RawMessage, path string) []string {
	var node schemaNode
	if err := json.Unmarshal(schemaRaw, &node); err != nil {
		return []string{path + ": schema node is not an object"}
	}
	schemaType := firstSchemaType(node)
	var errors []string
	if schemaType != "" && !jsonValueMatchesType(value, schemaType) {
		return []string{fmt.Sprintf("%s: expected %s", path, schemaType)}
	}
	if schemaType == "object" || len(node.Properties) > 0 {
		obj, ok := value.(map[string]any)
		if !ok {
			return []string{fmt.Sprintf("%s: expected object", path)}
		}
		for _, required := range node.Required {
			if _, ok := obj[required]; !ok {
				errors = append(errors, fmt.Sprintf("%s.%s: required property is missing", path, required))
			}
		}
		for name, childSchema := range node.Properties {
			childValue, ok := obj[name]
			if !ok {
				continue
			}
			errors = append(errors, validateAgainstSchema(childValue, childSchema, path+"."+name)...)
		}
	}
	if schemaType == "array" && len(node.Items) > 0 {
		items, ok := value.([]any)
		if !ok {
			return []string{fmt.Sprintf("%s: expected array", path)}
		}
		for i, item := range items {
			errors = append(errors, validateAgainstSchema(item, node.Items, fmt.Sprintf("%s[%d]", path, i))...)
		}
	}
	return errors
}

func compareSchemaCompatibility(oldRaw, newRaw json.RawMessage, path string) []string {
	var oldNode, newNode schemaNode
	if err := json.Unmarshal(oldRaw, &oldNode); err != nil {
		return []string{path + ": current schema node is not an object"}
	}
	if err := json.Unmarshal(newRaw, &newNode); err != nil {
		return []string{path + ": new schema node is not an object"}
	}
	var errors []string
	oldType := firstSchemaType(oldNode)
	newType := firstSchemaType(newNode)
	if oldType != "" && newType != "" && oldType != newType {
		errors = append(errors, fmt.Sprintf("%s: type changed from %s to %s", path, oldType, newType))
	}
	oldRequired := stringSet(oldNode.Required)
	for _, required := range newNode.Required {
		if _, ok := oldRequired[required]; !ok {
			errors = append(errors, fmt.Sprintf("%s.%s: new required property is not backward compatible", path, required))
		}
	}
	for name, oldChild := range oldNode.Properties {
		newChild, ok := newNode.Properties[name]
		if !ok {
			errors = append(errors, fmt.Sprintf("%s.%s: existing property was removed", path, name))
			continue
		}
		errors = append(errors, compareSchemaCompatibility(oldChild, newChild, path+"."+name)...)
	}
	return errors
}

func firstSchemaType(node schemaNode) string {
	switch value := node.Type.(type) {
	case string:
		return strings.TrimSpace(value)
	case []any:
		for _, item := range value {
			if s, ok := item.(string); ok && s != "null" {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

func jsonValueMatchesType(value any, schemaType string) bool {
	switch schemaType {
	case "object":
		_, ok := value.(map[string]any)
		return ok
	case "array":
		_, ok := value.([]any)
		return ok
	case "string":
		_, ok := value.(string)
		return ok
	case "number":
		_, ok := value.(float64)
		return ok
	case "integer":
		n, ok := value.(float64)
		return ok && math.Trunc(n) == n
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "null":
		return value == nil
	default:
		return true
	}
}

func stringSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		out[value] = struct{}{}
	}
	return out
}
