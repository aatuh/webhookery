package transform

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"webhookery/internal/canonicaljson"
)

var (
	ErrInvalidOperation = errors.New("invalid transformation operation")
	ErrProtectedPath    = errors.New("protected transformation path")
)

type Operation struct {
	Op    string          `json:"op"`
	Path  string          `json:"path"`
	From  string          `json:"from,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

func ParseOperations(raw []byte) ([]Operation, error) {
	var ops []Operation
	if err := json.Unmarshal(raw, &ops); err != nil {
		return nil, fmt.Errorf("%w: operations must be JSON array", ErrInvalidOperation)
	}
	if len(ops) == 0 {
		return nil, fmt.Errorf("%w: at least one operation is required", ErrInvalidOperation)
	}
	if len(ops) > 100 {
		return nil, fmt.Errorf("%w: at most 100 operations are supported", ErrInvalidOperation)
	}
	for i := range ops {
		ops[i].Op = strings.TrimSpace(strings.ToLower(ops[i].Op))
		ops[i].Path = strings.TrimSpace(ops[i].Path)
		ops[i].From = strings.TrimSpace(ops[i].From)
		if err := validateOperation(ops[i]); err != nil {
			return nil, err
		}
	}
	return ops, nil
}

func Apply(input []byte, ops []Operation) ([]byte, error) {
	var doc any
	if err := json.Unmarshal(input, &doc); err != nil {
		return nil, fmt.Errorf("%w: input must be JSON", ErrInvalidOperation)
	}
	for _, op := range ops {
		if err := validateOperation(op); err != nil {
			return nil, err
		}
		switch op.Op {
		case "set":
			var value any
			if len(op.Value) == 0 {
				return nil, fmt.Errorf("%w: set value is required", ErrInvalidOperation)
			}
			if err := json.Unmarshal(op.Value, &value); err != nil {
				return nil, fmt.Errorf("%w: set value must be JSON", ErrInvalidOperation)
			}
			if err := setValue(&doc, op.Path, value); err != nil {
				return nil, err
			}
		case "copy":
			value, err := getValue(doc, op.From)
			if err != nil {
				return nil, err
			}
			cloned, err := cloneJSON(value)
			if err != nil {
				return nil, err
			}
			if err := setValue(&doc, op.Path, cloned); err != nil {
				return nil, err
			}
		case "drop":
			if err := dropValue(&doc, op.Path); err != nil {
				return nil, err
			}
		case "redact":
			if err := setValue(&doc, op.Path, "[REDACTED]"); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("%w: unsupported op %q", ErrInvalidOperation, op.Op)
		}
	}
	return canonicaljson.Marshal(doc)
}

func validateOperation(op Operation) error {
	switch op.Op {
	case "set", "copy", "drop", "redact":
	default:
		return fmt.Errorf("%w: unsupported op %q", ErrInvalidOperation, op.Op)
	}
	if err := validatePointer(op.Path); err != nil {
		return err
	}
	if isProtectedPath(op.Path) {
		return fmt.Errorf("%w: %s", ErrProtectedPath, op.Path)
	}
	if op.Op == "copy" {
		if err := validatePointer(op.From); err != nil {
			return err
		}
		if isProtectedPath(op.From) {
			return fmt.Errorf("%w: %s", ErrProtectedPath, op.From)
		}
	}
	return nil
}

func validatePointer(path string) error {
	if path == "" || !strings.HasPrefix(path, "/") {
		return fmt.Errorf("%w: path must be a JSON Pointer", ErrInvalidOperation)
	}
	return nil
}

func isProtectedPath(path string) bool {
	for index, token := range pointerTokens(path) {
		switch token {
		case "raw_payload_id", "raw_payload_hash", "signature_verified", "verification", "verification_reason",
			"deduplication_key", "dedupe_status", "adapter_version_id", "normalized_envelope_id",
			"normalized_payload_hash", "envelope_hash", "data_hash", "metadata_hash", "audit":
			return true
		case "id", "tenant_id", "source_id", "provider", "provider_event_id":
			if index == 0 {
				return true
			}
		}
		if strings.HasSuffix(token, "_hash") || strings.HasSuffix(token, "_sha256") {
			return true
		}
	}
	return false
}

func pointerTokens(path string) []string {
	if path == "" || path == "/" {
		return nil
	}
	raw := strings.Split(strings.TrimPrefix(path, "/"), "/")
	out := make([]string, 0, len(raw))
	for _, part := range raw {
		part = strings.ReplaceAll(part, "~1", "/")
		part = strings.ReplaceAll(part, "~0", "~")
		out = append(out, part)
	}
	return out
}

func getValue(doc any, path string) (any, error) {
	current := doc
	for _, token := range pointerTokens(path) {
		switch node := current.(type) {
		case map[string]any:
			value, ok := node[token]
			if !ok {
				return nil, fmt.Errorf("%w: source path not found", ErrInvalidOperation)
			}
			current = value
		case []any:
			index, err := strconv.Atoi(token)
			if err != nil || index < 0 || index >= len(node) {
				return nil, fmt.Errorf("%w: array source path not found", ErrInvalidOperation)
			}
			current = node[index]
		default:
			return nil, fmt.Errorf("%w: source parent is not addressable", ErrInvalidOperation)
		}
	}
	return current, nil
}

func setValue(doc *any, path string, value any) error {
	tokens := pointerTokens(path)
	if len(tokens) == 0 {
		*doc = value
		return nil
	}
	parent, final, err := parentForSet(doc, tokens)
	if err != nil {
		return err
	}
	switch node := parent.(type) {
	case map[string]any:
		node[final] = value
	case []any:
		index, err := strconv.Atoi(final)
		if err != nil || index < 0 || index >= len(node) {
			return fmt.Errorf("%w: array path not found", ErrInvalidOperation)
		}
		node[index] = value
	default:
		return fmt.Errorf("%w: parent is not addressable", ErrInvalidOperation)
	}
	return nil
}

func parentForSet(doc *any, tokens []string) (any, string, error) {
	current := *doc
	if current == nil {
		current = map[string]any{}
		*doc = current
	}
	for _, token := range tokens[:len(tokens)-1] {
		switch node := current.(type) {
		case map[string]any:
			next, ok := node[token]
			if !ok {
				next = map[string]any{}
				node[token] = next
			}
			current = next
		case []any:
			index, err := strconv.Atoi(token)
			if err != nil || index < 0 || index >= len(node) {
				return nil, "", fmt.Errorf("%w: array path not found", ErrInvalidOperation)
			}
			current = node[index]
		default:
			return nil, "", fmt.Errorf("%w: parent is not addressable", ErrInvalidOperation)
		}
	}
	return current, tokens[len(tokens)-1], nil
}

func dropValue(doc *any, path string) error {
	tokens := pointerTokens(path)
	if len(tokens) == 0 {
		return fmt.Errorf("%w: cannot drop document root", ErrInvalidOperation)
	}
	return dropAt(doc, tokens)
}

func dropAt(current *any, tokens []string) error {
	final := tokens[0]
	switch node := (*current).(type) {
	case map[string]any:
		if len(tokens) > 1 {
			next, ok := node[final]
			if !ok {
				return fmt.Errorf("%w: path not found", ErrInvalidOperation)
			}
			if err := dropAt(&next, tokens[1:]); err != nil {
				return err
			}
			node[final] = next
			return nil
		}
		delete(node, final)
	case []any:
		index, err := strconv.Atoi(final)
		if err != nil || index < 0 || index >= len(node) {
			return fmt.Errorf("%w: array path not found", ErrInvalidOperation)
		}
		if len(tokens) > 1 {
			next := node[index]
			if err := dropAt(&next, tokens[1:]); err != nil {
				return err
			}
			node[index] = next
			return nil
		}
		copy(node[index:], node[index+1:])
		*current = node[:len(node)-1]
	default:
		return fmt.Errorf("%w: parent is not addressable", ErrInvalidOperation)
	}
	return nil
}

func cloneJSON(value any) (any, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}
