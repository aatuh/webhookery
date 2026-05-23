package auditchain

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"webhookery/internal/canonicaljson"
	"webhookery/internal/domain"
)

const CanonicalizationVersion = "audit-chain-v1"

type canonicalEvent struct {
	ID         string `json:"id"`
	TenantID   string `json:"tenant_id"`
	ActorID    string `json:"actor_id"`
	Action     string `json:"action"`
	Resource   string `json:"resource"`
	ResourceID string `json:"resource_id"`
	Reason     string `json:"reason"`
	OccurredAt string `json:"occurred_at"`
}

func EventHash(event domain.AuditEvent) (string, error) {
	raw, err := canonicaljson.Marshal(canonicalEvent{
		ID:         event.ID,
		TenantID:   event.TenantID,
		ActorID:    event.ActorID,
		Action:     event.Action,
		Resource:   event.Resource,
		ResourceID: event.ResourceID,
		Reason:     event.Reason,
		OccurredAt: event.OccurredAt.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return "", err
	}
	return hash(raw), nil
}

func ChainHash(previousChainHash, eventHash string) string {
	raw, _ := canonicaljson.Marshal(map[string]string{
		"canonicalization_version": CanonicalizationVersion,
		"event_hash":               eventHash,
		"previous_chain_hash":      previousChainHash,
	})
	return hash(raw)
}

func PreviousHashForSequence(sequence int64, previous string) string {
	if sequence <= 1 {
		return ""
	}
	return previous
}

func hash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
