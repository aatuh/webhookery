package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestStoreDoesNotOwnDeliveryFanoutOrchestration(t *testing.T) {
	body, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, forbidden := range []string{
		"func (s *Store) ProcessOutbox",
		"func (s *Store) createDeliveriesForEvent",
		"createDeliveriesForEventWithOptions",
		"createReplayDeliveries",
		"deliveryCreationOptions",
		"currentDeliveryReplayConfig",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("delivery fanout orchestration must stay out of postgres.Store; found %q", forbidden)
		}
	}
}
