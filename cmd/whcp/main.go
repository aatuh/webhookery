package main

import (
	"context"
	"fmt"
	"os"

	"webhookery/internal/adapters/deliveryhttp"
	"webhookery/internal/adapters/signalhttp"
	"webhookery/internal/worker"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "api":
		return runAPI()
	case "migrate":
		return runMigrate(args[1:])
	case "worker", "scheduler":
		return runWorker(args[1:])
	case "admin":
		return runAdmin(args[1:])
	case "api-keys":
		return runAPIKeys(args[1:])
	case "producer-clients":
		return runProducerClients(args[1:])
	case "producer-mtls-identities":
		return runProducerMTLSIdentities(args[1:])
	case "key-custody":
		return runKeyCustody(args[1:])
	case "doctor":
		return runDoctor(args[1:])
	case "identity-providers":
		return runIdentityProviders(args[1:])
	case "scim-tokens":
		return runSCIMTokens(args[1:])
	case "role-bindings":
		return runRoleBindings(args[1:])
	case "access-policies":
		return runAccessPolicies(args[1:])
	case "authz":
		return runAuthz(args[1:])
	case "events":
		return runEvents(args[1:])
	case "sources":
		return runSources(args[1:])
	case "provider-connections":
		return runProviderConnections(args[1:])
	case "adapters":
		return runAdapters(args[1:])
	case "endpoints":
		return runEndpoints(args[1:])
	case "subscriptions":
		return runSubscriptions(args[1:])
	case "retry-policies":
		return runRetryPolicies(args[1:])
	case "routes":
		return runRoutes(args[1:])
	case "transformations":
		return runTransformations(args[1:])
	case "deliveries":
		return runDeliveries(args[1:])
	case "replay-jobs":
		return runReplayJobs(args[1:])
	case "replay-approval-policies":
		return runReplayApprovalPolicies(args[1:])
	case "reconciliation-jobs":
		return runReconciliationJobs(args[1:])
	case "ops":
		return runOps(args[1:])
	case "alerts":
		return runAlerts(args[1:])
	case "notification-channels":
		return runNotificationChannels(args[1:])
	case "notification-deliveries":
		return runNotificationDeliveries(args[1:])
	case "siem-sinks":
		return runSIEMSinks(args[1:])
	case "siem-deliveries":
		return runSIEMDeliveries(args[1:])
	case "audit":
		return runAudit(args[1:])
	case "evidence":
		return runEvidence(args[1:])
	case "retention":
		return runRetention(args[1:])
	case "schemas":
		return runSchemas(args[1:])
	case "dead-letter":
		return runDeadLetter(args[1:])
	case "quarantine":
		return runQuarantine(args[1:])
	case "incidents":
		return runIncidents(args[1:])
	case "signatures":
		return runSignatures(args[1:])
	default:
		return usage()
	}
}

func usage() error {
	return fmt.Errorf("usage: whcp <api|worker|scheduler|migrate|admin|api-keys|producer-clients|producer-mtls-identities|key-custody|doctor|identity-providers|scim-tokens|role-bindings|access-policies|authz|events|sources|provider-connections|adapters|endpoints|subscriptions|retry-policies|routes|transformations|deliveries|replay-jobs|replay-approval-policies|reconciliation-jobs|ops|alerts|notification-channels|notification-deliveries|siem-sinks|siem-deliveries|audit|evidence|retention|schemas|dead-letter|quarantine|incidents|signatures>")
}

type doctorFinding struct {
	Severity string
	Check    string
	Message  string
}

type deliveryAdapter struct {
	client deliveryhttp.Client
}

func (d deliveryAdapter) Deliver(ctx context.Context, rawURL string, body []byte, secret []byte, keyID string, keyVersion int, mtlsCertPEM, mtlsKeyPEM []byte) (worker.DeliveryResult, error) {
	client := d.client
	client.Secret = secret
	client.SigningKeyID = keyID
	client.SigningKeyVersion = keyVersion
	client.MTLSClientCertPEM = mtlsCertPEM
	client.MTLSClientKeyPEM = mtlsKeyPEM
	result, err := client.Deliver(ctx, rawURL, body)
	return worker.DeliveryResult{
		StatusCode:        result.StatusCode,
		ResponseBody:      result.ResponseBody,
		ResponseTruncated: result.ResponseTruncated,
		FailureClass:      result.FailureClass,
	}, err
}

type signalAdapter struct {
	client signalhttp.Client
}

func (s signalAdapter) Deliver(ctx context.Context, rawURL string, body []byte, secret []byte) (worker.SignalDeliveryResult, error) {
	result, err := s.client.Deliver(ctx, rawURL, body, secret)
	return worker.SignalDeliveryResult{
		StatusCode:        result.StatusCode,
		ResponseBody:      result.ResponseBody,
		ResponseTruncated: result.ResponseTruncated,
		FailureClass:      result.FailureClass,
	}, err
}
