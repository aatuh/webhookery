# Webhookery API Contract Matrix

Generated from `openapi.yaml`. Do not edit operation rows manually; run `make openapi-reference-generate`.

Total operations: `214`.

| Method | Path | Operation ID | Tag | Auth | Parameters | Request | Responses |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `GET` | `/healthz` | `getHealthz` | System | none | - | - | 200 |
| `GET` | `/metrics` | `getMetrics` | System | none | - | - | 200 |
| `GET` | `/openapi.yaml` | `getOpenapiYaml` | System | none | - | - | 200 |
| `GET` | `/readyz` | `getReadyz` | System | none | - | - | 200, 503 |
| `GET` | `/v1/access-policies` | `getAccessPolicies` | Auth And Identity | bearerAuth | - | - | 200 |
| `POST` | `/v1/access-policies` | `postAccessPolicies` | Auth And Identity | bearerAuth | - | application/json | 201 |
| `PATCH` | `/v1/access-policies/{policy_id}` | `patchAccessPoliciesPolicyId` | Auth And Identity | bearerAuth | path:policy_id | application/json | 200 |
| `DELETE` | `/v1/access-policies/{policy_id}` | `deleteAccessPoliciesPolicyId` | Auth And Identity | bearerAuth | path:policy_id | application/json | 200 |
| `GET` | `/v1/adapters` | `getAdapters` | Sources And Providers | bearerAuth | ref:Limit | - | 200 |
| `POST` | `/v1/adapters` | `postAdapters` | Sources And Providers | bearerAuth | - | application/json | 201 |
| `GET` | `/v1/adapters/{adapter_id}` | `getAdaptersAdapterId` | Sources And Providers | bearerAuth | path:adapter_id | - | 200 |
| `GET` | `/v1/adapters/{adapter_id}/versions` | `getAdaptersAdapterIdVersions` | Sources And Providers | bearerAuth | path:adapter_id, ref:Limit | - | 200 |
| `POST` | `/v1/adapters/{adapter_id}/versions` | `postAdaptersAdapterIdVersions` | Sources And Providers | bearerAuth | path:adapter_id | application/json | 201 |
| `POST` | `/v1/adapters/{adapter_id}/versions/{version_id}/test-vectors` | `postAdaptersAdapterIdVersionsVersionIdTestVectors` | Sources And Providers | bearerAuth | path:adapter_id, path:version_id | application/json | 201 |
| `POST` | `/v1/adapters/{adapter_id}/versions/{version_id}:transition` | `postAdaptersAdapterIdVersionsVersionIdTransition` | Sources And Providers | bearerAuth | path:adapter_id, path:version_id | application/json | 200 |
| `GET` | `/v1/admin/retention-policies` | `getAdminRetentionPolicies` | Audit And Retention | bearerAuth | ref:Limit | - | 200 |
| `POST` | `/v1/admin/retention-policies` | `postAdminRetentionPolicies` | Audit And Retention | bearerAuth | - | application/json | 201 |
| `PATCH` | `/v1/admin/retention-policies/{policy_id}` | `patchAdminRetentionPoliciesPolicyId` | Audit And Retention | bearerAuth | path:policy_id | application/json | 200 |
| `GET` | `/v1/alert-firings` | `getAlertFirings` | Operations | bearerAuth | ref:Limit, query:state | - | 200 |
| `GET` | `/v1/alert-firings/{firing_id}` | `getAlertFiringsFiringId` | Operations | bearerAuth | path:firing_id | - | 200 |
| `POST` | `/v1/alert-firings/{firing_id}:acknowledge` | `postAlertFiringsFiringIdAcknowledge` | Operations | bearerAuth | path:firing_id | application/json | 200 |
| `GET` | `/v1/alerts` | `getAlerts` | Operations | bearerAuth | ref:Limit | - | 200 |
| `POST` | `/v1/alerts` | `postAlerts` | Operations | bearerAuth | - | application/json | 201, 403 |
| `GET` | `/v1/alerts/{alert_id}` | `getAlertsAlertId` | Operations | bearerAuth | path:alert_id | - | 200 |
| `PATCH` | `/v1/alerts/{alert_id}` | `patchAlertsAlertId` | Operations | bearerAuth | path:alert_id | application/json | 200 |
| `DELETE` | `/v1/alerts/{alert_id}` | `deleteAlertsAlertId` | Operations | bearerAuth | path:alert_id | application/json | 200 |
| `GET` | `/v1/api-keys` | `getApiKeys` | API Keys | bearerAuth | ref:Limit | - | 200 |
| `POST` | `/v1/api-keys` | `postApiKeys` | API Keys | bearerAuth | - | application/json | 201, 403 |
| `POST` | `/v1/api-keys/{api_key_id}:revoke` | `postApiKeysApiKeyIdRevoke` | API Keys | bearerAuth | path:api_key_id | application/json | 200 |
| `GET` | `/v1/audit-chain/anchors` | `getAuditChainAnchors` | Audit And Retention | bearerAuth | ref:Limit | - | 200 |
| `GET` | `/v1/audit-chain/anchors/{anchor_id}` | `getAuditChainAnchorsAnchorId` | Audit And Retention | bearerAuth | path:anchor_id | - | 200, 404 |
| `GET` | `/v1/audit-chain/head` | `getAuditChainHead` | Audit And Retention | bearerAuth | - | - | 200 |
| `POST` | `/v1/audit-chain:anchor` | `postAuditChainAnchor` | Audit And Retention | bearerAuth | - | application/json | 201, 403 |
| `POST` | `/v1/audit-chain:verify` | `postAuditChainVerify` | Audit And Retention | bearerAuth | - | application/json | 200 |
| `GET` | `/v1/audit-events` | `getAuditEvents` | Audit And Retention | bearerAuth | - | - | 200 |
| `POST` | `/v1/audit-events:export` | `postAuditEventsExport` | Audit And Retention | bearerAuth | - | application/json | 202, 403 |
| `GET` | `/v1/audit-exports` | `getAuditExports` | Audit And Retention | bearerAuth | ref:Limit | - | 200 |
| `GET` | `/v1/audit-exports/{export_id}` | `getAuditExportsExportId` | Audit And Retention | bearerAuth | path:export_id | - | 200, 404 |
| `GET` | `/v1/audit-exports/{export_id}:download` | `getAuditExportsExportIdDownload` | Audit And Retention | bearerAuth | path:export_id | - | 200, 403, 410 |
| `POST` | `/v1/auth/logout` | `postAuthLogout` | Auth And Identity | bearerAuth | - | - | 204 |
| `GET` | `/v1/auth/oidc/callback` | `getAuthOidcCallback` | Auth And Identity | none | query:state, query:code | - | 200 |
| `GET` | `/v1/auth/oidc/login` | `getAuthOidcLogin` | Auth And Identity | none | query:tenant_id, query:provider_id, query:redirect_after | - | 302 |
| `GET` | `/v1/auth/session` | `getAuthSession` | Auth And Identity | bearerAuth | - | - | 200 |
| `GET` | `/v1/auth/sessions` | `getAuthSessions` | Auth And Identity | bearerAuth | ref:Limit | - | 200 |
| `POST` | `/v1/auth/sessions/{session_id}:revoke` | `postAuthSessionsSessionIdRevoke` | Auth And Identity | bearerAuth | path:session_id | application/json | 200 |
| `POST` | `/v1/authz:explain` | `postAuthzExplain` | Auth And Identity | bearerAuth | - | application/json | 200 |
| `GET` | `/v1/dead-letter` | `getDeadLetter` | Delivery And Replay | bearerAuth | - | - | 200 |
| `POST` | `/v1/dead-letter/{entry_id}:release` | `postDeadLetterEntryIdRelease` | Delivery And Replay | bearerAuth | path:entry_id | application/json | 202 |
| `POST` | `/v1/dead-letter:bulk-release` | `postDeadLetterBulkRelease` | Delivery And Replay | bearerAuth | - | application/json | 202 |
| `GET` | `/v1/deliveries` | `getDeliveries` | Delivery And Replay | bearerAuth | - | - | 200 |
| `GET` | `/v1/deliveries/{delivery_id}/attempts` | `getDeliveriesDeliveryIdAttempts` | Delivery And Replay | bearerAuth | path:delivery_id | - | 200 |
| `POST` | `/v1/deliveries/{delivery_id}:cancel` | `postDeliveriesDeliveryIdCancel` | Delivery And Replay | bearerAuth | path:delivery_id | application/json | 200 |
| `POST` | `/v1/deliveries/{delivery_id}:retry` | `postDeliveriesDeliveryIdRetry` | Delivery And Replay | bearerAuth | path:delivery_id | application/json | 202 |
| `GET` | `/v1/delivery-attempts/{attempt_id}` | `getDeliveryAttemptsAttemptId` | Delivery And Replay | bearerAuth | path:attempt_id | - | 200 |
| `GET` | `/v1/endpoint-health` | `getEndpointHealth` | Operations | bearerAuth | - | - | 200 |
| `GET` | `/v1/endpoints` | `getEndpoints` | Endpoints And Routing | bearerAuth | - | - | 200 |
| `POST` | `/v1/endpoints` | `postEndpoints` | Endpoints And Routing | bearerAuth | - | application/json | 201 |
| `GET` | `/v1/endpoints/{endpoint_id}` | `getEndpointsEndpointId` | Endpoints And Routing | bearerAuth | path:endpoint_id | - | 200, 404 |
| `PATCH` | `/v1/endpoints/{endpoint_id}` | `patchEndpointsEndpointId` | Endpoints And Routing | bearerAuth | path:endpoint_id | application/json | 200, 422 |
| `DELETE` | `/v1/endpoints/{endpoint_id}` | `deleteEndpointsEndpointId` | Endpoints And Routing | bearerAuth | path:endpoint_id | application/json | 200 |
| `POST` | `/v1/endpoints/{endpoint_id}/secrets:rotate` | `postEndpointsEndpointIdSecretsRotate` | Endpoints And Routing | bearerAuth | path:endpoint_id | application/json | 200 |
| `POST` | `/v1/endpoints/{endpoint_id}:test` | `postEndpointsEndpointIdTest` | Endpoints And Routing | bearerAuth | path:endpoint_id | application/json | 202 |
| `POST` | `/v1/endpoints:validate-url` | `postEndpointsValidateUrl` | Endpoints And Routing | bearerAuth | - | - | 200 |
| `GET` | `/v1/event-types` | `getEventTypes` | Schemas And Transformations | bearerAuth | - | - | 200 |
| `POST` | `/v1/event-types` | `postEventTypes` | Schemas And Transformations | bearerAuth | - | application/json | 201 |
| `GET` | `/v1/event-types/{event_type}` | `getEventTypesEventType` | Schemas And Transformations | bearerAuth | path:event_type | - | 200, 404 |
| `PATCH` | `/v1/event-types/{event_type}` | `patchEventTypesEventType` | Schemas And Transformations | bearerAuth | path:event_type | application/json | 200 |
| `DELETE` | `/v1/event-types/{event_type}` | `deleteEventTypesEventType` | Schemas And Transformations | bearerAuth | path:event_type | application/json | 200 |
| `GET` | `/v1/event-types/{event_type}/schemas` | `getEventTypesEventTypeSchemas` | Schemas And Transformations | bearerAuth | path:event_type | - | 200 |
| `POST` | `/v1/event-types/{event_type}/schemas` | `postEventTypesEventTypeSchemas` | Schemas And Transformations | bearerAuth | path:event_type | application/json | 201 |
| `GET` | `/v1/event-types/{event_type}/schemas/{schema_version}` | `getEventTypesEventTypeSchemasSchemaVersion` | Schemas And Transformations | bearerAuth | path:event_type, path:schema_version | - | 200, 404 |
| `PATCH` | `/v1/event-types/{event_type}/schemas/{schema_version}` | `patchEventTypesEventTypeSchemasSchemaVersion` | Schemas And Transformations | bearerAuth | path:event_type, path:schema_version | application/json | 200 |
| `DELETE` | `/v1/event-types/{event_type}/schemas/{schema_version}` | `deleteEventTypesEventTypeSchemasSchemaVersion` | Schemas And Transformations | bearerAuth | path:event_type, path:schema_version | application/json | 200 |
| `POST` | `/v1/event-types/{event_type}/schemas/{schema_version}:check-compatibility` | `postEventTypesEventTypeSchemasSchemaVersionCheckCompatibility` | Schemas And Transformations | bearerAuth | path:event_type, path:schema_version | application/json | 200 |
| `POST` | `/v1/event-types/{event_type}/schemas/{schema_version}:validate` | `postEventTypesEventTypeSchemasSchemaVersionValidate` | Schemas And Transformations | bearerAuth | path:event_type, path:schema_version | application/json | 200 |
| `GET` | `/v1/events` | `getEvents` | Events And Ingestion | bearerAuth | query:limit, query:provider, query:external_id, query:delivery_id, query:status, query:verification, query:received_after, query:route_id | - | 200, 400 |
| `POST` | `/v1/events` | `postEvents` | Events And Ingestion | bearerAuth, producerMTLS | - | application/json | 202, 400, 401, 403 |
| `GET` | `/v1/events/{event_id}` | `getEventsEventId` | Events And Ingestion | bearerAuth | path:event_id | - | 200, 404 |
| `GET` | `/v1/events/{event_id}/normalized` | `getEventsEventIdNormalized` | Events And Ingestion | bearerAuth | path:event_id, query:include_data | - | 200, 403, 410 |
| `GET` | `/v1/events/{event_id}/raw` | `getEventsEventIdRaw` | Events And Ingestion | bearerAuth | path:event_id, query:reason | - | 200, 400, 403, 410 |
| `GET` | `/v1/events/{event_id}/timeline` | `getEventsEventIdTimeline` | Events And Ingestion | bearerAuth | path:event_id, ref:Limit | - | 200 |
| `GET` | `/v1/identity-providers` | `getIdentityProviders` | Auth And Identity | bearerAuth | ref:Limit | - | 200 |
| `POST` | `/v1/identity-providers` | `postIdentityProviders` | Auth And Identity | bearerAuth | - | application/json | 201 |
| `GET` | `/v1/identity-providers/{provider_id}` | `getIdentityProvidersProviderId` | Auth And Identity | bearerAuth | path:provider_id | - | 200 |
| `PATCH` | `/v1/identity-providers/{provider_id}` | `patchIdentityProvidersProviderId` | Auth And Identity | bearerAuth | path:provider_id | application/json | 200 |
| `DELETE` | `/v1/identity-providers/{provider_id}` | `deleteIdentityProvidersProviderId` | Auth And Identity | bearerAuth | path:provider_id | application/json | 200 |
| `POST` | `/v1/identity-providers/{provider_id}:test` | `postIdentityProvidersProviderIdTest` | Auth And Identity | bearerAuth | path:provider_id | application/json | 200 |
| `GET` | `/v1/incidents` | `getIncidents` | Incidents | bearerAuth | ref:Limit | - | 200 |
| `POST` | `/v1/incidents` | `postIncidents` | Incidents | bearerAuth | - | application/json | 201, 403 |
| `GET` | `/v1/incidents/{incident_id}` | `getIncidentsIncidentId` | Incidents | bearerAuth | path:incident_id | - | 200, 404 |
| `POST` | `/v1/incidents/{incident_id}/events` | `postIncidentsIncidentIdEvents` | Incidents | bearerAuth | path:incident_id | application/json | 201, 404 |
| `DELETE` | `/v1/incidents/{incident_id}/events/{event_id}` | `deleteIncidentsIncidentIdEventsEventId` | Incidents | bearerAuth | path:incident_id, path:event_id | application/json | 200 |
| `POST` | `/v1/incidents/{incident_id}/evidence-export` | `postIncidentsIncidentIdEvidenceExport` | Incidents | bearerAuth | path:incident_id | application/json | 202 |
| `POST` | `/v1/incidents/{incident_id}/generate-report` | `postIncidentsIncidentIdGenerateReport` | Incidents | bearerAuth | path:incident_id | application/json | 201 |
| `GET` | `/v1/incidents/{incident_id}/report` | `getIncidentsIncidentIdReport` | Incidents | bearerAuth | path:incident_id, query:format | - | 200 |
| `POST` | `/v1/ingest/cloudevents/{source_id}` | `postIngestCloudeventsSourceId` | Events And Ingestion | none | - | - | 200, 431 |
| `POST` | `/v1/ingest/generic-jwt/{source_id}` | `postIngestGenericJwtSourceId` | Events And Ingestion | none | - | - | 200, 401, 431 |
| `POST` | `/v1/ingest/github/{source_id}` | `postIngestGithubSourceId` | Events And Ingestion | none | - | - | 200, 431 |
| `POST` | `/v1/ingest/shopify/{source_id}` | `postIngestShopifySourceId` | Events And Ingestion | none | - | - | 200, 431 |
| `POST` | `/v1/ingest/slack/{source_id}` | `postIngestSlackSourceId` | Events And Ingestion | none | - | - | 200, 431 |
| `POST` | `/v1/ingest/stripe/{source_id}` | `postIngestStripeSourceId` | Events And Ingestion | none | - | - | 200, 431 |
| `POST` | `/v1/ingest/{tenant_id}/{source_id}` | `postIngestTenantIdSourceId` | Events And Ingestion | none | path:tenant_id, path:source_id | application/json | 200, 401, 413, 431, 503 |
| `GET` | `/v1/notification-channels` | `getNotificationChannels` | Signal Egress | bearerAuth | ref:Limit | - | 200 |
| `POST` | `/v1/notification-channels` | `postNotificationChannels` | Signal Egress | bearerAuth | - | application/json | 201 |
| `GET` | `/v1/notification-channels/{channel_id}` | `getNotificationChannelsChannelId` | Signal Egress | bearerAuth | path:channel_id | - | 200 |
| `PATCH` | `/v1/notification-channels/{channel_id}` | `patchNotificationChannelsChannelId` | Signal Egress | bearerAuth | path:channel_id | application/json | 200 |
| `DELETE` | `/v1/notification-channels/{channel_id}` | `deleteNotificationChannelsChannelId` | Signal Egress | bearerAuth | path:channel_id | application/json | 200 |
| `POST` | `/v1/notification-channels/{channel_id}:test` | `postNotificationChannelsChannelIdTest` | Signal Egress | bearerAuth | path:channel_id | application/json | 202 |
| `GET` | `/v1/notification-deliveries` | `getNotificationDeliveries` | Signal Egress | bearerAuth | ref:Limit, query:state | - | 200 |
| `GET` | `/v1/notification-deliveries/{delivery_id}/attempts` | `getNotificationDeliveriesDeliveryIdAttempts` | Signal Egress | bearerAuth | path:delivery_id, ref:Limit | - | 200 |
| `POST` | `/v1/notification-deliveries/{delivery_id}:retry` | `postNotificationDeliveriesDeliveryIdRetry` | Signal Egress | bearerAuth | path:delivery_id | application/json | 200 |
| `POST` | `/v1/oauth/token` | `postOauthToken` | Producer Trust | basicAuth | - | application/x-www-form-urlencoded | 200, 400, 401 |
| `GET` | `/v1/ops/config` | `getOpsConfig` | Operations | bearerAuth | - | - | 200 |
| `GET` | `/v1/ops/metrics` | `getOpsMetrics` | Operations | bearerAuth | - | - | 200 |
| `GET` | `/v1/ops/metrics/rollups` | `getOpsMetricsRollups` | Operations | bearerAuth | ref:Limit, query:metric_name | - | 200, 400 |
| `GET` | `/v1/ops/queues` | `getOpsQueues` | Operations | bearerAuth | - | - | 200 |
| `GET` | `/v1/ops/storage` | `getOpsStorage` | Operations | bearerAuth | - | - | 200 |
| `GET` | `/v1/ops/workers` | `getOpsWorkers` | Operations | bearerAuth | ref:Limit | - | 200 |
| `GET` | `/v1/ops/workers/{worker_id}` | `getOpsWorkersWorkerId` | Operations | bearerAuth | path:worker_id | - | 200, 404 |
| `GET` | `/v1/producer-clients` | `getProducerClients` | Producer Trust | bearerAuth | ref:Limit | - | 200 |
| `POST` | `/v1/producer-clients` | `postProducerClients` | Producer Trust | bearerAuth | - | application/json | 201, 403 |
| `GET` | `/v1/producer-clients/{client_id}` | `getProducerClientsClientId` | Producer Trust | bearerAuth | path:client_id | - | 200 |
| `PATCH` | `/v1/producer-clients/{client_id}` | `patchProducerClientsClientId` | Producer Trust | bearerAuth | path:client_id | application/json | 200 |
| `DELETE` | `/v1/producer-clients/{client_id}` | `deleteProducerClientsClientId` | Producer Trust | bearerAuth | path:client_id | application/json | 200 |
| `POST` | `/v1/producer-clients/{client_id}/secrets:rotate` | `postProducerClientsClientIdSecretsRotate` | Producer Trust | bearerAuth | path:client_id | application/json | 200 |
| `GET` | `/v1/producer-mtls-identities` | `getProducerMtlsIdentities` | Producer Trust | bearerAuth | ref:Limit | - | 200 |
| `POST` | `/v1/producer-mtls-identities` | `postProducerMtlsIdentities` | Producer Trust | bearerAuth | - | application/json | 201 |
| `GET` | `/v1/producer-mtls-identities/{identity_id}` | `getProducerMtlsIdentitiesIdentityId` | Producer Trust | bearerAuth | path:identity_id | - | 200 |
| `PATCH` | `/v1/producer-mtls-identities/{identity_id}` | `patchProducerMtlsIdentitiesIdentityId` | Producer Trust | bearerAuth | path:identity_id | application/json | 200 |
| `DELETE` | `/v1/producer-mtls-identities/{identity_id}` | `deleteProducerMtlsIdentitiesIdentityId` | Producer Trust | bearerAuth | path:identity_id | application/json | 200 |
| `POST` | `/v1/producer-mtls-identities/{identity_id}:verify` | `postProducerMtlsIdentitiesIdentityIdVerify` | Producer Trust | bearerAuth | path:identity_id | application/json | 200 |
| `GET` | `/v1/provider-connections` | `getProviderConnections` | Sources And Providers | bearerAuth | ref:Limit | - | 200 |
| `POST` | `/v1/provider-connections` | `postProviderConnections` | Sources And Providers | bearerAuth | - | application/json | 201 |
| `GET` | `/v1/provider-connections/{connection_id}` | `getProviderConnectionsConnectionId` | Sources And Providers | bearerAuth | path:connection_id | - | 200 |
| `POST` | `/v1/provider-connections/{connection_id}:revoke` | `postProviderConnectionsConnectionIdRevoke` | Sources And Providers | bearerAuth | path:connection_id | application/json | 200 |
| `POST` | `/v1/provider-connections/{connection_id}:verify` | `postProviderConnectionsConnectionIdVerify` | Sources And Providers | bearerAuth | path:connection_id | application/json | 200 |
| `GET` | `/v1/quarantine` | `getQuarantine` | Delivery And Replay | bearerAuth | - | - | 200 |
| `POST` | `/v1/quarantine/{entry_id}:approve` | `postQuarantineEntryIdApprove` | Delivery And Replay | bearerAuth | path:entry_id | - | 200 |
| `POST` | `/v1/quarantine/{entry_id}:reject` | `postQuarantineEntryIdReject` | Delivery And Replay | bearerAuth | path:entry_id | - | 200 |
| `GET` | `/v1/reconciliation-jobs` | `getReconciliationJobs` | Reconciliation | bearerAuth | ref:Limit | - | 200 |
| `POST` | `/v1/reconciliation-jobs` | `postReconciliationJobs` | Reconciliation | bearerAuth | - | application/json | 201 |
| `GET` | `/v1/reconciliation-jobs/{job_id}` | `getReconciliationJobsJobId` | Reconciliation | bearerAuth | path:job_id | - | 200 |
| `GET` | `/v1/reconciliation-jobs/{job_id}/items` | `getReconciliationJobsJobIdItems` | Reconciliation | bearerAuth | path:job_id, ref:Limit | - | 200 |
| `POST` | `/v1/reconciliation-jobs/{job_id}:cancel` | `postReconciliationJobsJobIdCancel` | Reconciliation | bearerAuth | path:job_id | application/json | 200 |
| `POST` | `/v1/reconciliation-jobs:dry-run` | `postReconciliationJobsDryRun` | Reconciliation | bearerAuth | - | application/json | 200 |
| `GET` | `/v1/replay-approval-policies` | `getReplayApprovalPolicies` | Delivery And Replay | bearerAuth | - | - | 200 |
| `POST` | `/v1/replay-approval-policies` | `postReplayApprovalPolicies` | Delivery And Replay | bearerAuth | - | application/json | 201 |
| `DELETE` | `/v1/replay-approval-policies/{policy_id}` | `deleteReplayApprovalPoliciesPolicyId` | Delivery And Replay | bearerAuth | path:policy_id | application/json | 200 |
| `GET` | `/v1/replay-jobs` | `getReplayJobs` | Delivery And Replay | bearerAuth | - | - | 200 |
| `POST` | `/v1/replay-jobs` | `postReplayJobs` | Delivery And Replay | bearerAuth | - | application/json | 202 |
| `POST` | `/v1/replay-jobs/preview` | `postReplayJobsPreview` | Delivery And Replay | bearerAuth | - | application/json | 200 |
| `POST` | `/v1/replay-jobs/{replay_job_id}:approve` | `postReplayJobsReplayJobIdApprove` | Delivery And Replay | bearerAuth | path:replay_job_id | application/json | 200 |
| `POST` | `/v1/replay-jobs/{replay_job_id}:cancel` | `postReplayJobsReplayJobIdCancel` | Delivery And Replay | bearerAuth | path:replay_job_id | application/json | 200 |
| `POST` | `/v1/replay-jobs/{replay_job_id}:pause` | `postReplayJobsReplayJobIdPause` | Delivery And Replay | bearerAuth | path:replay_job_id | application/json | 200 |
| `POST` | `/v1/replay-jobs/{replay_job_id}:resume` | `postReplayJobsReplayJobIdResume` | Delivery And Replay | bearerAuth | path:replay_job_id | application/json | 200 |
| `POST` | `/v1/replay-jobs:dry-run` | `postReplayJobsDryRun` | Delivery And Replay | bearerAuth | - | application/json | 200 |
| `GET` | `/v1/retry-policies` | `getRetryPolicies` | Endpoints And Routing | bearerAuth | - | - | 200 |
| `POST` | `/v1/retry-policies` | `postRetryPolicies` | Endpoints And Routing | bearerAuth | - | application/json | 201 |
| `GET` | `/v1/retry-policies/{retry_policy_id}` | `getRetryPoliciesRetryPolicyId` | Endpoints And Routing | bearerAuth | path:retry_policy_id | - | 200, 404 |
| `PATCH` | `/v1/retry-policies/{retry_policy_id}` | `patchRetryPoliciesRetryPolicyId` | Endpoints And Routing | bearerAuth | path:retry_policy_id | application/json | 200 |
| `DELETE` | `/v1/retry-policies/{retry_policy_id}` | `deleteRetryPoliciesRetryPolicyId` | Endpoints And Routing | bearerAuth | path:retry_policy_id | application/json | 200 |
| `GET` | `/v1/role-bindings` | `getRoleBindings` | Auth And Identity | bearerAuth | - | - | 200 |
| `POST` | `/v1/role-bindings` | `postRoleBindings` | Auth And Identity | bearerAuth | - | application/json | 201 |
| `PATCH` | `/v1/role-bindings/{binding_id}` | `patchRoleBindingsBindingId` | Auth And Identity | bearerAuth | path:binding_id | application/json | 200 |
| `DELETE` | `/v1/role-bindings/{binding_id}` | `deleteRoleBindingsBindingId` | Auth And Identity | bearerAuth | path:binding_id | application/json | 200 |
| `GET` | `/v1/routes` | `getRoutes` | Endpoints And Routing | bearerAuth | - | - | 200 |
| `POST` | `/v1/routes` | `postRoutes` | Endpoints And Routing | bearerAuth | - | application/json | 201 |
| `GET` | `/v1/routes/{route_id}` | `getRoutesRouteId` | Endpoints And Routing | bearerAuth | path:route_id | - | 200, 404 |
| `PATCH` | `/v1/routes/{route_id}` | `patchRoutesRouteId` | Endpoints And Routing | bearerAuth | path:route_id | application/json | 200 |
| `DELETE` | `/v1/routes/{route_id}` | `deleteRoutesRouteId` | Endpoints And Routing | bearerAuth | path:route_id | application/json | 200 |
| `GET` | `/v1/routes/{route_id}/versions` | `getRoutesRouteIdVersions` | Endpoints And Routing | bearerAuth | path:route_id, ref:Limit | - | 200 |
| `POST` | `/v1/routes/{route_id}:activate` | `postRoutesRouteIdActivate` | Endpoints And Routing | bearerAuth | path:route_id | - | 200 |
| `POST` | `/v1/routes/{route_id}:dry-run` | `postRoutesRouteIdDryRun` | Endpoints And Routing | bearerAuth | path:route_id | - | 200 |
| `GET` | `/v1/scim-tokens` | `getScimTokens` | Auth And Identity | bearerAuth | - | - | 200 |
| `POST` | `/v1/scim-tokens` | `postScimTokens` | Auth And Identity | bearerAuth | - | application/json | 201 |
| `DELETE` | `/v1/scim-tokens/{token_id}` | `deleteScimTokensTokenId` | Auth And Identity | bearerAuth | path:token_id | application/json | 200 |
| `GET` | `/v1/scim/v2/Groups` | `getScimV2Groups` | Auth And Identity | bearerAuth | - | - | 200 |
| `POST` | `/v1/scim/v2/Groups` | `postScimV2Groups` | Auth And Identity | bearerAuth | - | application/json | 201 |
| `GET` | `/v1/scim/v2/Groups/{group_id}` | `getScimV2GroupsGroupId` | Auth And Identity | bearerAuth | path:group_id | - | 200 |
| `PUT` | `/v1/scim/v2/Groups/{group_id}` | `putScimV2GroupsGroupId` | Auth And Identity | bearerAuth | path:group_id | application/json | 200 |
| `PATCH` | `/v1/scim/v2/Groups/{group_id}` | `patchScimV2GroupsGroupId` | Auth And Identity | bearerAuth | path:group_id | application/json | 200 |
| `DELETE` | `/v1/scim/v2/Groups/{group_id}` | `deleteScimV2GroupsGroupId` | Auth And Identity | bearerAuth | path:group_id | - | 200 |
| `GET` | `/v1/scim/v2/Users` | `getScimV2Users` | Auth And Identity | bearerAuth | - | - | 200 |
| `POST` | `/v1/scim/v2/Users` | `postScimV2Users` | Auth And Identity | bearerAuth | - | application/json | 201 |
| `GET` | `/v1/scim/v2/Users/{user_id}` | `getScimV2UsersUserId` | Auth And Identity | bearerAuth | path:user_id | - | 200 |
| `PUT` | `/v1/scim/v2/Users/{user_id}` | `putScimV2UsersUserId` | Auth And Identity | bearerAuth | path:user_id | application/json | 200 |
| `PATCH` | `/v1/scim/v2/Users/{user_id}` | `patchScimV2UsersUserId` | Auth And Identity | bearerAuth | path:user_id | application/json | 200 |
| `DELETE` | `/v1/scim/v2/Users/{user_id}` | `deleteScimV2UsersUserId` | Auth And Identity | bearerAuth | path:user_id | - | 200 |
| `GET` | `/v1/siem-deliveries` | `getSiemDeliveries` | Signal Egress | bearerAuth | ref:Limit, query:state | - | 200 |
| `GET` | `/v1/siem-deliveries/{delivery_id}/attempts` | `getSiemDeliveriesDeliveryIdAttempts` | Signal Egress | bearerAuth | path:delivery_id, ref:Limit | - | 200 |
| `POST` | `/v1/siem-deliveries/{delivery_id}:retry` | `postSiemDeliveriesDeliveryIdRetry` | Signal Egress | bearerAuth | path:delivery_id | application/json | 200 |
| `GET` | `/v1/siem-sinks` | `getSiemSinks` | Signal Egress | bearerAuth | ref:Limit | - | 200 |
| `POST` | `/v1/siem-sinks` | `postSiemSinks` | Signal Egress | bearerAuth | - | application/json | 201 |
| `GET` | `/v1/siem-sinks/{sink_id}` | `getSiemSinksSinkId` | Signal Egress | bearerAuth | path:sink_id | - | 200 |
| `PATCH` | `/v1/siem-sinks/{sink_id}` | `patchSiemSinksSinkId` | Signal Egress | bearerAuth | path:sink_id | application/json | 200 |
| `DELETE` | `/v1/siem-sinks/{sink_id}` | `deleteSiemSinksSinkId` | Signal Egress | bearerAuth | path:sink_id | application/json | 200 |
| `POST` | `/v1/siem-sinks/{sink_id}:test` | `postSiemSinksSinkIdTest` | Signal Egress | bearerAuth | path:sink_id | application/json | 202 |
| `GET` | `/v1/sources` | `getSources` | Sources And Providers | bearerAuth | - | - | 200 |
| `POST` | `/v1/sources` | `postSources` | Sources And Providers | bearerAuth | - | application/json | 201 |
| `GET` | `/v1/sources/{source_id}` | `getSourcesSourceId` | Sources And Providers | bearerAuth | path:source_id | - | 200, 404 |
| `PATCH` | `/v1/sources/{source_id}` | `patchSourcesSourceId` | Sources And Providers | bearerAuth | path:source_id | application/json | 200 |
| `DELETE` | `/v1/sources/{source_id}` | `deleteSourcesSourceId` | Sources And Providers | bearerAuth | path:source_id | application/json | 200 |
| `POST` | `/v1/sources/{source_id}/secrets:rotate` | `postSourcesSourceIdSecretsRotate` | Sources And Providers | bearerAuth | path:source_id | application/json | 200 |
| `GET` | `/v1/subscriptions` | `getSubscriptions` | Endpoints And Routing | bearerAuth | - | - | 200 |
| `POST` | `/v1/subscriptions` | `postSubscriptions` | Endpoints And Routing | bearerAuth | - | application/json | 201 |
| `GET` | `/v1/subscriptions/{subscription_id}` | `getSubscriptionsSubscriptionId` | Endpoints And Routing | bearerAuth | path:subscription_id | - | 200, 404 |
| `PATCH` | `/v1/subscriptions/{subscription_id}` | `patchSubscriptionsSubscriptionId` | Endpoints And Routing | bearerAuth | path:subscription_id | application/json | 200 |
| `DELETE` | `/v1/subscriptions/{subscription_id}` | `deleteSubscriptionsSubscriptionId` | Endpoints And Routing | bearerAuth | path:subscription_id | application/json | 200 |
| `GET` | `/v1/transformations` | `getTransformations` | Schemas And Transformations | bearerAuth | ref:Limit | - | 200 |
| `POST` | `/v1/transformations` | `postTransformations` | Schemas And Transformations | bearerAuth | - | application/json | 201 |
| `GET` | `/v1/transformations/{transformation_id}` | `getTransformationsTransformationId` | Schemas And Transformations | bearerAuth | path:transformation_id | - | 200 |
| `GET` | `/v1/transformations/{transformation_id}/versions` | `getTransformationsTransformationIdVersions` | Schemas And Transformations | bearerAuth | path:transformation_id, ref:Limit | - | 200 |
| `POST` | `/v1/transformations/{transformation_id}/versions` | `postTransformationsTransformationIdVersions` | Schemas And Transformations | bearerAuth | path:transformation_id | application/json | 201 |
| `POST` | `/v1/transformations/{transformation_id}/versions/{version_id}:activate` | `postTransformationsTransformationIdVersionsVersionIdActivate` | Schemas And Transformations | bearerAuth | path:transformation_id, path:version_id | application/json | 200 |
