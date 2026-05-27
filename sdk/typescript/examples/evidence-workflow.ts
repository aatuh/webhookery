import { writeFile } from "node:fs/promises";
import { WebhookeryClient } from "../src/index";

const baseUrl = requiredEnv("WEBHOOKERY_BASE_URL").replace(/\/+$/, "");
const apiKey = requiredEnv("WEBHOOKERY_API_KEY");
const sourceId = requiredEnv("WEBHOOKERY_SOURCE_ID");
const output = process.env.WEBHOOKERY_EVIDENCE_OUTPUT ?? "evidence-workflow.tar.gz";

const client = new WebhookeryClient(baseUrl, apiKey);

const eventId = `evt_ts_sdk_${new Date().toISOString().replace(/[-:.]/g, "")}`;
const created = await client.createEvent(
  {
    id: eventId,
    type: "sdk.evidence.demo",
    source_id: sourceId,
    data: { sanitized: true },
  },
  { idempotencyKey: eventId },
);

const canonicalEventId = String(created.EventID ?? created.event_id ?? eventId);
const incident = await apiJson<{ id: string }>("/v1/incidents", {
  title: "TypeScript SDK evidence workflow",
  reason: "local SDK evidence example",
});

await apiJson(`/v1/incidents/${encodeURIComponent(incident.id)}/events`, {
  event_id: canonicalEventId,
  reason: "attach SDK-created event to evidence workflow",
});
await apiJson(`/v1/incidents/${encodeURIComponent(incident.id)}/generate-report`, {
  reason: "generate TypeScript SDK example report",
});
const evidenceExport = await apiJson<{ id: string }>(
  `/v1/incidents/${encodeURIComponent(incident.id)}/evidence-export`,
  { reason: "create TypeScript SDK example evidence export" },
);

const bundle = await fetch(`${baseUrl}/v1/audit-exports/${encodeURIComponent(evidenceExport.id)}:download`, {
  headers: { Authorization: `Bearer ${apiKey}` },
});
if (!bundle.ok) {
  throw await problemError(bundle);
}
await writeFile(output, Buffer.from(await bundle.arrayBuffer()), { mode: 0o600 });

const verification = await client.verifyAuditChain();
if (verification.valid !== true) {
  throw new Error("audit chain did not verify after evidence workflow");
}

console.log(`wrote evidence bundle to ${output}`);

async function apiJson<T = Record<string, unknown>>(path: string, body: unknown): Promise<T> {
  const response = await fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: {
      Accept: "application/json",
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    throw await problemError(response);
  }
  return (await response.json()) as T;
}

async function problemError(response: Response): Promise<Error> {
  let code = "unknown_error";
  let requestId = "";
  try {
    const body = (await response.json()) as { code?: string; stable_code?: string; request_id?: string };
    code = body.stable_code ?? body.code ?? code;
    requestId = body.request_id ?? "";
  } catch {
    // Leave the sanitized fallback code in place.
  }
  const suffix = requestId ? ` (${code}, request_id=${requestId})` : ` (${code})`;
  return new Error(`webhookery API returned HTTP ${response.status}${suffix}`);
}

function requiredEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
}
