import assert from "node:assert/strict";
import test from "node:test";

import { WebhookeryClient, WebhookeryHTTPError } from "../.build/index.js";

test("rejects unsafe base URLs", () => {
  assert.throws(() => new WebhookeryClient("file:///tmp/socket", "whcp_secret"), /http or https/);
});

test("createEvent posts JSON with bearer and idempotency", async () => {
  const calls = [];
  const client = new WebhookeryClient("https://api.example.test", "whcp_secret", {
    fetch: async (url, init) => {
      calls.push({ url, init });
      return new Response(JSON.stringify({ id: "evt_1" }), { status: 202 });
    },
  });

  const result = await client.createEvent(
    { id: "evt_1", type: "invoice.paid", source_id: "src_1", data: { invoice_id: "inv_1" } },
    { idempotencyKey: "invoice:inv_1:paid" },
  );

  assert.equal(result.id, "evt_1");
  assert.equal(calls[0].url, "https://api.example.test/v1/events");
  assert.equal(calls[0].init.method, "POST");
  assert.equal(calls[0].init.headers.Authorization, "Bearer whcp_secret");
  assert.equal(calls[0].init.headers["Idempotency-Key"], "invoice:inv_1:paid");
  assert.equal(JSON.parse(calls[0].init.body).id, "evt_1");
});

test("HTTP error messages do not include API keys", () => {
  const err = new WebhookeryHTTPError(403, "forbidden");
  assert.equal(err.status, 403);
  assert.match(String(err), /403/);
  assert.doesNotMatch(String(err), /whcp_secret/);
});
