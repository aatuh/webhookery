package httpui

import (
	"html/template"
	"net/http"
)

var indexTemplate = template.Must(template.New("index").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Webhookery</title>
  <style>
    :root { color-scheme: light; --ink: #17202a; --muted: #5d6978; --line: #c9d2dc; --fill: #f4f7f9; --accent: #0f766e; --danger: #b42318; }
    * { box-sizing: border-box; }
    body { margin: 0; font: 14px/1.45 system-ui, -apple-system, Segoe UI, sans-serif; color: var(--ink); background: #fff; }
    header { border-bottom: 1px solid var(--line); padding: 14px 20px; display: flex; align-items: center; gap: 18px; flex-wrap: wrap; }
    h1 { font-size: 20px; line-height: 1.2; margin: 0; }
    main { display: grid; grid-template-columns: 240px minmax(0, 1fr); min-height: calc(100vh - 57px); }
    nav { border-right: 1px solid var(--line); background: var(--fill); padding: 12px; }
    nav button { width: 100%; min-height: 34px; border: 0; background: transparent; text-align: left; padding: 8px 10px; color: var(--ink); cursor: pointer; }
    nav button[aria-current="true"] { background: #dcebe8; color: #0b4f4a; font-weight: 650; }
    section { padding: 18px 22px; min-width: 0; }
    .toolbar { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 14px; }
    input, select, textarea { border: 1px solid var(--line); padding: 8px 9px; min-height: 34px; background: #fff; color: var(--ink); }
    input[type="password"] { width: min(420px, 100%); }
    button { border: 1px solid #8da29f; background: #edf7f5; color: #0b4f4a; min-height: 34px; padding: 7px 10px; cursor: pointer; }
    button.danger { border-color: #e09a93; background: #fff0ee; color: var(--danger); }
    table { width: 100%; border-collapse: collapse; table-layout: fixed; }
    th, td { border-bottom: 1px solid var(--line); padding: 8px; text-align: left; vertical-align: top; overflow-wrap: anywhere; }
    th { color: var(--muted); font-size: 12px; text-transform: uppercase; }
    pre { margin: 0; padding: 12px; background: #101820; color: #f5f7f8; overflow: auto; min-height: 180px; }
    .grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; margin-bottom: 14px; }
    .status { color: var(--muted); min-height: 20px; }
    @media (max-width: 760px) { main { grid-template-columns: 1fr; } nav { border-right: 0; border-bottom: 1px solid var(--line); display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); } .grid { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <header>
    <h1>Webhookery</h1>
    <input id="token" type="password" autocomplete="off" placeholder="API key">
    <button id="reload">Refresh</button>
    <span class="status" id="status"></span>
  </header>
  <main>
    <nav id="nav"></nav>
    <section>
      <div class="toolbar" id="actions"></div>
      <div id="view"></div>
      <pre id="raw" hidden></pre>
    </section>
  </main>
  <script>
    const resources = [
      ["sources", "/v1/sources"],
      ["provider connections", "/v1/provider-connections"],
      ["endpoints", "/v1/endpoints"],
      ["subscriptions", "/v1/subscriptions"],
      ["transformations", "/v1/transformations"],
      ["retry policies", "/v1/retry-policies"],
      ["routes", "/v1/routes"],
      ["schemas", "/v1/event-types"],
      ["events", "/v1/events"],
      ["deliveries", "/v1/deliveries"],
      ["replay", "/v1/replay-jobs"],
      ["reconciliation", "/v1/reconciliation-jobs"],
      ["dead letter", "/v1/dead-letter"],
      ["quarantine", "/v1/quarantine"],
      ["audit", "/v1/audit-events"],
      ["audit chain", "/v1/audit-chain/head"],
      ["audit anchors", "/v1/audit-chain/anchors"],
      ["audit exports", "/v1/audit-exports"],
      ["retention", "/v1/admin/retention-policies"],
      ["endpoint health", "/v1/endpoint-health"],
      ["ops", "/v1/ops/metrics"],
      ["ops rollups", "/v1/ops/metrics/rollups"],
      ["ops storage", "/v1/ops/storage"],
      ["ops config", "/v1/ops/config"],
      ["workers", "/v1/ops/workers"],
      ["queues", "/v1/ops/queues"]
    ];
    let current = resources[0];
    const token = document.querySelector("#token");
    const nav = document.querySelector("#nav");
    const view = document.querySelector("#view");
    const raw = document.querySelector("#raw");
    const actions = document.querySelector("#actions");
    const status = document.querySelector("#status");

    for (const item of resources) {
      const button = document.createElement("button");
      button.textContent = item[0];
      button.onclick = () => { current = item; load(); };
      nav.append(button);
    }
    document.querySelector("#reload").onclick = load;

    async function request(path, options = {}) {
      const headers = {"Accept": "application/json", ...(options.headers || {})};
      if (token.value) headers.Authorization = "Bearer " + token.value;
      const response = await fetch(path, {...options, headers});
      const text = await response.text();
      let body = text;
      try { body = JSON.parse(text); } catch {}
      if (!response.ok) throw body;
      return body;
    }

    async function load() {
      status.textContent = "";
      raw.hidden = true;
      [...nav.children].forEach((button, index) => button.setAttribute("aria-current", resources[index] === current ? "true" : "false"));
      try {
        const body = await request(current[1]);
        render(current[0], body);
      } catch (error) {
        view.innerHTML = "";
        raw.hidden = false;
        raw.textContent = JSON.stringify(error, null, 2);
        status.textContent = "Request failed";
      }
    }

    function render(name, body) {
      actions.replaceChildren();
      if (name === "ops") {
        raw.hidden = false;
        raw.textContent = JSON.stringify(body, null, 2);
        view.innerHTML = "";
        return;
      }
      if (name === "audit chain") {
        renderAuditChain(body);
        return;
      }
      const rows = Array.isArray(body.data) ? body.data : [];
      view.innerHTML = "";
      if (rows.length === 0) {
        view.textContent = "No rows";
        return;
      }
      let keys = [...new Set(rows.flatMap(row => Object.keys(row)))].slice(0, 8);
      if (name === "deliveries") {
        keys = ["id", "event_id", "endpoint_id", "state", "retry_seed", "adapter_version_id", "transformation_version_id", "delivery_payload_sha256"];
      }
      if (name === "provider connections") {
        keys = ["id", "name", "provider", "state", "credential_type", "credential_hint", "verified_at", "updated_at"];
      }
      if (name === "reconciliation") {
        keys = ["id", "connection_id", "provider", "state", "total_items", "missing_items", "captured_items", "redelivered_items"];
      }
      if (name === "audit anchors") {
        keys = ["id", "from_sequence", "to_sequence", "chain_hash", "manifest_sha256", "storage_backend", "created_at"];
      }
      const table = document.createElement("table");
      const head = document.createElement("tr");
      for (const key of keys) {
        const th = document.createElement("th");
        th.textContent = key;
        head.append(th);
      }
      if (name === "events") {
        const th = document.createElement("th");
        th.textContent = "normalized";
        head.append(th);
      }
      if (name === "transformations") {
        const th = document.createElement("th");
        th.textContent = "versions";
        head.append(th);
      }
      if (name === "audit exports") {
        const th = document.createElement("th");
        th.textContent = "download";
        head.append(th);
      }
      if (name === "reconciliation") {
        const th = document.createElement("th");
        th.textContent = "items";
        head.append(th);
      }
      table.append(head);
      for (const row of rows) {
        const tr = document.createElement("tr");
        for (const key of keys) {
          const td = document.createElement("td");
          const value = row[key];
          td.textContent = typeof value === "object" && value !== null ? JSON.stringify(value) : String(value ?? "");
          tr.append(td);
        }
        if (name === "events") {
          const td = document.createElement("td");
          if (row.id) {
            const button = document.createElement("button");
            button.textContent = "View";
            button.onclick = () => showNormalized(row.id);
            td.append(button);
          }
          tr.append(td);
        }
        if (name === "transformations") {
          const td = document.createElement("td");
          if (row.id) {
            const button = document.createElement("button");
            button.textContent = "Versions";
            button.onclick = () => showTransformationVersions(row.id);
            td.append(button);
          }
          tr.append(td);
        }
        if (name === "audit exports") {
          const td = document.createElement("td");
          if (row.state === "ready" && row.id) {
            const button = document.createElement("button");
            button.textContent = "Download";
            button.onclick = () => downloadExport(row.id);
            td.append(button);
          }
          tr.append(td);
        }
        if (name === "reconciliation") {
          const td = document.createElement("td");
          if (row.id) {
            const button = document.createElement("button");
            button.textContent = "Items";
            button.onclick = () => showReconciliationItems(row.id);
            td.append(button);
          }
          tr.append(td);
        }
        table.append(tr);
      }
      view.append(table);
    }

    function renderAuditChain(body) {
      view.innerHTML = "";
      raw.hidden = false;
      raw.textContent = JSON.stringify(body, null, 2);
      const verify = document.createElement("button");
      verify.textContent = "Verify";
      verify.onclick = verifyAuditChain;
      const anchor = document.createElement("button");
      anchor.textContent = "Anchor";
      anchor.onclick = anchorAuditChain;
      actions.replaceChildren(verify, anchor);
      const table = document.createElement("table");
      const rows = [
        ["sequence", body.sequence],
        ["chain_hash", body.chain_hash],
        ["unchained_events", body.unchained_events],
        ["last_anchor_id", body.last_anchor_id],
        ["last_anchor_sequence", body.last_anchor_sequence],
        ["last_anchored_at", body.last_anchored_at],
        ["updated_at", body.updated_at]
      ];
      for (const row of rows) {
        const tr = document.createElement("tr");
        const key = document.createElement("th");
        key.textContent = row[0];
        const value = document.createElement("td");
        value.textContent = String(row[1] ?? "");
        tr.append(key, value);
        table.append(tr);
      }
      view.append(table);
    }

    async function verifyAuditChain() {
      try {
        const body = await request("/v1/audit-chain:verify", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: "{}"
        });
        raw.hidden = false;
        raw.textContent = JSON.stringify(body, null, 2);
        status.textContent = body.valid ? "Audit chain verified" : "Audit chain verification failed";
      } catch (error) {
        raw.hidden = false;
        raw.textContent = JSON.stringify(error, null, 2);
        status.textContent = "Audit chain verification failed";
      }
    }

    async function anchorAuditChain() {
      const reason = prompt("Reason for audit chain anchor");
      if (!reason) return;
      try {
        const body = await request("/v1/audit-chain:anchor", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({reason})
        });
        raw.hidden = false;
        raw.textContent = JSON.stringify(body, null, 2);
        status.textContent = "Audit chain anchored";
      } catch (error) {
        raw.hidden = false;
        raw.textContent = JSON.stringify(error, null, 2);
        status.textContent = "Audit chain anchor failed";
      }
    }

    async function showNormalized(id) {
      try {
        const body = await request("/v1/events/" + encodeURIComponent(id) + "/normalized");
        raw.hidden = false;
        raw.textContent = JSON.stringify(body, null, 2);
      } catch (error) {
        raw.hidden = false;
        raw.textContent = JSON.stringify(error, null, 2);
        status.textContent = "Normalized read failed";
      }
    }

    async function showTransformationVersions(id) {
      try {
        const body = await request("/v1/transformations/" + encodeURIComponent(id) + "/versions");
        raw.hidden = false;
        raw.textContent = JSON.stringify(body, null, 2);
      } catch (error) {
        raw.hidden = false;
        raw.textContent = JSON.stringify(error, null, 2);
        status.textContent = "Version read failed";
      }
    }

    async function downloadExport(id) {
      try {
        const response = await fetch("/v1/audit-exports/" + encodeURIComponent(id) + ":download", {
          headers: token.value ? {"Authorization": "Bearer " + token.value} : {}
        });
        if (!response.ok) throw await response.text();
        const blob = await response.blob();
        const link = document.createElement("a");
        link.href = URL.createObjectURL(blob);
        link.download = id + ".tar.gz";
        link.click();
        URL.revokeObjectURL(link.href);
      } catch (error) {
        status.textContent = "Download failed";
      }
    }

    async function showReconciliationItems(id) {
      try {
        const body = await request("/v1/reconciliation-jobs/" + encodeURIComponent(id) + "/items");
        raw.hidden = false;
        raw.textContent = JSON.stringify(body, null, 2);
      } catch (error) {
        raw.hidden = false;
        raw.textContent = JSON.stringify(error, null, 2);
        status.textContent = "Reconciliation items read failed";
      }
    }
  </script>
</body>
</html>`))

func Index() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'none'; base-uri 'none'; frame-ancestors 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
		_ = indexTemplate.Execute(w, nil)
	}
}
