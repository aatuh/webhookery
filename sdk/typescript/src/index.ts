export interface ProductEvent {
  id: string;
  type: string;
  source_id: string;
  data: Record<string, unknown>;
  subject?: string;
  schema_version?: string;
}

export interface CreateEventOptions {
  idempotencyKey?: string;
}

export interface WebhookeryClientOptions {
  fetch?: typeof fetch;
  timeoutMs?: number;
}

export class WebhookeryHTTPError extends Error {
  readonly status: number;
  readonly body: string;

  constructor(status: number, body: string) {
    super(`webhookery API returned HTTP ${status}`);
    this.name = "WebhookeryHTTPError";
    this.status = status;
    this.body = body.slice(0, 16 * 1024);
  }
}

export class WebhookeryClient {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;

  constructor(baseUrl: string, apiKey: string, options: WebhookeryClientOptions = {}) {
    const parsed = new URL(baseUrl);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      throw new Error("baseUrl must be an http or https URL");
    }
    if (!parsed.host) {
      throw new Error("baseUrl must include a host");
    }
    if (!apiKey) {
      throw new Error("apiKey is required");
    }
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.apiKey = apiKey;
    this.fetchImpl = options.fetch ?? fetch;
    this.timeoutMs = options.timeoutMs ?? 10_000;
  }

  async createEvent(event: ProductEvent, options: CreateEventOptions = {}): Promise<Record<string, unknown>> {
    const headers: Record<string, string> = {};
    if (options.idempotencyKey) {
      headers["Idempotency-Key"] = options.idempotencyKey;
    }
    return this.json("POST", "/v1/events", event, headers);
  }

  async auditChainHead(): Promise<Record<string, unknown>> {
    return this.json("GET", "/v1/audit-chain/head");
  }

  async verifyAuditChain(request: { from_sequence?: number; to_sequence?: number } = {}): Promise<Record<string, unknown>> {
    return this.json("POST", "/v1/audit-chain:verify", request);
  }

  private async json(
    method: string,
    path: string,
    body?: unknown,
    headers: Record<string, string> = {},
  ): Promise<Record<string, unknown>> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    const init: RequestInit = {
      method,
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${this.apiKey}`,
        ...headers,
      },
      signal: controller.signal,
    };
    if (body !== undefined) {
      init.body = JSON.stringify(body);
      (init.headers as Record<string, string>)["Content-Type"] = "application/json";
    }
    try {
      const response = await this.fetchImpl(this.baseUrl + path, init);
      const text = await response.text();
      if (!response.ok) {
        throw new WebhookeryHTTPError(response.status, text);
      }
      if (!text) {
        return {};
      }
      const decoded: unknown = JSON.parse(text);
      if (!decoded || typeof decoded !== "object" || Array.isArray(decoded)) {
        throw new Error("webhookery API returned a non-object JSON response");
      }
      return decoded as Record<string, unknown>;
    } finally {
      clearTimeout(timer);
    }
  }
}
