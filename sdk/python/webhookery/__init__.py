from __future__ import annotations

import json
from typing import Any
from urllib import error, parse, request


class WebhookeryHTTPError(RuntimeError):
    def __init__(self, status: int, body: bytes):
        self.status = status
        self.body = body[:16 * 1024]
        super().__init__(f"webhookery API returned HTTP {status}")


class WebhookeryClient:
    def __init__(self, base_url: str, api_key: str, *, timeout: int = 10, opener: Any | None = None):
        parsed = parse.urlparse(base_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("base_url must be an http or https URL with a host")
        if any(ord(ch) < 32 for ch in base_url):
            raise ValueError("base_url contains control characters")
        if not api_key:
            raise ValueError("api_key is required")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.opener = opener or request.build_opener()

    def create_event(self, event: dict[str, Any], *, idempotency_key: str | None = None) -> dict[str, Any]:
        headers = {}
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        return self._json("POST", "/v1/events", event, headers=headers)

    def audit_chain_head(self) -> dict[str, Any]:
        return self._json("GET", "/v1/audit-chain/head")

    def verify_audit_chain(self, *, from_sequence: int | None = None, to_sequence: int | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {}
        if from_sequence is not None:
            body["from_sequence"] = from_sequence
        if to_sequence is not None:
            body["to_sequence"] = to_sequence
        return self._json("POST", "/v1/audit-chain:verify", body)

    def _json(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        data = None
        final_headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        if body is not None:
            data = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
            final_headers["Content-Type"] = "application/json"
        if headers:
            final_headers.update(headers)
        req = request.Request(self.base_url + path, data=data, headers=final_headers, method=method)
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                payload = resp.read()
        except error.HTTPError as exc:
            raise WebhookeryHTTPError(exc.code, exc.read()) from None
        if not payload:
            return {}
        decoded = json.loads(payload.decode("utf-8"))
        if not isinstance(decoded, dict):
            raise ValueError("webhookery API returned a non-object JSON response")
        return decoded
