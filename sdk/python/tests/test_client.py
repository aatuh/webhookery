import json
import unittest

from webhookery import WebhookeryClient, WebhookeryHTTPError


class FakeResponse:
    def __init__(self, status, body):
        self.status = status
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self):
        return self._body


class FakeOpener:
    def __init__(self, response):
        self.response = response
        self.requests = []

    def open(self, request, timeout=0):
        self.requests.append((request, timeout))
        return self.response


class WebhookeryClientTests(unittest.TestCase):
    def test_rejects_unsafe_base_url(self):
        with self.assertRaises(ValueError):
            WebhookeryClient("file:///tmp/socket", "whcp_secret")

    def test_create_event_posts_json_with_bearer_and_idempotency(self):
        opener = FakeOpener(FakeResponse(202, b'{"id":"evt_1"}'))
        client = WebhookeryClient("https://api.example.test", "whcp_secret", opener=opener)

        result = client.create_event(
            {
                "id": "evt_1",
                "type": "invoice.paid",
                "source": "billing",
                "data": {"invoice_id": "inv_1"},
            },
            idempotency_key="invoice:inv_1:paid",
        )

        self.assertEqual(result["id"], "evt_1")
        request, timeout = opener.requests[0]
        self.assertEqual(timeout, 10)
        self.assertEqual(request.full_url, "https://api.example.test/v1/events")
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.headers["Authorization"], "Bearer whcp_secret")
        self.assertEqual(request.headers["Idempotency-key"], "invoice:inv_1:paid")
        self.assertEqual(json.loads(request.data.decode("utf-8"))["id"], "evt_1")

    def test_http_error_does_not_include_api_key(self):
        client = WebhookeryClient("https://api.example.test", "whcp_secret")
        err = WebhookeryHTTPError(403, b'{"error":"forbidden"}')
        self.assertNotIn("whcp_secret", str(err))
        self.assertIn("403", str(err))


if __name__ == "__main__":
    unittest.main()
