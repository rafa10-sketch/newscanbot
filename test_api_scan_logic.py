import json
import sys
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "backend"))

try:
    import httpx  # noqa: F401
except ModuleNotFoundError:
    sys.modules["httpx"] = types.SimpleNamespace(AsyncClient=object)

from pipeline.api_scan import APIScanStage


def make_stage() -> APIScanStage:
    stage = APIScanStage.__new__(APIScanStage)
    stage.target = "api.example.com"
    stage.ctx = {"limitations": [], "tool_errors": []}
    return stage


class APIScanLogicTests(unittest.TestCase):
    def test_parse_openapi_endpoints_with_example_body(self):
        stage = make_stage()
        raw = json.dumps({
            "openapi": "3.0.0",
            "paths": {
                "/v1/payments": {
                    "post": {
                        "operationId": "createPayment",
                        "summary": "Create payment",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "example": {"merchant_id": "M1", "amount": 1000}
                                }
                            }
                        },
                    }
                },
                "/v1/transactions/{transaction_id}": {
                    "get": {"summary": "Get transaction"}
                },
            },
        })

        endpoints = stage._parse_endpoints(raw)

        self.assertEqual(len(endpoints), 2)
        self.assertEqual(endpoints[0]["method"], "POST")
        self.assertEqual(endpoints[0]["body"]["amount"], 1000)
        self.assertEqual(endpoints[1]["method"], "GET")

    def test_build_tampered_urls_targets_sensitive_identifiers(self):
        stage = make_stage()
        mutations = stage._build_tampered_urls(
            "https://api.example.com/v1/merchants/10/transactions?merchant_id=10&amount=50000"
        )
        urls = [item["url"] for item in mutations]

        self.assertIn("https://api.example.com/v1/merchants/11/transactions?merchant_id=10&amount=50000", urls)
        self.assertIn("https://api.example.com/v1/merchants/10/transactions?merchant_id=11&amount=50000", urls)
        self.assertIn("https://api.example.com/v1/merchants/10/transactions?merchant_id=10&amount=50001", urls)

    def test_invalid_auth_headers_replaces_auth_material(self):
        stage = make_stage()
        invalid = stage._invalid_auth_headers({
            "Authorization": "Bearer valid-token",
            "Cookie": "session=abc; other=def",
            "X-Api-Key": "real-key",
        })

        self.assertEqual(invalid["Authorization"], "Bearer scanbot-invalid-token")
        self.assertEqual(invalid["Cookie"], "session=scanbot_invalid; other=scanbot_invalid")
        self.assertEqual(invalid["X-Api-Key"], "scanbot-invalid-token")

    def test_invalid_auth_finding_is_high_for_payment_endpoint(self):
        stage = make_stage()
        findings = []
        ok = {"status": 200, "length": 1200, "body_hash": "same"}
        stage._inspect_invalid_auth(
            findings,
            "GET",
            "https://api.example.com/v1/payment/status?merchant_id=1",
            ok,
            ok,
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "high")
        self.assertEqual(findings[0]["extra"]["kind"], "api-invalid-auth-accepted")

    def test_high_risk_endpoint_creates_manual_validation_queue_item(self):
        stage = make_stage()
        queue = []
        stage._queue_endpoint_review(
            queue,
            {"name": "Payment callback"},
            "POST",
            "https://api.example.com/v1/payment/callback",
            {"status": 200},
        )

        self.assertEqual(len(queue), 1)
        self.assertEqual(queue[0]["kind"], "high-risk-api-workflow")
        self.assertTrue(any("signature" in check.lower() for check in queue[0]["suggested_checks"]))

    def test_successful_negative_control_creates_finding(self):
        stage = make_stage()
        findings = []
        stage._inspect_negative_control_acceptance(
            findings,
            "Balance with channel key swap negative control",
            "GET",
            "https://api.example.com/api/v1/balance/M123?key=channel-key",
            {
                "status": 200,
                "body": json.dumps({
                    "currency_code": "INR",
                    "balance": "redacted",
                    "available_balance": "redacted",
                }),
            },
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "medium")
        self.assertEqual(findings[0]["extra"]["kind"], "api-negative-control-accepted")
        self.assertTrue(findings[0]["extra"]["has_financial_fields"])

    def test_key_swap_hint_without_negative_control_phrase_creates_finding(self):
        stage = make_stage()
        findings = []
        stage._inspect_negative_control_acceptance(
            findings,
            "Transactions with balance key",
            "POST",
            "https://api.example.com/api/v1/M123/transactions/status",
            {"status": 200, "body": '{"status":"success"}'},
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["extra"]["kind"], "api-negative-control-accepted")
        self.assertTrue(findings[0]["extra"]["is_key_swap"])

    def test_failed_negative_control_does_not_create_finding(self):
        stage = make_stage()
        findings = []
        stage._inspect_negative_control_acceptance(
            findings,
            "Channel invalid key negative control",
            "POST",
            "https://api.example.com/api/v2/channel/M123",
            {"status": 400, "body": '{"status":"failed"}'},
        )

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
