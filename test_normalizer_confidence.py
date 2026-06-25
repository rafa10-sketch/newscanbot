import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "backend"))

from analysis.normalizer import Normalizer
from analysis.result_aggregator import AggregatedResult, Finding


def make_result(findings: list[Finding], scan_mode: str = "api") -> AggregatedResult:
    return AggregatedResult(
        scan_id="test-scan",
        target="api.example.com",
        target_type="domain",
        scan_started="2026-01-01T00:00:00",
        scan_completed="2026-01-01T00:01:00",
        scan_duration=60.0,
        scan_mode=scan_mode,
        findings=findings,
        observed_findings_count=len(findings),
        total_findings=len(findings),
    )


class NormalizerConfidenceTests(unittest.TestCase):
    def test_api_negative_control_with_financial_fields_is_confirmed(self):
        finding = Finding(
            id="api-negative-control-1",
            title="API negative control returned a successful response",
            severity="medium",
            description="Negative control returned HTTP 200.",
            affected=["https://api.example.com/api/v1/balance/M123"],
            source="api-scan",
            extra={
                "kind": "api-negative-control-accepted",
                "has_financial_fields": True,
                "json_fields": ["balance", "available_balance"],
            },
        )

        normalized = Normalizer(scan_mode="api").normalize(make_result([finding]))

        self.assertEqual(len(normalized.findings), 1)
        self.assertEqual(normalized.findings[0].confidence, "confirmed")
        self.assertEqual(normalized.findings[0].confidence_score, 92)
        self.assertGreater(normalized.risk_score, 2.0)

    def test_sqlmap_finding_is_confirmed(self):
        finding = Finding(
            id="sqlmap-1",
            title="SQL Injection Vulnerability",
            severity="high",
            description="SQLMap identified an injection point.",
            affected=["https://example.com/item?id=1"],
            source="sqlmap",
            validated=True,
            extra={"kind": "sqlmap"},
        )

        normalized = Normalizer(scan_mode="fast").normalize(make_result([finding], scan_mode="fast"))

        self.assertEqual(len(normalized.findings), 1)
        self.assertEqual(normalized.findings[0].confidence, "confirmed")
        self.assertEqual(normalized.findings[0].confidence_score, 95)


if __name__ == "__main__":
    unittest.main()
