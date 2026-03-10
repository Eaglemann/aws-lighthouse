"""Unit tests for aws_lighthouse/tools/notify.py."""

import json
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

import pytest

from aws_lighthouse.tools.notify import (
    _count_high_critical,
    build_alert_payload,
    send_webhook,
    should_alert,
)

pytestmark = [pytest.mark.unit]


class TestCountHighCritical:
    def test_counts_high(self) -> None:
        findings = [{"severity": "HIGH"}, {"severity": "MEDIUM"}, {"severity": "HIGH"}]
        assert _count_high_critical(findings) == 2

    def test_counts_critical(self) -> None:
        findings = [{"severity": "CRITICAL"}, {"severity": "LOW"}]
        assert _count_high_critical(findings) == 1

    def test_empty_returns_zero(self) -> None:
        assert _count_high_critical([]) == 0

    def test_no_severity_field(self) -> None:
        assert _count_high_critical([{"resource": "r"}]) == 0


class TestBuildAlertPayload:
    def test_includes_account_id(self) -> None:
        p = build_alert_payload("123456789012", [], [], [])
        assert p["account_id"] == "123456789012"

    def test_total_new_sums_all_findings(self) -> None:
        p = build_alert_payload(
            "123",
            new_security=[{"severity": "HIGH", "finding": "f1"}],
            new_iam=[{"severity": "MEDIUM", "reason": "r1"}],
            new_cost_waste=[{"finding": "c1"}],
        )
        assert p["total_new"] == 3

    def test_high_critical_count_correct(self) -> None:
        p = build_alert_payload(
            "123",
            new_security=[{"severity": "CRITICAL"}, {"severity": "LOW"}],
            new_iam=[{"severity": "HIGH"}],
            new_cost_waste=[],
        )
        assert p["high_critical_count"] == 2

    def test_text_contains_account_id(self) -> None:
        p = build_alert_payload("999888777666", [], [], [])
        assert "999888777666" in p["text"]

    def test_scan_url_included_when_provided(self) -> None:
        p = build_alert_payload("123", [], [], [], scan_url="https://example.com/scan")
        assert p["scan_url"] == "https://example.com/scan"

    def test_scan_url_absent_when_not_provided(self) -> None:
        p = build_alert_payload("123", [], [], [])
        assert "scan_url" not in p

    def test_text_mentions_high_critical_count(self) -> None:
        p = build_alert_payload(
            "123",
            new_security=[{"severity": "CRITICAL", "finding": "bad"}],
            new_iam=[],
            new_cost_waste=[],
        )
        assert "HIGH/CRITICAL" in p["text"]


class TestSendWebhook:
    def test_returns_true_on_200(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = send_webhook("https://example.com/hook", {"text": "hello"})
        assert result is True

    def test_returns_false_on_url_error(self) -> None:
        with patch(
            "urllib.request.urlopen", side_effect=URLError("connection refused")
        ):
            result = send_webhook("https://example.com/hook", {"text": "hello"})
        assert result is False

    def test_returns_false_on_http_error(self) -> None:
        with patch(
            "urllib.request.urlopen",
            side_effect=HTTPError("https://example.com", 500, "Server Error", {}, None),
        ):
            result = send_webhook("https://example.com/hook", {"text": "hello"})
        assert result is False

    def test_posts_json_content_type(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=mock_resp) as mock_open:
            send_webhook("https://example.com/hook", {"key": "value"})
        req = mock_open.call_args[0][0]
        assert req.get_header("Content-type") == "application/json"

    def test_payload_serialized_as_json(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=mock_resp) as mock_open:
            send_webhook("https://example.com/hook", {"key": "value"})
        req = mock_open.call_args[0][0]
        body = json.loads(req.data.decode("utf-8"))
        assert body == {"key": "value"}


class TestShouldAlert:
    def _delta(
        self,
        baseline_found: bool = True,
        total_new: int = 0,
        new_security: list[dict[str, str]] | None = None,
        new_iam: list[dict[str, str]] | None = None,
    ) -> dict:
        """Build a delta dict matching the real _build_delta_payload structure."""
        return {
            "baseline_found": baseline_found,
            "summary": {"total_new": total_new},
            "sections": {
                "security_findings": {"new": new_security or [], "resolved": []},
                "iam_findings": {"new": new_iam or [], "resolved": []},
                "cost_waste": {"new": [], "resolved": []},
            },
        }

    def test_no_baseline_returns_false(self) -> None:
        assert not should_alert(self._delta(baseline_found=False, total_new=5))

    def test_zero_new_findings_returns_false(self) -> None:
        assert not should_alert(self._delta(total_new=0))

    def test_high_security_finding_triggers_alert(self) -> None:
        delta = self._delta(
            total_new=1,
            new_security=[{"severity": "HIGH", "finding": "bad"}],
        )
        assert should_alert(delta, min_severity="HIGH")

    def test_medium_only_does_not_trigger_high_alert(self) -> None:
        delta = self._delta(
            total_new=1,
            new_security=[{"severity": "MEDIUM", "finding": "medium"}],
        )
        assert not should_alert(delta, min_severity="HIGH")

    def test_any_new_finding_triggers_when_min_severity_none(self) -> None:
        delta = self._delta(
            total_new=1,
            new_security=[{"severity": "LOW", "finding": "low"}],
        )
        assert should_alert(delta, min_severity=None)

    def test_critical_iam_triggers_alert(self) -> None:
        delta = self._delta(
            total_new=1,
            new_iam=[{"severity": "CRITICAL", "reason": "iam:*"}],
        )
        assert should_alert(delta, min_severity="HIGH")
