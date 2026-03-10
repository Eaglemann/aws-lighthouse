import datetime
from unittest.mock import MagicMock, patch

from aws_lighthouse.tools.cost_anomaly import detect_cost_anomalies

MOD = "aws_lighthouse.tools.cost_anomaly"

# Fixed reference date: 2024-01-15
# 30-day window logic (mid_str = today - 30 days):
#   mid_str    = "2023-12-16"  (2024-01-15 - 30 days)
#   start_str  = "2023-11-16"  (2024-01-15 - 60 days)
# baseline window: day_start < "2023-12-16"  → use "2023-11-20"
# recent  window: day_start >= "2023-12-16"  → use "2023-12-16"
_TODAY = datetime.date(2024, 1, 15)
_BASELINE_DAY = "2023-11-20"  # falls in baseline bucket
_RECENT_DAY = "2023-12-16"  # falls in recent bucket (== mid_str)


def _make_ce(baseline_amount: float, recent_amount: float, service: str = "Amazon EC2"):
    """Return a mock CE client whose get_cost_and_usage splits spend across two windows."""
    mock_ce = MagicMock()
    mock_ce.get_cost_and_usage.return_value = {
        "ResultsByTime": [
            {
                "TimePeriod": {"Start": _BASELINE_DAY},
                "Groups": [
                    {
                        "Keys": [service],
                        "Metrics": {"UnblendedCost": {"Amount": str(baseline_amount)}},
                    }
                ],
            },
            {
                "TimePeriod": {"Start": _RECENT_DAY},
                "Groups": [
                    {
                        "Keys": [service],
                        "Metrics": {"UnblendedCost": {"Amount": str(recent_amount)}},
                    }
                ],
            },
        ]
    }
    return mock_ce


def _run(mock_ce):
    with (
        patch(f"{MOD}.get_client", return_value=mock_ce),
        patch(f"{MOD}.date") as mock_date,
    ):
        mock_date.today.return_value = _TODAY
        return detect_cost_anomalies()


def test_anomaly_detected_above_threshold():
    # baseline=10, recent=25 → 150% spike
    results = _run(_make_ce(10.0, 25.0))
    assert results["ok"] is True
    assert len(results["data"]) == 1
    anomaly = results["data"][0]
    assert anomaly["service"] == "Amazon EC2"
    assert anomaly["pct_change"] == 150.0
    assert anomaly["baseline_30d"] == 10.0
    assert anomaly["recent_30d"] == 25.0
    assert anomaly["detection_type"] == "spike"


def test_no_anomaly_below_creep_threshold():
    # baseline=10, recent=11.5 → 15% (below 20% creep threshold)
    results = _run(_make_ce(10.0, 11.5))
    assert results["ok"] is True
    assert results["data"] == []


def test_creep_detection_between_20_and_50_pct():
    # baseline=10, recent=13 → 30% (>= 20% creep threshold, < 50% spike threshold)
    results = _run(_make_ce(10.0, 13.0))
    assert results["ok"] is True
    assert len(results["data"]) == 1
    anomaly = results["data"][0]
    assert anomaly["detection_type"] == "creep"
    assert anomaly["pct_change"] == 30.0


def test_new_service_no_baseline_skipped():
    # service only appears in recent window — no baseline → skip
    mock_ce = MagicMock()
    mock_ce.get_cost_and_usage.return_value = {
        "ResultsByTime": [
            {
                "TimePeriod": {"Start": _RECENT_DAY},
                "Groups": [
                    {
                        "Keys": ["AWS Lambda"],
                        "Metrics": {"UnblendedCost": {"Amount": "50.0"}},
                    }
                ],
            }
        ]
    }
    results = _run(mock_ce)
    assert results["ok"] is True
    assert results["data"] == []


def test_negligible_baseline_skipped():
    # baseline < _MIN_BASELINE_USD (1.0) → skip
    results = _run(_make_ce(0.5, 5.0))
    assert results["ok"] is True
    assert results["data"] == []


def test_results_sorted_by_pct_change_descending():
    mock_ce = MagicMock()
    mock_ce.get_cost_and_usage.return_value = {
        "ResultsByTime": [
            {
                "TimePeriod": {"Start": _BASELINE_DAY},
                "Groups": [
                    {"Keys": ["EC2"], "Metrics": {"UnblendedCost": {"Amount": "10.0"}}},
                    {"Keys": ["S3"], "Metrics": {"UnblendedCost": {"Amount": "10.0"}}},
                ],
            },
            {
                "TimePeriod": {"Start": _RECENT_DAY},
                "Groups": [
                    {"Keys": ["EC2"], "Metrics": {"UnblendedCost": {"Amount": "30.0"}}},
                    {"Keys": ["S3"], "Metrics": {"UnblendedCost": {"Amount": "20.0"}}},
                ],
            },
        ]
    }
    results = _run(mock_ce)
    assert len(results["data"]) == 2
    assert results["data"][0]["service"] == "EC2"  # 200% > 100%
    assert results["data"][1]["service"] == "S3"


def test_api_error_returns_envelope_error():
    from botocore.exceptions import ClientError

    mock_ce = MagicMock()
    mock_ce.get_cost_and_usage.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": ""}}, "GetCostAndUsage"
    )
    with (
        patch(f"{MOD}.get_client", return_value=mock_ce),
        patch(f"{MOD}.date") as mock_date,
    ):
        mock_date.today.return_value = _TODAY
        results = detect_cost_anomalies()
    assert results["ok"] is False
    assert results["data"] == []
    assert results["errors"][0]["code"] == "AccessDenied"


# ── MED-7: env var threshold override ─────────────────────────────────────────


def test_anomaly_threshold_env_var_overrides_default(monkeypatch):
    """LIGHTHOUSE_ANOMALY_THRESHOLD_PCT controls the default threshold."""
    import importlib

    import aws_lighthouse.tools.cost_anomaly as mod

    monkeypatch.setenv("LIGHTHOUSE_ANOMALY_THRESHOLD_PCT", "25.0")
    importlib.reload(mod)
    assert mod._DEFAULT_ANOMALY_THRESHOLD_PCT == 25.0
    monkeypatch.delenv("LIGHTHOUSE_ANOMALY_THRESHOLD_PCT", raising=False)
    importlib.reload(mod)
    assert mod._DEFAULT_ANOMALY_THRESHOLD_PCT == 50.0
