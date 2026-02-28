import datetime
from unittest.mock import MagicMock, patch

from aws_lighthouse.tools.cost_anomaly import detect_cost_anomalies

MOD = "aws_lighthouse.tools.cost_anomaly"

# Fixed reference date: 2024-01-15
# baseline window: 2024-01-01 → 2024-01-07  (day_start < "2024-01-08")
# recent window:   2024-01-08 → 2024-01-14  (day_start >= "2024-01-08")
_TODAY = datetime.date(2024, 1, 15)
_MID = "2024-01-08"


def _make_ce(baseline_amount: float, recent_amount: float, service: str = "Amazon EC2"):
    """Return a mock CE client whose get_cost_and_usage splits spend across two windows."""
    mock_ce = MagicMock()
    mock_ce.get_cost_and_usage.return_value = {
        "ResultsByTime": [
            {
                "TimePeriod": {"Start": "2024-01-01"},
                "Groups": [
                    {
                        "Keys": [service],
                        "Metrics": {"UnblendedCost": {"Amount": str(baseline_amount)}},
                    }
                ],
            },
            {
                "TimePeriod": {"Start": _MID},
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
    with patch(f"{MOD}.get_aws_client", return_value=mock_ce):
        with patch(f"{MOD}.date") as mock_date:
            mock_date.today.return_value = _TODAY
            return detect_cost_anomalies()


def test_anomaly_detected_above_threshold():
    # baseline=10, recent=25 → 150% spike
    results = _run(_make_ce(10.0, 25.0))
    assert len(results) == 1
    assert results[0]["service"] == "Amazon EC2"
    assert results[0]["pct_change"] == 150.0
    assert results[0]["baseline_7d"] == 10.0
    assert results[0]["recent_7d"] == 25.0


def test_no_anomaly_below_threshold():
    # baseline=10, recent=14 → 40% (< 50% threshold)
    results = _run(_make_ce(10.0, 14.0))
    assert results == []


def test_new_service_no_baseline_skipped():
    # service only appears in recent window — no baseline → skip
    mock_ce = MagicMock()
    mock_ce.get_cost_and_usage.return_value = {
        "ResultsByTime": [
            {
                "TimePeriod": {"Start": _MID},
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
    assert results == []


def test_negligible_baseline_skipped():
    # baseline < _MIN_BASELINE_USD (1.0) → skip
    results = _run(_make_ce(0.5, 5.0))
    assert results == []


def test_results_sorted_by_pct_change_descending():
    mock_ce = MagicMock()
    mock_ce.get_cost_and_usage.return_value = {
        "ResultsByTime": [
            {
                "TimePeriod": {"Start": "2024-01-01"},
                "Groups": [
                    {"Keys": ["EC2"], "Metrics": {"UnblendedCost": {"Amount": "10.0"}}},
                    {"Keys": ["S3"], "Metrics": {"UnblendedCost": {"Amount": "10.0"}}},
                ],
            },
            {
                "TimePeriod": {"Start": _MID},
                "Groups": [
                    {"Keys": ["EC2"], "Metrics": {"UnblendedCost": {"Amount": "30.0"}}},
                    {"Keys": ["S3"], "Metrics": {"UnblendedCost": {"Amount": "20.0"}}},
                ],
            },
        ]
    }
    results = _run(mock_ce)
    assert len(results) == 2
    assert results[0]["service"] == "EC2"  # 200% > 100%
    assert results[1]["service"] == "S3"


def test_api_error_returns_error_entry():
    mock_ce = MagicMock()
    mock_ce.get_cost_and_usage.side_effect = Exception("access denied")
    with patch(f"{MOD}.get_aws_client", return_value=mock_ce):
        with patch(f"{MOD}.date") as mock_date:
            mock_date.today.return_value = _TODAY
            results = detect_cost_anomalies()
    assert len(results) == 1
    assert "error" in results[0]
