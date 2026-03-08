from datetime import date, timedelta
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import BotoCoreError

from aws_lighthouse.tools.cost import get_cost_forecast, get_monthly_cost_summary

MOD = "aws_lighthouse.tools.cost"


def _data(result):
    assert set(result.keys()) == {"ok", "data", "errors"}
    return result["data"]


def _make_day(groups):
    """Build a single ResultsByTime entry from a list of (service, amount) pairs."""
    return {
        "Groups": [
            {
                "Keys": [svc],
                "Metrics": {"UnblendedCost": {"Amount": str(amt)}},
            }
            for svc, amt in groups
        ]
    }


def _make_ce(days_data):
    """days_data: list of ResultsByTime dicts."""
    ce = MagicMock()
    ce.get_cost_and_usage.return_value = {"ResultsByTime": days_data}
    return ce


# ── aggregation ───────────────────────────────────────────────────────────────


def test_single_day_single_service():
    ce = _make_ce([_make_day([("Amazon EC2", 10.50)])])
    with patch(f"{MOD}.get_client", return_value=ce):
        result = get_monthly_cost_summary()
    payload = _data(result)
    assert result["ok"] is True
    assert payload["total_usd"] == pytest.approx(10.50)
    assert payload["breakdown"] == {"Amazon EC2": pytest.approx(10.50)}


def test_multi_day_aggregates_same_service():
    ce = _make_ce(
        [
            _make_day([("Amazon EC2", 5.00), ("Amazon S3", 1.00)]),
            _make_day([("Amazon EC2", 3.00), ("Amazon S3", 2.00)]),
        ]
    )
    with patch(f"{MOD}.get_client", return_value=ce):
        result = get_monthly_cost_summary()
    payload = _data(result)
    assert payload["total_usd"] == pytest.approx(11.00)
    assert payload["breakdown"]["Amazon EC2"] == pytest.approx(8.00)
    assert payload["breakdown"]["Amazon S3"] == pytest.approx(3.00)


def test_empty_results_returns_zero():
    ce = _make_ce([])
    with patch(f"{MOD}.get_client", return_value=ce):
        result = get_monthly_cost_summary()
    payload = _data(result)
    assert payload["total_usd"] == 0.0
    assert payload["breakdown"] == {}


def test_breakdown_sorted_descending():
    groups = [(f"Service{i}", float(i)) for i in range(1, 6)]
    ce = _make_ce([_make_day(groups)])
    with patch(f"{MOD}.get_client", return_value=ce):
        result = get_monthly_cost_summary()
    costs = list(_data(result)["breakdown"].values())
    assert costs == sorted(costs, reverse=True)


# ── top-15 truncation ─────────────────────────────────────────────────────────


def test_top_15_truncation_keeps_highest():
    # 20 services with costs 1..20; top 15 should be services 6..20
    groups = [(f"Service{i}", float(i)) for i in range(1, 21)]
    ce = _make_ce([_make_day(groups)])
    with patch(f"{MOD}.get_client", return_value=ce):
        result = get_monthly_cost_summary()
    payload = _data(result)
    assert len(payload["breakdown"]) == 15
    # Cheapest 5 (1..5) must be excluded
    for i in range(1, 6):
        assert f"Service{i}" not in payload["breakdown"]
    # Most expensive must be present
    assert "Service20" in payload["breakdown"]


def test_fewer_than_15_services_all_included():
    groups = [(f"Svc{i}", float(i)) for i in range(1, 11)]
    ce = _make_ce([_make_day(groups)])
    with patch(f"{MOD}.get_client", return_value=ce):
        result = get_monthly_cost_summary()
    assert len(_data(result)["breakdown"]) == 10


# ── return shape ──────────────────────────────────────────────────────────────


def test_return_shape_has_required_keys():
    ce = _make_ce([_make_day([("EC2", 1.0)])])
    with patch(f"{MOD}.get_client", return_value=ce):
        result = get_monthly_cost_summary()
    assert {"period", "start", "end", "total_usd", "breakdown"} <= _data(result).keys()


def test_days_param_sets_start_date():
    ce = _make_ce([])
    with patch(f"{MOD}.get_client", return_value=ce):
        result = get_monthly_cost_summary(days=7)
    expected_start = (date.today() - timedelta(days=7)).isoformat()
    assert _data(result)["start"] == expected_start


# ── error path ────────────────────────────────────────────────────────────────


def test_api_error_returns_envelope_error():
    ce = MagicMock()
    ce.get_cost_and_usage.side_effect = BotoCoreError()
    with patch(f"{MOD}.get_client", return_value=ce):
        result = get_monthly_cost_summary()
    payload = _data(result)
    assert result["ok"] is False
    assert result["errors"]
    assert payload["total_usd"] == 0.0


# ── get_cost_forecast ─────────────────────────────────────────────────────────


def _make_forecast_ce(total_amount="55.00", forecast_values=None):
    ce = MagicMock()
    forecast_values = forecast_values or ["50.00", "60.00"]
    ce.get_cost_forecast.return_value = {
        "Total": {"Amount": total_amount, "Unit": "USD"},
        "ForecastResultsByTime": [
            {"MeanValue": v} for v in forecast_values
        ],
    }
    return ce


def test_forecast_returns_total_usd():
    ce = _make_forecast_ce()
    with patch(f"{MOD}.get_client", return_value=ce):
        result = get_cost_forecast()
    payload = _data(result)
    assert result["ok"] is True
    assert payload["total_usd"] == 55.0
    assert payload["lower_bound_usd"] == 50.0
    assert payload["upper_bound_usd"] == 60.0


def test_forecast_period_keys_present():
    ce = _make_forecast_ce()
    with patch(f"{MOD}.get_client", return_value=ce):
        result = get_cost_forecast(forecast_days=30)
    payload = _data(result)
    assert "forecast_start" in payload
    assert "forecast_end" in payload
    # Start should be tomorrow (future date)
    from datetime import UTC, datetime, timedelta
    today = datetime.now(UTC).date()
    assert payload["forecast_start"] == (today + timedelta(days=1)).isoformat()


def test_forecast_api_error_returns_error_envelope():
    ce = MagicMock()
    ce.get_cost_forecast.side_effect = BotoCoreError()
    with patch(f"{MOD}.get_client", return_value=ce):
        result = get_cost_forecast()
    assert result["ok"] is False
    assert result["errors"]
    assert _data(result)["total_usd"] is None
