import threading
from unittest.mock import MagicMock, patch

from botocore.exceptions import BotoCoreError, ClientError

from aws_lighthouse.tools.ri_sp_coverage import (
    _fetch_ri_coverage,
    _fetch_ri_utilization,
    _fetch_sp_coverage,
    _fetch_sp_utilization,
    get_ri_sp_coverage,
)

MOD = "aws_lighthouse.tools.ri_sp_coverage"


def make_client_error(code: str, message: str = "msg") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": message}}, "Op")


def _data(result):
    assert set(result.keys()) == {"ok", "data", "errors"}
    return result["data"]


def _make_ce(
    ri_cov_pct="75.0",
    ri_od_cost="100.0",
    ri_util_pct="80.0",
    ri_unused="20.0",
    sp_cov_pct="60.0",
    sp_od_cost="50.0",
    sp_util_pct="90.0",
    sp_unused="10.0",
):
    ce = MagicMock()
    ce.get_reservation_coverage.return_value = {
        "Total": {
            "CoverageHours": {"CoverageHoursPercentage": ri_cov_pct},
            "CoverageCost": {"OnDemandCost": ri_od_cost},
        }
    }
    ce.get_reservation_utilization.return_value = {
        "Total": {"UtilizationPercentage": ri_util_pct, "UnusedRecurringFee": ri_unused}
    }
    ce.get_savings_plans_coverage.return_value = {
        "Total": {
            "Coverage": {"CoveragePercentage": sp_cov_pct, "OnDemandCost": sp_od_cost}
        }
    }
    ce.get_savings_plans_utilization.return_value = {
        "Total": {
            "Utilization": {
                "UtilizationPercentage": sp_util_pct,
                "UnusedCommitment": sp_unused,
            }
        }
    }
    return ce


def test_all_fields_populated():
    mock_ce = _make_ce()
    with patch(f"{MOD}.get_client", return_value=mock_ce):
        result = get_ri_sp_coverage(days=30)
    payload = _data(result)

    assert payload["ri_coverage_pct"] == 75.0
    assert payload["ri_on_demand_cost"] == 100.0
    assert payload["ri_utilization_pct"] == 80.0
    assert payload["ri_unused_cost"] == 20.0
    assert payload["sp_coverage_pct"] == 60.0
    assert payload["sp_on_demand_cost"] == 50.0
    assert payload["sp_utilization_pct"] == 90.0
    assert payload["sp_unused_commitment"] == 10.0
    assert "period" in payload


def test_ri_coverage_api_error_sets_none():
    mock_ce = _make_ce()
    mock_ce.get_reservation_coverage.side_effect = BotoCoreError()
    with patch(f"{MOD}.get_client", return_value=mock_ce):
        result = get_ri_sp_coverage()
    payload = _data(result)
    assert result["ok"] is False
    assert payload["ri_coverage_pct"] is None
    assert payload["ri_on_demand_cost"] is None
    # other fields still populated
    assert payload["ri_utilization_pct"] == 80.0


def test_ri_utilization_api_error_sets_none():
    mock_ce = _make_ce()
    mock_ce.get_reservation_utilization.side_effect = BotoCoreError()
    with patch(f"{MOD}.get_client", return_value=mock_ce):
        result = get_ri_sp_coverage()
    payload = _data(result)
    assert result["ok"] is False
    assert payload["ri_utilization_pct"] is None
    assert payload["ri_unused_cost"] is None


def test_sp_coverage_api_error_sets_none():
    mock_ce = _make_ce()
    mock_ce.get_savings_plans_coverage.side_effect = BotoCoreError()
    with patch(f"{MOD}.get_client", return_value=mock_ce):
        result = get_ri_sp_coverage()
    payload = _data(result)
    assert result["ok"] is False
    assert payload["sp_coverage_pct"] is None
    assert payload["sp_on_demand_cost"] is None


def test_sp_utilization_api_error_sets_none():
    mock_ce = _make_ce()
    mock_ce.get_savings_plans_utilization.side_effect = BotoCoreError()
    with patch(f"{MOD}.get_client", return_value=mock_ce):
        result = get_ri_sp_coverage()
    payload = _data(result)
    assert result["ok"] is False
    assert payload["sp_utilization_pct"] is None
    assert payload["sp_unused_commitment"] is None


def test_zero_values_handled():
    mock_ce = _make_ce(
        ri_cov_pct="0",
        ri_od_cost="0",
        ri_util_pct="0",
        ri_unused="0",
        sp_cov_pct="0",
        sp_od_cost="0",
        sp_util_pct="0",
        sp_unused="0",
    )
    with patch(f"{MOD}.get_client", return_value=mock_ce):
        result = get_ri_sp_coverage()
    payload = _data(result)
    assert payload["ri_coverage_pct"] == 0.0
    assert payload["sp_utilization_pct"] == 0.0


# ── Unit tests for private fetchers ──────────────────────────────────────────


def test_fetch_ri_coverage_returns_correct_keys():
    ce = _make_ce()
    period = {"Start": "2025-01-01", "End": "2025-02-01"}
    out = _fetch_ri_coverage(ce, period)
    assert out["ok"] is True
    assert out["data"] == {"ri_coverage_pct": 75.0, "ri_on_demand_cost": 100.0}


def test_fetch_ri_coverage_error_returns_none_values():
    ce = MagicMock()
    ce.get_reservation_coverage.side_effect = BotoCoreError()
    out = _fetch_ri_coverage(ce, {})
    assert out["ok"] is False
    assert out["data"] == {"ri_coverage_pct": None, "ri_on_demand_cost": None}


def test_fetch_ri_utilization_returns_correct_keys():
    ce = _make_ce()
    out = _fetch_ri_utilization(ce, {})
    assert out["ok"] is True
    assert out["data"] == {"ri_utilization_pct": 80.0, "ri_unused_cost": 20.0}


def test_fetch_sp_coverage_returns_correct_keys():
    ce = _make_ce()
    out = _fetch_sp_coverage(ce, {})
    assert out["ok"] is True
    assert out["data"] == {"sp_coverage_pct": 60.0, "sp_on_demand_cost": 50.0}


def test_fetch_sp_utilization_returns_correct_keys():
    ce = _make_ce()
    out = _fetch_sp_utilization(ce, {})
    assert out["ok"] is True
    assert out["data"] == {"sp_utilization_pct": 90.0, "sp_unused_commitment": 10.0}


def test_fetch_sp_coverage_expected_unavailable_logs_without_display():
    ce = MagicMock()
    ce.get_savings_plans_coverage.side_effect = make_client_error(
        "DataUnavailableException"
    )
    with patch(f"{MOD}.logger.error") as mock_error:
        out = _fetch_sp_coverage(ce, {})

    assert out["ok"] is False
    assert out["errors"][0]["code"] == "DataUnavailableException"
    mock_error.assert_called_once()
    assert mock_error.call_args.kwargs["display"] is False


def test_fetch_sp_utilization_expected_unavailable_logs_without_display():
    ce = MagicMock()
    ce.get_savings_plans_utilization.side_effect = make_client_error(
        "DataUnavailableException"
    )
    with patch(f"{MOD}.logger.error") as mock_error:
        out = _fetch_sp_utilization(ce, {})

    assert out["ok"] is False
    assert out["errors"][0]["code"] == "DataUnavailableException"
    mock_error.assert_called_once()
    assert mock_error.call_args.kwargs["display"] is False


# ── MED-2: partial result preservation on unexpected future exception ─────────


def test_unexpected_future_exception_preserves_partial_results():
    """An unexpected exception in one fetcher does not discard remaining futures."""
    mock_ce = _make_ce()

    def _boom(ce, period):
        raise RuntimeError("unexpected kaboom")

    patched_fetchers = [
        _boom,
        _fetch_ri_utilization,
        _fetch_sp_coverage,
        _fetch_sp_utilization,
    ]

    with (
        patch(f"{MOD}.get_client", return_value=mock_ce),
        patch(f"{MOD}._FETCHERS", patched_fetchers),
    ):
        result = get_ri_sp_coverage()

    assert result["ok"] is False
    assert len(result["errors"]) >= 1
    # Partial results from the other three fetchers are still present
    payload = result["data"]
    assert payload["ri_utilization_pct"] == 80.0
    assert payload["sp_coverage_pct"] == 60.0
    assert payload["sp_utilization_pct"] == 90.0


# ── Parallelism smoke test ────────────────────────────────────────────────────


def test_all_four_ce_calls_issued_in_parallel():
    """All 4 CE methods must be called, and they must overlap in time."""
    call_times: list[float] = []
    lock = threading.Lock()

    import time

    original_ce = _make_ce()

    def _timed(name):
        original = getattr(original_ce, name)

        def _wrapper(*a, **kw):
            with lock:
                call_times.append(time.monotonic())
            return original(*a, **kw)

        return _wrapper

    original_ce.get_reservation_coverage = _timed("get_reservation_coverage")
    original_ce.get_reservation_utilization = _timed("get_reservation_utilization")
    original_ce.get_savings_plans_coverage = _timed("get_savings_plans_coverage")
    original_ce.get_savings_plans_utilization = _timed("get_savings_plans_utilization")

    with patch(f"{MOD}.get_client", return_value=original_ce):
        result = get_ri_sp_coverage()

    # All 4 calls were made
    assert len(call_times) == 4
    # All 8 result keys are present
    expected_keys = {
        "ri_coverage_pct",
        "ri_on_demand_cost",
        "ri_utilization_pct",
        "ri_unused_cost",
        "sp_coverage_pct",
        "sp_on_demand_cost",
        "sp_utilization_pct",
        "sp_unused_commitment",
    }
    assert expected_keys.issubset(result["data"].keys())
