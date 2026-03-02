from unittest.mock import MagicMock, patch

from aws_lighthouse.tools.ri_sp_coverage import get_ri_sp_coverage

MOD = "aws_lighthouse.tools.ri_sp_coverage"


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

    assert result["ri_coverage_pct"] == 75.0
    assert result["ri_on_demand_cost"] == 100.0
    assert result["ri_utilization_pct"] == 80.0
    assert result["ri_unused_cost"] == 20.0
    assert result["sp_coverage_pct"] == 60.0
    assert result["sp_on_demand_cost"] == 50.0
    assert result["sp_utilization_pct"] == 90.0
    assert result["sp_unused_commitment"] == 10.0
    assert "period" in result


def test_ri_coverage_api_error_sets_none():
    mock_ce = _make_ce()
    mock_ce.get_reservation_coverage.side_effect = Exception("access denied")
    with patch(f"{MOD}.get_client", return_value=mock_ce):
        result = get_ri_sp_coverage()
    assert result["ri_coverage_pct"] is None
    assert result["ri_on_demand_cost"] is None
    # other fields still populated
    assert result["ri_utilization_pct"] == 80.0


def test_ri_utilization_api_error_sets_none():
    mock_ce = _make_ce()
    mock_ce.get_reservation_utilization.side_effect = Exception("denied")
    with patch(f"{MOD}.get_client", return_value=mock_ce):
        result = get_ri_sp_coverage()
    assert result["ri_utilization_pct"] is None
    assert result["ri_unused_cost"] is None


def test_sp_coverage_api_error_sets_none():
    mock_ce = _make_ce()
    mock_ce.get_savings_plans_coverage.side_effect = Exception("denied")
    with patch(f"{MOD}.get_client", return_value=mock_ce):
        result = get_ri_sp_coverage()
    assert result["sp_coverage_pct"] is None
    assert result["sp_on_demand_cost"] is None


def test_sp_utilization_api_error_sets_none():
    mock_ce = _make_ce()
    mock_ce.get_savings_plans_utilization.side_effect = Exception("denied")
    with patch(f"{MOD}.get_client", return_value=mock_ce):
        result = get_ri_sp_coverage()
    assert result["sp_utilization_pct"] is None
    assert result["sp_unused_commitment"] is None


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
    assert result["ri_coverage_pct"] == 0.0
    assert result["sp_utilization_pct"] == 0.0
