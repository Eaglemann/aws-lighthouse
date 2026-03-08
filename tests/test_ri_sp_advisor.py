"""Tests for aws_lighthouse/tools/ri_sp_advisor.py."""

from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import BotoCoreError, ClientError

from aws_lighthouse.tools.ri_sp_advisor import (
    _extract_instance_details,
    _safe_float,
    get_ri_recommendations,
    get_sp_recommendations,
)

pytestmark = [pytest.mark.unit]

MOD = "aws_lighthouse.tools.ri_sp_advisor.get_client"


# ── helpers ──────────────────────────────────────────────────────────────────


def _client_error(code: str = "AccessDeniedException") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "denied"}}, "Op")


def _ri_response(
    instance_type: str = "r5.xlarge",
    region: str = "us-east-1",
    platform: str = "Linux/UNIX",
    count: str = "3",
    monthly_savings: str = "847.0",
    break_even: str = "0.0",
    on_demand: str = "2340.0",
    amortized: str = "1493.0",
    upfront: str = "0.0",
    term: str = "ONE_YEAR",
    payment: str = "NO_UPFRONT",
) -> dict:
    return {
        "Recommendations": [
            {
                "TermInYears": term,
                "PaymentOption": payment,
                "RecommendationDetails": [
                    {
                        "InstanceDetails": {
                            "EC2InstanceDetails": {
                                "InstanceType": instance_type,
                                "Region": region,
                                "Platform": platform,
                            }
                        },
                        "RecommendedNumberOfInstancesToPurchase": count,
                        "EstimatedMonthlySavingsAmount": monthly_savings,
                        "EstimatedBreakevenInMonths": break_even,
                        "EstimatedMonthlyOnDemandCost": on_demand,
                        "EstimatedMonthlyAmortizedOnDemandFee": amortized,
                        "UpfrontCost": upfront,
                    }
                ],
            }
        ]
    }


def _sp_response(
    sp_type: str = "COMPUTE_SP",
    term: str = "ONE_YEAR",
    payment: str = "NO_UPFRONT",
    hourly: str = "2.45",
    monthly_savings: str = "1234.0",
    savings_pct: str = "26.0",
    on_demand_spend: str = "4712.0",
) -> dict:
    return {
        "SavingsPlansPurchaseRecommendation": {
            "SavingsPlansType": sp_type,
            "TermInYears": term,
            "PaymentOption": payment,
            "SavingsPlansPurchaseRecommendationDetails": [],
            "SavingsPlansPurchaseRecommendationSummary": {
                "HourlyCommitmentToPurchase": hourly,
                "EstimatedMonthlySavingsAmount": monthly_savings,
                "EstimatedSavingsPercentage": savings_pct,
                "CurrentOnDemandSpend": on_demand_spend,
                "TotalRecommendationCount": "1",
            },
        }
    }


# ── _safe_float unit tests ────────────────────────────────────────────────────


def test_safe_float_converts_string() -> None:
    assert _safe_float("3.14") == pytest.approx(3.14)


def test_safe_float_handles_none() -> None:
    assert _safe_float(None) == 0.0


def test_safe_float_handles_empty_string() -> None:
    assert _safe_float("") == 0.0


# ── _extract_instance_details unit tests ──────────────────────────────────────


def test_extract_ec2_details() -> None:
    detail = {
        "InstanceDetails": {
            "EC2InstanceDetails": {
                "InstanceType": "m5.large",
                "Region": "eu-west-1",
                "Platform": "Windows",
            }
        }
    }
    it, region, platform = _extract_instance_details(detail)
    assert it == "m5.large"
    assert region == "eu-west-1"
    assert platform == "Windows"


def test_extract_rds_details() -> None:
    detail = {
        "InstanceDetails": {
            "RDSInstanceDetails": {
                "InstanceType": "db.r5.large",
                "Region": "us-west-2",
                "DatabaseEngine": "MySQL",
            }
        }
    }
    it, region, platform = _extract_instance_details(detail)
    assert it == "db.r5.large"
    assert region == "us-west-2"
    assert platform == "MySQL"


def test_extract_elasticache_details() -> None:
    detail = {
        "InstanceDetails": {
            "ElastiCacheInstanceDetails": {
                "NodeType": "cache.r6g.large",
                "Region": "ap-southeast-1",
                "ProductDescription": "Redis",
            }
        }
    }
    it, region, platform = _extract_instance_details(detail)
    assert it == "cache.r6g.large"
    assert region == "ap-southeast-1"
    assert platform == "Redis"


def test_extract_empty_details() -> None:
    it, region, platform = _extract_instance_details({})
    assert it == ""
    assert region == ""
    assert platform == ""


# ── get_ri_recommendations integration tests ─────────────────────────────────


@patch(MOD)
def test_ri_recommendations_parses_ec2_response(mock_get_client: MagicMock) -> None:
    """Happy path: EC2 RI recommendation is parsed into RIRecommendation dict."""
    ce = MagicMock()
    mock_get_client.return_value = ce
    ce.get_reservation_purchase_recommendation.return_value = _ri_response()

    result = get_ri_recommendations()

    assert result["ok"] is True
    recs = result["data"]
    assert len(recs) >= 1
    rec = recs[0]
    assert rec["instance_type"] == "r5.xlarge"
    assert rec["region"] == "us-east-1"
    assert rec["term"] == "1yr"
    assert rec["payment_option"] == "No Upfront"
    assert rec["count"] == 3
    assert rec["monthly_savings_usd"] == pytest.approx(847.0)
    assert rec["break_even_months"] == pytest.approx(0.0)


@patch(MOD)
def test_ri_recommendations_empty_response(mock_get_client: MagicMock) -> None:
    """Empty Recommendations list → empty result, ok=True."""
    ce = MagicMock()
    mock_get_client.return_value = ce
    ce.get_reservation_purchase_recommendation.return_value = {"Recommendations": []}

    result = get_ri_recommendations()

    assert result["ok"] is True
    assert result["data"] == []


@patch(MOD)
def test_ri_recommendations_api_error_returns_partial(
    mock_get_client: MagicMock,
) -> None:
    """One service errors → partial data preserved, ok=False, error recorded."""
    ce = MagicMock()
    mock_get_client.return_value = ce

    # EC2 succeeds, others raise ClientError
    def _side_effect(Service, **_kwargs):  # noqa: N803
        if Service == "AmazonEC2":
            return _ri_response()
        raise _client_error()

    ce.get_reservation_purchase_recommendation.side_effect = _side_effect

    result = get_ri_recommendations()

    assert result["ok"] is False
    assert result["errors"]
    # EC2 recommendation still present in partial data
    services = [r["service"] for r in result["data"]]
    assert "EC2" in services


@patch(MOD)
def test_ri_recommendations_sorted_by_savings(mock_get_client: MagicMock) -> None:
    """Recommendations are sorted by monthly_savings_usd descending."""
    ce = MagicMock()
    mock_get_client.return_value = ce

    # First call returns high savings, second returns low
    responses = iter(
        [
            _ri_response(monthly_savings="200.0"),
            _ri_response(monthly_savings="1000.0"),
            _ri_response(monthly_savings="50.0"),
            _ri_response(monthly_savings="500.0"),
        ]
    )
    ce.get_reservation_purchase_recommendation.side_effect = lambda **_kw: next(
        responses
    )

    result = get_ri_recommendations()

    savings = [r["monthly_savings_usd"] for r in result["data"]]
    assert savings == sorted(savings, reverse=True)


@patch(MOD)
def test_ri_client_init_error(mock_get_client: MagicMock) -> None:
    """get_client failure → ok=False, empty data."""
    mock_get_client.side_effect = _client_error()

    result = get_ri_recommendations()

    assert result["ok"] is False
    assert result["data"] == []
    assert result["errors"]


@patch(MOD)
def test_ri_term_normalization(mock_get_client: MagicMock) -> None:
    """THREE_YEARS term is normalized to '3yr'."""
    ce = MagicMock()
    mock_get_client.return_value = ce
    ce.get_reservation_purchase_recommendation.return_value = _ri_response(
        term="THREE_YEARS"
    )

    result = get_ri_recommendations()

    assert result["ok"] is True
    assert result["data"][0]["term"] == "3yr"


# ── get_sp_recommendations integration tests ─────────────────────────────────


@patch(MOD)
def test_sp_recommendations_parses_response(mock_get_client: MagicMock) -> None:
    """Happy path: SP recommendation is parsed correctly."""
    ce = MagicMock()
    mock_get_client.return_value = ce
    ce.get_savings_plans_purchase_recommendation.return_value = _sp_response()

    result = get_sp_recommendations()

    assert result["ok"] is True
    recs = result["data"]
    assert len(recs) >= 1
    rec = next(r for r in recs if r["savings_plan_type"] == "Compute SP")
    assert rec["term"] == "1yr"
    assert rec["payment_option"] == "No Upfront"
    assert rec["hourly_commitment_usd"] == pytest.approx(2.45)
    assert rec["estimated_monthly_savings_usd"] == pytest.approx(1234.0)
    assert rec["estimated_savings_pct"] == pytest.approx(26.0)


@patch(MOD)
def test_sp_recommendations_zero_commitment_excluded(
    mock_get_client: MagicMock,
) -> None:
    """SP types with zero hourly commitment and zero savings are excluded."""
    ce = MagicMock()
    mock_get_client.return_value = ce
    ce.get_savings_plans_purchase_recommendation.return_value = _sp_response(
        hourly="0.0", monthly_savings="0.0"
    )

    result = get_sp_recommendations()

    assert result["ok"] is True
    assert result["data"] == []


@patch(MOD)
def test_sp_recommendations_api_error(mock_get_client: MagicMock) -> None:
    """ClientError from CE → ok=False, error recorded."""
    ce = MagicMock()
    mock_get_client.return_value = ce
    ce.get_savings_plans_purchase_recommendation.side_effect = _client_error()

    result = get_sp_recommendations()

    assert result["ok"] is False
    assert result["errors"]


@patch(MOD)
def test_sp_recommendations_sorted_by_savings(mock_get_client: MagicMock) -> None:
    """SP recommendations are sorted by estimated_monthly_savings_usd descending."""
    ce = MagicMock()
    mock_get_client.return_value = ce

    responses = iter(
        [
            _sp_response(sp_type="COMPUTE_SP", monthly_savings="500.0"),
            _sp_response(sp_type="EC2_INSTANCE_SP", monthly_savings="1200.0"),
            _sp_response(sp_type="SAGEMAKER_SP", monthly_savings="100.0"),
        ]
    )
    ce.get_savings_plans_purchase_recommendation.side_effect = lambda **_kw: next(
        responses
    )

    result = get_sp_recommendations()

    savings = [r["estimated_monthly_savings_usd"] for r in result["data"]]
    assert savings == sorted(savings, reverse=True)


@patch(MOD)
def test_sp_client_init_error(mock_get_client: MagicMock) -> None:
    """get_client failure for SP → ok=False, empty data."""
    mock_get_client.side_effect = BotoCoreError()

    result = get_sp_recommendations()

    assert result["ok"] is False
    assert result["data"] == []
    assert result["errors"]
