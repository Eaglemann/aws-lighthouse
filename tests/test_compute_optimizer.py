"""Tests for aws_lighthouse/tools/compute_optimizer.py."""

from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import BotoCoreError, ClientError

from aws_lighthouse.tools.compute_optimizer import (
    _is_graviton,
    get_compute_optimizer_recommendations,
)

pytestmark = [pytest.mark.unit]

MOD = "aws_lighthouse.tools.compute_optimizer.get_client"


# ── helpers ──────────────────────────────────────────────────────────────────


def _client_error(code: str = "AccessDeniedException") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "denied"}}, "Op")


def _make_rec(
    instance_id: str = "i-abc123",
    instance_name: str = "web-server",
    current_type: str = "m5.xlarge",
    recommended_type: str = "m5.large",
    finding: str = "Overprovisioned",
    finding_reason_codes: list[str] | None = None,
    savings_usd: float = 50.0,
    savings_pct: float = 25.0,
    performance_risk: float = 1.0,
    account_id: str = "123456789012",
    arn: str | None = None,
) -> dict:
    if arn is None:
        arn = f"arn:aws:ec2:us-east-1:{account_id}:instance/{instance_id}"
    return {
        "accountId": account_id,
        "instanceArn": arn,
        "instanceName": instance_name,
        "currentInstanceType": current_type,
        "finding": finding,
        "findingReasonCodes": finding_reason_codes or [],
        "recommendationOptions": [
            {
                "instanceType": recommended_type,
                "performanceRisk": performance_risk,
                "savingsOpportunity": {
                    "savingsOpportunityPercentage": savings_pct,
                    "estimatedMonthlySavings": {
                        "currency": "USD",
                        "value": savings_usd,
                    },
                },
            }
        ],
    }


def _response(*recs: dict, cursor: str | None = None) -> dict:
    resp: dict = {"instanceRecommendations": list(recs)}
    if cursor is not None:
        resp["nextToken"] = cursor
    return resp


# ── tests ────────────────────────────────────────────────────────────────────


@patch(MOD)
def test_returns_recommendations_sorted_by_savings(mock_get_client: MagicMock) -> None:
    """Recommendations are sorted by estimated_monthly_savings_usd descending."""
    ct = MagicMock()
    mock_get_client.return_value = ct
    ct.get_ec2_instance_recommendations.return_value = _response(
        _make_rec(instance_id="i-low", savings_usd=10.0),
        _make_rec(instance_id="i-high", savings_usd=100.0),
    )

    result = get_compute_optimizer_recommendations()

    assert result["ok"] is True
    recs = result["data"]
    assert len(recs) == 2
    assert recs[0]["instance_id"] == "i-high"
    assert recs[1]["instance_id"] == "i-low"
    savings = [r["estimated_monthly_savings_usd"] for r in recs]
    assert savings == sorted(savings, reverse=True)


@patch(MOD)
def test_skips_optimized_findings(mock_get_client: MagicMock) -> None:
    """Instances with finding='Optimized' are excluded from results."""
    ct = MagicMock()
    mock_get_client.return_value = ct
    ct.get_ec2_instance_recommendations.return_value = _response(
        _make_rec(instance_id="i-ok", finding="Optimized"),
        _make_rec(instance_id="i-over", finding="Overprovisioned", savings_usd=30.0),
    )

    result = get_compute_optimizer_recommendations()

    assert result["ok"] is True
    ids = [r["instance_id"] for r in result["data"]]
    assert "i-ok" not in ids
    assert "i-over" in ids


@patch(MOD)
def test_skips_recs_with_no_options(mock_get_client: MagicMock) -> None:
    """Recommendations with empty recommendationOptions are excluded."""
    ct = MagicMock()
    mock_get_client.return_value = ct
    no_opts = _make_rec(instance_id="i-noopts")
    no_opts["recommendationOptions"] = []
    ct.get_ec2_instance_recommendations.return_value = _response(
        no_opts,
        _make_rec(instance_id="i-good", savings_usd=20.0),
    )

    result = get_compute_optimizer_recommendations()

    assert result["ok"] is True
    ids = [r["instance_id"] for r in result["data"]]
    assert "i-noopts" not in ids
    assert "i-good" in ids


def test_is_graviton_detected() -> None:
    """Graviton instance types are correctly identified."""
    assert _is_graviton("m7g.large") is True
    assert _is_graviton("c6g.xlarge") is True
    assert _is_graviton("t4g.nano") is True
    assert _is_graviton("r7g.2xlarge") is True
    assert _is_graviton("x2gd.metal") is True
    assert _is_graviton("im4gn.large") is True
    assert _is_graviton("is4gen.xlarge") is True
    assert _is_graviton("hpc7g.large") is True
    # Non-Graviton
    assert _is_graviton("m5.large") is False
    assert _is_graviton("c5.xlarge") is False
    assert _is_graviton("r5a.large") is False


@patch(MOD)
def test_instance_id_extracted_from_arn(mock_get_client: MagicMock) -> None:
    """Instance ID is correctly extracted from the ARN suffix."""
    ct = MagicMock()
    mock_get_client.return_value = ct
    ct.get_ec2_instance_recommendations.return_value = _response(
        _make_rec(arn="arn:aws:ec2:us-east-1:123:instance/i-abc")
    )

    result = get_compute_optimizer_recommendations()

    assert result["ok"] is True
    assert result["data"][0]["instance_id"] == "i-abc"


@patch(MOD)
def test_savings_from_savings_opportunity(mock_get_client: MagicMock) -> None:
    """Savings values are parsed from the savingsOpportunity dict."""
    ct = MagicMock()
    mock_get_client.return_value = ct
    ct.get_ec2_instance_recommendations.return_value = _response(
        _make_rec(savings_usd=42.50, savings_pct=15.3)
    )

    result = get_compute_optimizer_recommendations()

    assert result["ok"] is True
    rec = result["data"][0]
    assert rec["estimated_monthly_savings_usd"] == pytest.approx(42.50)
    assert rec["estimated_savings_pct"] == pytest.approx(15.3)


@patch(MOD)
def test_api_error_returns_error_result(mock_get_client: MagicMock) -> None:
    """ClientError from the API returns ok=False with error details."""
    ct = MagicMock()
    mock_get_client.return_value = ct
    ct.get_ec2_instance_recommendations.side_effect = _client_error()

    result = get_compute_optimizer_recommendations()

    assert result["ok"] is False
    assert result["data"] == []
    assert result["errors"]


@patch(MOD)
def test_empty_response_returns_empty_list(mock_get_client: MagicMock) -> None:
    """No instanceRecommendations key returns empty data list."""
    ct = MagicMock()
    mock_get_client.return_value = ct
    ct.get_ec2_instance_recommendations.return_value = {}

    result = get_compute_optimizer_recommendations()

    assert result["ok"] is True
    assert result["data"] == []


@patch(MOD)
def test_pagination_fetches_next_page(mock_get_client: MagicMock) -> None:
    """When nextToken is present, a second API call is made."""
    ct = MagicMock()
    mock_get_client.return_value = ct
    ct.get_ec2_instance_recommendations.side_effect = [
        _response(_make_rec(instance_id="i-page1", savings_usd=50.0), cursor="tk"),
        _response(_make_rec(instance_id="i-page2", savings_usd=30.0)),
    ]

    result = get_compute_optimizer_recommendations()

    assert result["ok"] is True
    assert len(result["data"]) == 2
    assert ct.get_ec2_instance_recommendations.call_count == 2
    # Second call should include nextToken
    second_call_kwargs = ct.get_ec2_instance_recommendations.call_args_list[1][1]
    assert second_call_kwargs.get("nextToken") == "tk"


@patch(MOD)
def test_recommendation_reason_includes_finding_and_codes(
    mock_get_client: MagicMock,
) -> None:
    """Recommendation reason contains both the finding and reason codes."""
    ct = MagicMock()
    mock_get_client.return_value = ct
    ct.get_ec2_instance_recommendations.return_value = _response(
        _make_rec(
            finding="Overprovisioned",
            finding_reason_codes=["CPUOverprovisioned", "MemoryOverprovisioned"],
        )
    )

    result = get_compute_optimizer_recommendations()

    assert result["ok"] is True
    reason = result["data"][0]["recommendation_reason"]
    assert "Overprovisioned" in reason
    assert "CPUOverprovisioned" in reason
    assert "MemoryOverprovisioned" in reason


@patch(MOD)
def test_max_results_respected(mock_get_client: MagicMock) -> None:
    """Passing max_results limits the number of returned recommendations."""
    ct = MagicMock()
    mock_get_client.return_value = ct
    recs = [_make_rec(instance_id=f"i-{i}", savings_usd=float(i)) for i in range(10)]
    ct.get_ec2_instance_recommendations.return_value = _response(*recs)

    result = get_compute_optimizer_recommendations(max_results=3)

    assert result["ok"] is True
    assert len(result["data"]) == 3


@patch(MOD)
def test_client_init_error_returns_error_result(mock_get_client: MagicMock) -> None:
    """get_client failure returns ok=False, empty data."""
    mock_get_client.side_effect = BotoCoreError()

    result = get_compute_optimizer_recommendations()

    assert result["ok"] is False
    assert result["data"] == []
    assert result["errors"]


@patch(MOD)
def test_graviton_flag_set_correctly(mock_get_client: MagicMock) -> None:
    """is_graviton flag is True for Graviton types, False otherwise."""
    ct = MagicMock()
    mock_get_client.return_value = ct
    ct.get_ec2_instance_recommendations.return_value = _response(
        _make_rec(instance_id="i-grav", recommended_type="m7g.large", savings_usd=20.0),
        _make_rec(instance_id="i-x86", recommended_type="m5.large", savings_usd=10.0),
    )

    result = get_compute_optimizer_recommendations()

    assert result["ok"] is True
    by_id = {r["instance_id"]: r for r in result["data"]}
    assert by_id["i-grav"]["is_graviton"] is True
    assert by_id["i-x86"]["is_graviton"] is False
