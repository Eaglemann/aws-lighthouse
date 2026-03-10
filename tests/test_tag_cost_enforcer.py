"""Unit tests for aws_lighthouse/tools/tag_cost_enforcer.py."""

from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from aws_lighthouse.tools.tag_cost_enforcer import get_untagged_spend

pytestmark = [pytest.mark.unit]

MOD = "aws_lighthouse.tools.tag_cost_enforcer"


def _mock_ce(groups_by_tag: dict[str, list[tuple[str, float]]]):
    """Build a mock CE client.

    groups_by_tag: {tag_key: [(tag_value, amount), ...]}
    """
    ce = MagicMock()

    def get_cost_and_usage(**kwargs):
        tag_key = kwargs["GroupBy"][0]["Key"]
        groups = [
            {
                "Keys": [f"{tag_key}${val}"],
                "Metrics": {"UnblendedCost": {"Amount": str(amount), "Unit": "USD"}},
            }
            for val, amount in groups_by_tag.get(tag_key, [])
        ]
        return {"ResultsByTime": [{"Groups": groups}]}

    ce.get_cost_and_usage.side_effect = get_cost_and_usage
    return ce


class TestGetUntaggedSpend:
    def test_returns_sorted_by_untagged_usd(self):
        with patch(f"{MOD}.get_client") as mock_gc:
            mock_gc.return_value = _mock_ce(
                {
                    "Environment": [("", 10.0), ("production", 90.0)],
                    "Project": [("", 50.0), ("myapp", 50.0)],
                    "Owner": [("alice", 100.0)],
                    "CostCenter": [("", 80.0), ("eng", 20.0)],
                }
            )
            result = get_untagged_spend()
        assert result["ok"]
        data = result["data"]
        untagged_vals = [r["untagged_usd"] for r in data]
        assert untagged_vals == sorted(untagged_vals, reverse=True)

    def test_untagged_group_identified_by_empty_value(self):
        with patch(f"{MOD}.get_client") as mock_gc:
            mock_gc.return_value = _mock_ce(
                {
                    "Environment": [("", 30.0), ("prod", 70.0)],
                    "Project": [],
                    "Owner": [],
                    "CostCenter": [],
                }
            )
            result = get_untagged_spend()
        env = next(r for r in result["data"] if r["tag_key"] == "Environment")
        assert env["untagged_usd"] == 30.0
        assert env["tagged_usd"] == 70.0

    def test_tagged_group_not_counted_as_untagged(self):
        with patch(f"{MOD}.get_client") as mock_gc:
            mock_gc.return_value = _mock_ce(
                {
                    "Environment": [("production", 100.0)],
                    "Project": [],
                    "Owner": [],
                    "CostCenter": [],
                }
            )
            result = get_untagged_spend()
        env = next(r for r in result["data"] if r["tag_key"] == "Environment")
        assert env["untagged_usd"] == 0.0
        assert env["tagged_usd"] == 100.0

    def test_zero_total_tag_excluded(self):
        with patch(f"{MOD}.get_client") as mock_gc:
            mock_gc.return_value = _mock_ce(
                {
                    "Environment": [],
                    "Project": [],
                    "Owner": [],
                    "CostCenter": [],
                }
            )
            result = get_untagged_spend()
        assert result["ok"]
        assert result["data"] == []

    def test_untagged_pct_calculated_correctly(self):
        with patch(f"{MOD}.get_client") as mock_gc:
            mock_gc.return_value = _mock_ce(
                {
                    "Environment": [("", 30.0), ("prod", 70.0)],
                    "Project": [],
                    "Owner": [],
                    "CostCenter": [],
                }
            )
            result = get_untagged_spend()
        env = next(r for r in result["data"] if r["tag_key"] == "Environment")
        assert env["untagged_pct"] == 30.0

    def test_api_error_returns_error_result(self):
        with patch(f"{MOD}.get_client") as mock_gc:
            mock_gc.return_value.get_cost_and_usage.side_effect = ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "GetCostAndUsage",
            )
            result = get_untagged_spend()
        assert not result["ok"]
        assert result["errors"][0]["service"] == "ce"

    def test_empty_results_by_time(self):
        with patch(f"{MOD}.get_client") as mock_gc:
            mock_gc.return_value.get_cost_and_usage.return_value = {"ResultsByTime": []}
            result = get_untagged_spend()
        assert result["ok"]
        assert result["data"] == []

    def test_multi_period_amounts_summed(self):
        ce = MagicMock()
        ce.get_cost_and_usage.return_value = {
            "ResultsByTime": [
                {
                    "Groups": [
                        {
                            "Keys": ["Environment$"],
                            "Metrics": {
                                "UnblendedCost": {"Amount": "20.0", "Unit": "USD"}
                            },
                        }
                    ]
                },
                {
                    "Groups": [
                        {
                            "Keys": ["Environment$"],
                            "Metrics": {
                                "UnblendedCost": {"Amount": "10.0", "Unit": "USD"}
                            },
                        }
                    ]
                },
            ]
        }
        with patch(f"{MOD}.get_client", return_value=ce):
            result = get_untagged_spend(tag_keys=["Environment"])
        assert result["ok"]
        assert result["data"][0]["untagged_usd"] == 30.0

    def test_default_tag_keys_used_when_none_provided(self):
        with patch(f"{MOD}.get_client") as mock_gc:
            mock_gc.return_value.get_cost_and_usage.return_value = {"ResultsByTime": []}
            get_untagged_spend()
        assert mock_gc.return_value.get_cost_and_usage.call_count == 4

    def test_custom_tag_keys_accepted(self):
        with patch(f"{MOD}.get_client") as mock_gc:
            mock_gc.return_value.get_cost_and_usage.return_value = {"ResultsByTime": []}
            get_untagged_spend(tag_keys=["Team"])
        assert mock_gc.return_value.get_cost_and_usage.call_count == 1

    def test_period_days_passed_through(self):
        with patch(f"{MOD}.get_client") as mock_gc:
            mock_gc.return_value = _mock_ce(
                {
                    "Environment": [("", 10.0), ("prod", 90.0)],
                    "Project": [],
                    "Owner": [],
                    "CostCenter": [],
                }
            )
            result = get_untagged_spend(days=7)
        env = next(r for r in result["data"] if r["tag_key"] == "Environment")
        assert env["period_days"] == 7
