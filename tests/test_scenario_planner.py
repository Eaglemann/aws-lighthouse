"""Tests for aws_lighthouse.tools.scenario_planner."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

from aws_lighthouse.tools.scenario_planner import (
    _map_instance_type,
    _parse_instance_type_from_usage,
    get_scenario_plan,
)


def _make_ce_response(usage_type: str, cost: float, qty: float) -> dict:
    return {
        "ResultsByTime": [
            {
                "Groups": [
                    {
                        "Keys": [usage_type],
                        "Metrics": {
                            "AmortizedCost": {"Amount": str(cost)},
                            "UsageQuantity": {"Amount": str(qty)},
                        },
                    }
                ]
            }
        ]
    }


def _make_pricing_response(price_usd: float) -> dict:
    price_item = {
        "terms": {
            "OnDemand": {
                "term1": {
                    "priceDimensions": {
                        "dim1": {"pricePerUnit": {"USD": str(price_usd)}}
                    }
                }
            }
        }
    }
    return {"PriceList": [json.dumps(price_item)]}


def _mock_client(ce_resp: dict, pricing_resp: dict | None = None):
    """Return a mock get_client that returns stubbed CE and Pricing clients."""
    ce = MagicMock()
    ce.get_cost_and_usage.return_value = ce_resp

    pricing = MagicMock()
    if pricing_resp is not None:
        pricing.get_products.return_value = pricing_resp
    else:
        pricing.get_products.return_value = {"PriceList": []}

    def _get_client(service: str, region: str = "us-east-1"):
        if service == "ce":
            return ce
        if service == "pricing":
            return pricing
        raise ValueError(f"unexpected service: {service}")

    return _get_client, ce, pricing


# ---------------------------------------------------------------------------
# Helper unit tests
# ---------------------------------------------------------------------------


class TestParseInstanceTypeFromUsage:
    def test_boxusage(self):
        assert _parse_instance_type_from_usage("USE1-BoxUsage:m5.large") == "m5.large"

    def test_no_match(self):
        assert _parse_instance_type_from_usage("NatGateway-Hours") is None


class TestMapInstanceType:
    def test_graviton_m5_to_m7g(self):
        assert _map_instance_type("m5.xlarge", "graviton") == "m7g.xlarge"

    def test_preserves_size(self):
        assert _map_instance_type("m5.2xlarge", "graviton") == "m7g.2xlarge"

    def test_latest_gen_m4_to_m5(self):
        assert _map_instance_type("m4.large", "latest-gen") == "m5.large"

    def test_unmapped_returns_none(self):
        assert _map_instance_type("p3.2xlarge", "graviton") is None

    def test_bad_format_returns_none(self):
        assert _map_instance_type("invalid", "graviton") is None

    def test_unknown_scenario_returns_none(self):
        assert _map_instance_type("m5.large", "nonexistent") is None


# ---------------------------------------------------------------------------
# Integration tests for get_scenario_plan
# ---------------------------------------------------------------------------


class TestGetScenarioPlan:
    @patch("aws_lighthouse.tools.scenario_planner.get_client")
    def test_graviton_maps_m5_to_m7g(self, mock_gc):
        gc, _ce, _pricing = _mock_client(
            _make_ce_response("USE1-BoxUsage:m5.large", 100, 720),
            _make_pricing_response(0.10),
        )
        mock_gc.side_effect = gc

        result = get_scenario_plan(scenario="graviton")
        assert result["ok"] is True
        entries = result["data"]["entries"]
        assert len(entries) == 1
        assert entries[0]["current_instance_type"] == "m5.large"
        assert entries[0]["target_instance_type"] == "m7g.large"

    @patch("aws_lighthouse.tools.scenario_planner.get_client")
    def test_latest_gen_maps_m4_to_m5(self, mock_gc):
        gc, _ce, _pricing = _mock_client(
            _make_ce_response("USE1-BoxUsage:m4.large", 100, 720),
            _make_pricing_response(0.10),
        )
        mock_gc.side_effect = gc

        result = get_scenario_plan(scenario="latest-gen")
        assert result["ok"] is True
        entries = result["data"]["entries"]
        assert len(entries) == 1
        assert entries[0]["target_instance_type"] == "m5.large"

    def test_unknown_scenario_returns_error(self):
        result = get_scenario_plan(scenario="foo")
        assert result["ok"] is False
        assert result["errors"][0]["code"] == "InvalidScenario"

    @patch("aws_lighthouse.tools.scenario_planner.get_client")
    def test_non_mappable_instance_skipped(self, mock_gc):
        gc, _ce, _pricing = _mock_client(
            _make_ce_response("USE1-BoxUsage:p3.2xlarge", 100, 720),
        )
        mock_gc.side_effect = gc

        result = get_scenario_plan(scenario="graviton")
        assert result["ok"] is True
        assert result["data"]["entries"] == []

    @patch("aws_lighthouse.tools.scenario_planner.get_client")
    def test_monthly_savings_computed(self, mock_gc):
        gc, _ce, _pricing = _mock_client(
            _make_ce_response("USE1-BoxUsage:m5.large", 100, 720),
            _make_pricing_response(0.11),  # target at $0.11/hr -> 720*0.11 = 79.2
        )
        mock_gc.side_effect = gc

        result = get_scenario_plan(scenario="graviton")
        entry = result["data"]["entries"][0]
        assert entry["current_monthly_cost"] == 100.0
        assert entry["projected_monthly_cost"] == 79.2
        assert entry["monthly_savings"] == 20.8

    @patch("aws_lighthouse.tools.scenario_planner.get_client")
    def test_zero_savings_when_target_costs_more(self, mock_gc):
        gc, _ce, _pricing = _mock_client(
            _make_ce_response("USE1-BoxUsage:m5.large", 50, 720),
            _make_pricing_response(0.10),  # target at $0.10/hr -> 720*0.10 = 72
        )
        mock_gc.side_effect = gc

        result = get_scenario_plan(scenario="graviton")
        entry = result["data"]["entries"][0]
        # current cost $50 < projected $72 -> negative savings
        assert entry["monthly_savings"] is not None
        assert entry["monthly_savings"] < 0

    @patch("aws_lighthouse.tools.scenario_planner.get_client")
    def test_entries_sorted_by_savings_desc(self, mock_gc):
        ce_resp = {
            "ResultsByTime": [
                {
                    "Groups": [
                        {
                            "Keys": ["USE1-BoxUsage:m5.large"],
                            "Metrics": {
                                "AmortizedCost": {"Amount": "200"},
                                "UsageQuantity": {"Amount": "720"},
                            },
                        },
                        {
                            "Keys": ["USE1-BoxUsage:c5.xlarge"],
                            "Metrics": {
                                "AmortizedCost": {"Amount": "500"},
                                "UsageQuantity": {"Amount": "720"},
                            },
                        },
                    ]
                }
            ]
        }
        gc, _ce, _pricing = _mock_client(ce_resp, _make_pricing_response(0.10))
        mock_gc.side_effect = gc

        result = get_scenario_plan(scenario="graviton")
        entries = result["data"]["entries"]
        assert len(entries) == 2
        # c5 has higher cost (500) so more savings than m5 (200) at same target rate
        assert entries[0]["monthly_savings"] >= entries[1]["monthly_savings"]

    @patch("aws_lighthouse.tools.scenario_planner.get_client")
    def test_total_fields_aggregated(self, mock_gc):
        ce_resp = {
            "ResultsByTime": [
                {
                    "Groups": [
                        {
                            "Keys": ["USE1-BoxUsage:m5.large"],
                            "Metrics": {
                                "AmortizedCost": {"Amount": "100"},
                                "UsageQuantity": {"Amount": "720"},
                            },
                        },
                        {
                            "Keys": ["USE1-BoxUsage:c5.xlarge"],
                            "Metrics": {
                                "AmortizedCost": {"Amount": "200"},
                                "UsageQuantity": {"Amount": "720"},
                            },
                        },
                    ]
                }
            ]
        }
        gc, _ce, _pricing = _mock_client(ce_resp, _make_pricing_response(0.10))
        mock_gc.side_effect = gc

        result = get_scenario_plan(scenario="graviton")
        plan = result["data"]
        assert plan["total_current_cost"] == 300.0
        assert plan["total_projected_cost"] is not None
        assert plan["total_monthly_savings"] is not None
        total_entry_savings = sum(
            e["monthly_savings"] for e in plan["entries"] if e["monthly_savings"]
        )
        assert abs(plan["total_monthly_savings"] - total_entry_savings) < 0.02

    @patch("aws_lighthouse.tools.scenario_planner.get_client")
    def test_ce_api_error_returns_error(self, mock_gc):
        ce = MagicMock()
        ce.get_cost_and_usage.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "nope"}}, "GetCostAndUsage"
        )
        pricing = MagicMock()
        mock_gc.side_effect = lambda svc, _r="us-east-1": ce if svc == "ce" else pricing

        result = get_scenario_plan(scenario="graviton")
        assert result["ok"] is False
        assert result["errors"][0]["code"] == "AccessDenied"

    @patch("aws_lighthouse.tools.scenario_planner.get_client")
    def test_non_boxusage_usage_type_skipped(self, mock_gc):
        gc, _ce, _pricing = _mock_client(
            _make_ce_response("NatGateway-Hours", 100, 720),
        )
        mock_gc.side_effect = gc

        result = get_scenario_plan(scenario="graviton")
        assert result["ok"] is True
        assert result["data"]["entries"] == []

    @patch("aws_lighthouse.tools.scenario_planner.get_client")
    def test_low_cost_entry_filtered(self, mock_gc):
        gc, _ce, _pricing = _mock_client(
            _make_ce_response("USE1-BoxUsage:m5.large", 0.005, 1),
        )
        mock_gc.side_effect = gc

        result = get_scenario_plan(scenario="graviton")
        assert result["ok"] is True
        assert result["data"]["entries"] == []

    @patch("aws_lighthouse.tools.scenario_planner.get_client")
    def test_pricing_api_none_gives_none_projected(self, mock_gc):
        gc, _ce, _pricing = _mock_client(
            _make_ce_response("USE1-BoxUsage:m5.large", 100, 720),
            {"PriceList": []},  # no price found
        )
        mock_gc.side_effect = gc

        result = get_scenario_plan(scenario="graviton")
        entry = result["data"]["entries"][0]
        assert entry["target_rate"] is None
        assert entry["projected_monthly_cost"] is None
        assert entry["monthly_savings"] is None

    @patch("aws_lighthouse.tools.scenario_planner.get_client")
    def test_price_cache_used(self, mock_gc):
        """Same target instance type across two usage types should call pricing once."""
        ce_resp = {
            "ResultsByTime": [
                {
                    "Groups": [
                        {
                            "Keys": ["USE1-BoxUsage:m5.large"],
                            "Metrics": {
                                "AmortizedCost": {"Amount": "100"},
                                "UsageQuantity": {"Amount": "720"},
                            },
                        },
                        {
                            "Keys": ["USE2-BoxUsage:m5a.large"],
                            "Metrics": {
                                "AmortizedCost": {"Amount": "100"},
                                "UsageQuantity": {"Amount": "720"},
                            },
                        },
                    ]
                }
            ]
        }
        # Both m5 and m5a map to m7g under graviton
        gc, _ce, pricing = _mock_client(ce_resp, _make_pricing_response(0.10))
        mock_gc.side_effect = gc

        result = get_scenario_plan(scenario="graviton")
        assert result["ok"] is True
        # m7g.large should only be priced once
        assert pricing.get_products.call_count == 1

    @patch("aws_lighthouse.tools.scenario_planner.get_client")
    def test_aggregates_across_periods(self, mock_gc):
        """Same usage_type in two ResultsByTime periods should have costs summed."""
        ce_resp = {
            "ResultsByTime": [
                {
                    "Groups": [
                        {
                            "Keys": ["USE1-BoxUsage:m5.large"],
                            "Metrics": {
                                "AmortizedCost": {"Amount": "50"},
                                "UsageQuantity": {"Amount": "360"},
                            },
                        }
                    ]
                },
                {
                    "Groups": [
                        {
                            "Keys": ["USE1-BoxUsage:m5.large"],
                            "Metrics": {
                                "AmortizedCost": {"Amount": "50"},
                                "UsageQuantity": {"Amount": "360"},
                            },
                        }
                    ]
                },
            ]
        }
        gc, _ce, _pricing = _mock_client(ce_resp, _make_pricing_response(0.10))
        mock_gc.side_effect = gc

        result = get_scenario_plan(scenario="graviton")
        entry = result["data"]["entries"][0]
        assert entry["current_monthly_cost"] == 100.0
        assert entry["usage_hours"] == 720.0
