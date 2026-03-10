"""Tests for aws_lighthouse.tools.effective_rate module."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from aws_lighthouse.tools.effective_rate import (
    _get_ec2_list_price,
    _parse_instance_type,
    get_effective_rates,
)


def _make_ce_group(service: str, usage_type: str, cost: float, qty: float) -> dict:
    return {
        "Keys": [service, usage_type],
        "Metrics": {
            "AmortizedCost": {"Amount": str(cost), "Unit": "USD"},
            "UsageQuantity": {"Amount": str(qty), "Unit": "N/A"},
        },
    }


def _make_ce_response(*groups: dict, periods: int = 1) -> dict:
    """Build a CE get_cost_and_usage response with the given groups spread across periods."""
    results = []
    for i in range(periods):
        results.append(
            {
                "TimePeriod": {
                    "Start": f"2024-0{i + 1}-01",
                    "End": f"2024-0{i + 2}-01",
                },
                "Groups": list(groups) if i == 0 else [],
            }
        )
    return {"ResultsByTime": results}


def _make_pricing_response(price_usd: str = "0.096") -> dict:
    price_item = {
        "terms": {
            "OnDemand": {
                "term1": {
                    "priceDimensions": {
                        "dim1": {
                            "pricePerUnit": {"USD": price_usd},
                        }
                    }
                }
            }
        }
    }
    return {"PriceList": [json.dumps(price_item)]}


# ---------------------------------------------------------------------------
# _parse_instance_type
# ---------------------------------------------------------------------------


class TestParseInstanceType:
    def test_box_usage_with_region_prefix(self):
        assert _parse_instance_type("USE1-BoxUsage:m5.large") == "m5.large"

    def test_box_usage_different_region(self):
        assert _parse_instance_type("APN1-BoxUsage:c6g.medium") == "c6g.medium"

    def test_box_usage_no_region(self):
        assert _parse_instance_type("BoxUsage:t3.micro") == "t3.micro"

    def test_no_match_nat_gateway(self):
        assert _parse_instance_type("USE2-NatGateway-Hours") is None

    def test_no_match_data_transfer(self):
        assert _parse_instance_type("USE1-DataTransfer-Out-Bytes") is None

    def test_r5_xlarge(self):
        assert _parse_instance_type("USE1-BoxUsage:r5.xlarge") == "r5.xlarge"


# ---------------------------------------------------------------------------
# _get_ec2_list_price
# ---------------------------------------------------------------------------


class TestGetEc2ListPrice:
    def test_success(self):
        pricing = MagicMock()
        pricing.get_products.return_value = _make_pricing_response("0.096")
        result = _get_ec2_list_price(pricing, "m5.large", "us-east-1")
        assert result == 0.096

    def test_empty_price_list(self):
        pricing = MagicMock()
        pricing.get_products.return_value = {"PriceList": []}
        result = _get_ec2_list_price(pricing, "m5.large", "us-east-1")
        assert result is None

    def test_api_error_returns_none(self):
        pricing = MagicMock()
        pricing.get_products.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            "GetProducts",
        )
        result = _get_ec2_list_price(pricing, "m5.large", "us-east-1")
        assert result is None

    def test_zero_price_skipped(self):
        pricing = MagicMock()
        pricing.get_products.return_value = _make_pricing_response("0")
        result = _get_ec2_list_price(pricing, "m5.large", "us-east-1")
        assert result is None

    def test_malformed_json_returns_none(self):
        pricing = MagicMock()
        pricing.get_products.return_value = {"PriceList": ["not valid json"]}
        result = _get_ec2_list_price(pricing, "m5.large", "us-east-1")
        assert result is None


# ---------------------------------------------------------------------------
# get_effective_rates
# ---------------------------------------------------------------------------


@pytest.fixture()
def _mock_clients():
    """Patch get_client to return separate CE and Pricing mocks."""
    ce = MagicMock()
    pricing = MagicMock()

    def _factory(service: str, region: str | None = None):
        if service == "ce":
            return ce
        if service == "pricing":
            return pricing
        return MagicMock()

    with patch("aws_lighthouse.tools.effective_rate.get_client", side_effect=_factory):
        yield ce, pricing


class TestGetEffectiveRates:
    def test_returns_top_n_entries_sorted_by_cost(self, _mock_clients):
        ce, pricing = _mock_clients
        groups = [
            _make_ce_group("EC2", f"USE1-BoxUsage:m5.{i}xlarge", 100.0 - i, 1000.0)
            for i in range(20)
        ]
        ce.get_cost_and_usage.return_value = _make_ce_response(*groups)
        pricing.get_products.return_value = {"PriceList": []}

        result = get_effective_rates(top_n=5)
        assert result["ok"] is True
        data = result["data"]
        assert len(data) == 5
        costs = [e["total_cost_usd"] for e in data]
        assert costs == sorted(costs, reverse=True)

    def test_parses_instance_type_from_usage_type(self, _mock_clients):
        ce, pricing = _mock_clients
        ce.get_cost_and_usage.return_value = _make_ce_response(
            _make_ce_group("EC2", "USE1-BoxUsage:m5.large", 50.0, 500.0)
        )
        pricing.get_products.return_value = {"PriceList": []}

        result = get_effective_rates()
        assert result["data"][0]["instance_type"] == "m5.large"

    def test_non_ec2_usage_type_has_no_instance_type(self, _mock_clients):
        ce, pricing = _mock_clients
        ce.get_cost_and_usage.return_value = _make_ce_response(
            _make_ce_group("VPC", "USE1-NatGateway-Hours", 30.0, 720.0)
        )
        pricing.get_products.return_value = {"PriceList": []}

        result = get_effective_rates()
        assert result["data"][0]["instance_type"] is None

    def test_effective_rate_computed_correctly(self, _mock_clients):
        ce, pricing = _mock_clients
        ce.get_cost_and_usage.return_value = _make_ce_response(
            _make_ce_group("EC2", "USE1-BoxUsage:m5.large", 100.0, 1000.0)
        )
        pricing.get_products.return_value = {"PriceList": []}

        result = get_effective_rates()
        assert result["data"][0]["effective_rate"] == 0.1

    def test_zero_quantity_gives_zero_effective_rate(self, _mock_clients):
        ce, pricing = _mock_clients
        ce.get_cost_and_usage.return_value = _make_ce_response(
            _make_ce_group("EC2", "USE1-BoxUsage:m5.large", 5.0, 0.0)
        )
        pricing.get_products.return_value = {"PriceList": []}

        result = get_effective_rates()
        assert result["data"][0]["effective_rate"] == 0.0

    def test_list_rate_lookup_called_for_ec2(self, _mock_clients):
        ce, pricing = _mock_clients
        ce.get_cost_and_usage.return_value = _make_ce_response(
            _make_ce_group("EC2", "USE1-BoxUsage:m5.large", 50.0, 500.0)
        )
        pricing.get_products.return_value = _make_pricing_response("0.096")

        result = get_effective_rates()
        pricing.get_products.assert_called_once()
        assert result["data"][0]["list_rate"] == 0.096

    def test_list_rate_cached_per_instance_type(self, _mock_clients):
        ce, pricing = _mock_clients
        ce.get_cost_and_usage.return_value = _make_ce_response(
            _make_ce_group("EC2", "USE1-BoxUsage:m5.large", 50.0, 500.0),
            _make_ce_group("EC2", "USE2-BoxUsage:m5.large", 30.0, 300.0),
        )
        pricing.get_products.return_value = _make_pricing_response("0.096")

        result = get_effective_rates()
        # Pricing API should only be called once for m5.large (cached)
        assert pricing.get_products.call_count == 1
        assert result["data"][0]["list_rate"] == 0.096
        assert result["data"][1]["list_rate"] == 0.096

    def test_discount_pct_computed_when_list_rate_available(self, _mock_clients):
        ce, pricing = _mock_clients
        # effective_rate = 72/1000 = 0.072; list = 0.096 → discount = (1 - 0.072/0.096)*100 = 25%
        ce.get_cost_and_usage.return_value = _make_ce_response(
            _make_ce_group("EC2", "USE1-BoxUsage:m5.large", 72.0, 1000.0)
        )
        pricing.get_products.return_value = _make_pricing_response("0.096")

        result = get_effective_rates()
        assert result["data"][0]["discount_pct"] == 25.0

    def test_discount_pct_none_when_no_list_rate(self, _mock_clients):
        ce, pricing = _mock_clients
        ce.get_cost_and_usage.return_value = _make_ce_response(
            _make_ce_group("EC2", "USE1-BoxUsage:m5.large", 50.0, 500.0)
        )
        pricing.get_products.return_value = {"PriceList": []}

        result = get_effective_rates()
        assert result["data"][0]["discount_pct"] is None

    def test_ce_api_error_returns_error_result(self, _mock_clients):
        ce, _pricing = _mock_clients
        ce.get_cost_and_usage.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            "GetCostAndUsage",
        )

        result = get_effective_rates()
        assert result["ok"] is False
        assert len(result["errors"]) == 1
        assert result["errors"][0]["service"] == "ce"

    def test_low_cost_entries_filtered_out(self, _mock_clients):
        ce, pricing = _mock_clients
        ce.get_cost_and_usage.return_value = _make_ce_response(
            _make_ce_group("EC2", "USE1-BoxUsage:m5.large", 50.0, 500.0),
            _make_ce_group("Other", "SmallUsage", 0.005, 1.0),
        )
        pricing.get_products.return_value = {"PriceList": []}

        result = get_effective_rates()
        assert len(result["data"]) == 1
        assert result["data"][0]["service"] == "EC2"

    def test_aggregates_across_multiple_time_periods(self, _mock_clients):
        ce, pricing = _mock_clients
        group = _make_ce_group("EC2", "USE1-BoxUsage:m5.large", 50.0, 500.0)
        # Two ResultsByTime with the same group → costs should sum
        ce.get_cost_and_usage.return_value = {
            "ResultsByTime": [
                {
                    "TimePeriod": {"Start": "2024-01-01", "End": "2024-02-01"},
                    "Groups": [group],
                },
                {
                    "TimePeriod": {"Start": "2024-02-01", "End": "2024-03-01"},
                    "Groups": [group],
                },
            ]
        }
        pricing.get_products.return_value = {"PriceList": []}

        result = get_effective_rates()
        assert result["data"][0]["total_cost_usd"] == 100.0
        assert result["data"][0]["usage_quantity"] == 1000.0
