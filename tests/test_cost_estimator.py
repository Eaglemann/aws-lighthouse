"""Tests for aws_lighthouse.tools.cost_estimator."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError
from typer.testing import CliRunner

from aws_lighthouse.cli import app
from aws_lighthouse.tools.cost_estimator import (
    _generate_terraform,
    _get_ec2_price,
    _get_rds_price,
    estimate_build_cost,
)

_MODULE = "aws_lighthouse.tools.cost_estimator"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_pricing_response(price_usd: str = "0.096") -> dict:
    price_item = {
        "terms": {
            "OnDemand": {
                "term1": {
                    "priceDimensions": {"dim1": {"pricePerUnit": {"USD": price_usd}}}
                }
            }
        }
    }
    return {"PriceList": [json.dumps(price_item)]}


def _mock_client(*_args: object, **_kwargs: object) -> MagicMock:
    client = MagicMock()
    client.get_products.return_value = _make_pricing_response("0.096")
    return client


# ---------------------------------------------------------------------------
# Unit: _get_ec2_price / _get_rds_price
# ---------------------------------------------------------------------------


class TestGetEc2Price:
    def test_returns_hourly_price(self) -> None:
        client = MagicMock()
        client.get_products.return_value = _make_pricing_response("0.192")
        assert _get_ec2_price(client, "m5.xlarge") == 0.192

    def test_returns_none_on_empty(self) -> None:
        client = MagicMock()
        client.get_products.return_value = {"PriceList": []}
        assert _get_ec2_price(client, "m5.xlarge") is None

    def test_returns_none_on_client_error(self) -> None:
        client = MagicMock()
        client.get_products.side_effect = ClientError(
            {"Error": {"Code": "Boom", "Message": "fail"}}, "GetProducts"
        )
        assert _get_ec2_price(client, "m5.xlarge") is None


class TestGetRdsPrice:
    def test_returns_hourly_price(self) -> None:
        client = MagicMock()
        client.get_products.return_value = _make_pricing_response("0.068")
        assert _get_rds_price(client, "db.t3.medium") == 0.068

    def test_uses_rds_service_code(self) -> None:
        client = MagicMock()
        client.get_products.return_value = _make_pricing_response("0.068")
        _get_rds_price(client, "db.t3.medium")
        call_kwargs = client.get_products.call_args[1]
        assert call_kwargs["ServiceCode"] == "AmazonRDS"


# ---------------------------------------------------------------------------
# Unit: estimate_build_cost
# ---------------------------------------------------------------------------


class TestEstimateBuildCost:
    @patch(f"{_MODULE}.get_client", side_effect=_mock_client)
    def test_ec2_monthly_cost_computed(self, _gc: MagicMock) -> None:
        result = estimate_build_cost(
            [{"type": "ec2", "instance_type": "m5.large", "count": 1}]
        )
        assert result["ok"]
        resources = result["data"]["resources"]
        assert len(resources) == 1
        # 0.096 * 730 = 70.08
        assert resources[0]["unit_monthly_cost"] == 70.08
        assert resources[0]["total_monthly_cost"] == 70.08

    @patch(f"{_MODULE}.get_client", side_effect=_mock_client)
    def test_ec2_count_multiplied(self, _gc: MagicMock) -> None:
        result = estimate_build_cost(
            [{"type": "ec2", "instance_type": "m5.large", "count": 3}]
        )
        assert result["ok"]
        r = result["data"]["resources"][0]
        assert r["unit_monthly_cost"] == 70.08
        assert r["total_monthly_cost"] == 210.24

    @patch(f"{_MODULE}.get_client", side_effect=_mock_client)
    def test_rds_lookup_uses_rds_service_code(self, _gc: MagicMock) -> None:
        result = estimate_build_cost(
            [{"type": "rds", "instance_class": "db.t3.medium", "count": 1}]
        )
        assert result["ok"]
        assert result["data"]["resources"][0]["resource_type"] == "rds"
        # pricing mock returns 0.096 → unit_monthly_cost = 0.096*730 = 70.08
        assert result["data"]["resources"][0]["unit_monthly_cost"] == 70.08

    @patch(f"{_MODULE}.get_client", side_effect=_mock_client)
    def test_lambda_uses_flat_estimate(self, _gc: MagicMock) -> None:
        result = estimate_build_cost([{"type": "lambda", "count": 2}])
        assert result["ok"]
        r = result["data"]["resources"][0]
        assert r["unit_monthly_cost"] == 5.0
        assert r["total_monthly_cost"] == 10.0
        assert "pay-per-use" in r["pricing_note"]

    @patch(f"{_MODULE}.get_client", side_effect=_mock_client)
    def test_nat_gateway_flat_estimate(self, _gc: MagicMock) -> None:
        result = estimate_build_cost([{"type": "nat_gateway", "count": 1}])
        assert result["ok"]
        r = result["data"]["resources"][0]
        assert r["unit_monthly_cost"] == 35.0
        assert r["total_monthly_cost"] == 35.0
        assert "data transfer" in r["pricing_note"]

    @patch(f"{_MODULE}.get_client", side_effect=_mock_client)
    def test_load_balancer_flat_estimate(self, _gc: MagicMock) -> None:
        result = estimate_build_cost([{"type": "load_balancer", "count": 1}])
        assert result["ok"]
        r = result["data"]["resources"][0]
        assert r["unit_monthly_cost"] == 22.50
        assert r["total_monthly_cost"] == 22.50
        assert "LCU" in r["pricing_note"]

    @patch(f"{_MODULE}.get_client", side_effect=_mock_client)
    def test_s3_has_no_unit_cost(self, _gc: MagicMock) -> None:
        result = estimate_build_cost([{"type": "s3", "count": 1}])
        assert result["ok"]
        r = result["data"]["resources"][0]
        assert r["unit_monthly_cost"] is None
        assert r["total_monthly_cost"] is None
        assert "$0.023/GB" in r["pricing_note"]

    @patch(f"{_MODULE}.get_client", side_effect=_mock_client)
    def test_unknown_type_skipped(self, _gc: MagicMock) -> None:
        result = estimate_build_cost([{"type": "kafka", "count": 1}])
        assert result["ok"]
        assert result["data"]["resources"] == []

    @patch(f"{_MODULE}.get_client", side_effect=_mock_client)
    def test_total_excludes_none_costs(self, _gc: MagicMock) -> None:
        result = estimate_build_cost(
            [
                {"type": "s3", "count": 1},
                {"type": "ec2", "instance_type": "m5.large", "count": 1},
            ]
        )
        assert result["ok"]
        # Total should only include EC2 (70.08), not S3 (None)
        assert result["data"]["total_monthly_cost"] == 70.08

    @patch(f"{_MODULE}.get_client", side_effect=_mock_client)
    def test_total_annual_is_12x_monthly(self, _gc: MagicMock) -> None:
        result = estimate_build_cost(
            [{"type": "ec2", "instance_type": "m5.large", "count": 1}]
        )
        assert result["ok"]
        monthly = result["data"]["total_monthly_cost"]
        annual = result["data"]["total_annual_cost"]
        assert annual == round(monthly * 12, 2)

    @patch(f"{_MODULE}.get_client", side_effect=_mock_client)
    def test_terraform_scaffold_in_result(self, _gc: MagicMock) -> None:
        result = estimate_build_cost(
            [{"type": "ec2", "instance_type": "m5.large", "count": 2}]
        )
        assert result["ok"]
        scaffold = result["data"]["terraform_scaffold"]
        assert "aws_instance" in scaffold
        assert "m5.large" in scaffold

    @patch(f"{_MODULE}.get_client", side_effect=_mock_client)
    def test_terraform_scaffold_for_rds(self, _gc: MagicMock) -> None:
        result = estimate_build_cost(
            [{"type": "rds", "instance_class": "db.t3.medium", "count": 1}]
        )
        assert result["ok"]
        scaffold = result["data"]["terraform_scaffold"]
        assert "aws_db_instance" in scaffold
        assert "db.t3.medium" in scaffold

    @patch(f"{_MODULE}.get_client")
    def test_pricing_api_error_gives_none_cost(self, mock_gc: MagicMock) -> None:
        client = MagicMock()
        client.get_products.side_effect = ClientError(
            {"Error": {"Code": "Boom", "Message": "fail"}}, "GetProducts"
        )
        mock_gc.return_value = client
        result = estimate_build_cost(
            [{"type": "ec2", "instance_type": "m5.large", "count": 1}]
        )
        assert result["ok"]
        r = result["data"]["resources"][0]
        assert r["unit_monthly_cost"] is None
        assert r["total_monthly_cost"] is None
        assert "price unavailable" in r["pricing_note"]

    @patch(f"{_MODULE}.get_client", side_effect=_mock_client)
    def test_empty_resources_returns_empty_estimate(self, _gc: MagicMock) -> None:
        result = estimate_build_cost([])
        assert result["ok"]
        assert result["data"]["resources"] == []
        assert result["data"]["total_monthly_cost"] is None
        assert result["data"]["total_annual_cost"] is None

    @patch(f"{_MODULE}.get_client", side_effect=_mock_client)
    def test_mixed_resources(self, _gc: MagicMock) -> None:
        result = estimate_build_cost(
            [
                {"type": "ec2", "instance_type": "m5.large", "count": 1},
                {"type": "rds", "instance_class": "db.t3.medium", "count": 1},
                {"type": "lambda", "count": 3},
                {"type": "s3", "count": 1},
            ]
        )
        assert result["ok"]
        types = [r["resource_type"] for r in result["data"]["resources"]]
        assert types == ["ec2", "rds", "lambda", "s3"]
        # Total = EC2 (70.08) + RDS (70.08) + Lambda (15.0) = 155.16
        assert result["data"]["total_monthly_cost"] == 155.16


# ---------------------------------------------------------------------------
# Unit: _generate_terraform
# ---------------------------------------------------------------------------


class TestGenerateTerraform:
    def test_header_present(self) -> None:
        tf = _generate_terraform([])
        assert "Terraform scaffold generated by AWS Lighthouse" in tf

    def test_lambda_block(self) -> None:
        tf = _generate_terraform([{"type": "lambda", "count": 2}])
        assert "aws_lambda_function" in tf
        assert "count" in tf

    def test_nat_gateway_block(self) -> None:
        tf = _generate_terraform([{"type": "nat_gateway", "count": 1}])
        assert "aws_nat_gateway" in tf

    def test_load_balancer_block(self) -> None:
        tf = _generate_terraform([{"type": "load_balancer", "count": 1}])
        assert "aws_lb" in tf

    def test_s3_block(self) -> None:
        tf = _generate_terraform([{"type": "s3", "count": 2}])
        assert "aws_s3_bucket" in tf


# ---------------------------------------------------------------------------
# CLI: estimate command
# ---------------------------------------------------------------------------


class TestEstimateCommand:
    @patch("aws_lighthouse.cli.estimate_build_cost")
    def test_estimate_command_text_output(self, mock_est: MagicMock) -> None:
        mock_est.return_value = {
            "ok": True,
            "data": {
                "resources": [
                    {
                        "resource_type": "ec2",
                        "label": "m5.large x1",
                        "count": 1,
                        "unit_monthly_cost": 70.08,
                        "total_monthly_cost": 70.08,
                        "pricing_note": "on-demand Linux",
                    }
                ],
                "total_monthly_cost": 70.08,
                "total_annual_cost": 840.96,
                "terraform_scaffold": '# scaffold\nresource "aws_instance" "app" {}',
                "currency": "USD",
            },
            "errors": [],
        }
        runner = CliRunner()
        result = runner.invoke(app, ["estimate", "ec2:m5.large:1"])
        assert result.exit_code == 0
        assert "m5.large" in result.output
        assert "$70.08" in result.output

    @patch("aws_lighthouse.cli.estimate_build_cost")
    def test_estimate_command_json_output(self, mock_est: MagicMock) -> None:
        mock_est.return_value = {
            "ok": True,
            "data": {
                "resources": [],
                "total_monthly_cost": None,
                "total_annual_cost": None,
                "terraform_scaffold": "# scaffold",
                "currency": "USD",
            },
            "errors": [],
        }
        runner = CliRunner()
        result = runner.invoke(app, ["estimate", "ec2:m5.large:1", "--output", "json"])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert "resources" in parsed
        assert parsed["currency"] == "USD"
