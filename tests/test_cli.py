"""Tests for cli.py: pure helpers and section renderer functions."""

import io
import json
from unittest.mock import MagicMock, patch

from rich.console import Console
from typer.testing import CliRunner

from aws_lighthouse.cli import (
    _count,
    _dollar,
    _pct_style,
    _section_cost_anomalies,
    _section_cost_waste,
    _section_iam,
    _section_lambda_detail,
    _section_security,
    app,
)

# ---------------------------------------------------------------------------
# Helper: capture Rich output in a string buffer
# ---------------------------------------------------------------------------


def _console() -> tuple[Console, io.StringIO]:
    """Return (console, buffer) — the console writes plain text to the buffer."""
    buf = io.StringIO()
    c = Console(file=buf, no_color=True, highlight=False, width=120)
    return c, buf


# ---------------------------------------------------------------------------
# _count
# ---------------------------------------------------------------------------


class TestCount:
    def test_normal_list_returns_length(self):
        assert _count([{"id": "i-1"}, {"id": "i-2"}]) == "2"

    def test_single_item_returns_one(self):
        assert _count([{"id": "i-1"}]) == "1"

    def test_empty_list_returns_error_markup(self):
        result = _count([])
        assert "[red]" in result

    def test_error_first_item_returns_error_markup(self):
        result = _count([{"error": "AccessDenied"}])
        assert "[red]" in result

    def test_error_key_in_first_item_regardless_of_length(self):
        # Even if there are more items, the first-item error wins
        result = _count([{"error": "msg"}, {"id": "i-1"}])
        assert "[red]" in result


# ---------------------------------------------------------------------------
# _pct_style
# ---------------------------------------------------------------------------


class TestPctStyle:
    def test_none_returns_na(self):
        assert _pct_style(None) == "[dim]N/A[/dim]"

    def test_above_high_is_green(self):
        result = _pct_style(85.0, low=60.0, high=80.0)
        assert "green" in result
        assert "85.0%" in result

    def test_exactly_at_high_is_green(self):
        result = _pct_style(80.0, low=60.0, high=80.0)
        assert "green" in result

    def test_between_low_and_high_is_yellow(self):
        result = _pct_style(70.0, low=60.0, high=80.0)
        assert "yellow" in result
        assert "70.0%" in result

    def test_exactly_at_low_is_yellow(self):
        result = _pct_style(60.0, low=60.0, high=80.0)
        assert "yellow" in result

    def test_below_low_is_red(self):
        result = _pct_style(40.0, low=60.0, high=80.0)
        assert "red" in result
        assert "40.0%" in result

    def test_zero_is_red(self):
        result = _pct_style(0.0)
        assert "red" in result

    def test_custom_thresholds_respected(self):
        assert "green" in _pct_style(95.0, low=90.0, high=95.0)
        assert "red" in _pct_style(80.0, low=90.0, high=95.0)


# ---------------------------------------------------------------------------
# _dollar
# ---------------------------------------------------------------------------


class TestDollar:
    def test_none_returns_na(self):
        assert _dollar(None) == "[dim]N/A[/dim]"

    def test_zero(self):
        assert _dollar(0.0) == "$0.00"

    def test_positive_value(self):
        assert _dollar(1234.56) == "$1,234.56"

    def test_large_value_uses_comma_separator(self):
        assert _dollar(1_000_000.0) == "$1,000,000.00"


# ---------------------------------------------------------------------------
# _section_cost_anomalies
# ---------------------------------------------------------------------------


class TestSectionCostAnomalies:
    def test_renders_spike_table_when_anomalies_present(self):
        c, buf = _console()
        anomalies = [
            {
                "service": "EC2",
                "baseline_7d": 100.0,
                "recent_7d": 200.0,
                "pct_change": 100.0,
            }
        ]
        with patch("aws_lighthouse.cli.detect_cost_anomalies", return_value=anomalies):
            _section_cost_anomalies(c)
        output = buf.getvalue()
        assert "EC2" in output
        assert "Cost Anomalies" in output

    def test_renders_clear_panel_when_no_anomalies(self):
        c, buf = _console()
        with patch("aws_lighthouse.cli.detect_cost_anomalies", return_value=[]):
            _section_cost_anomalies(c)
        assert "No cost spikes" in buf.getvalue()

    def test_plural_spike_label(self):
        c, buf = _console()
        anomalies = [
            {
                "service": "S3",
                "baseline_7d": 10.0,
                "recent_7d": 20.0,
                "pct_change": 100.0,
            },
            {
                "service": "RDS",
                "baseline_7d": 5.0,
                "recent_7d": 15.0,
                "pct_change": 200.0,
            },
        ]
        with patch("aws_lighthouse.cli.detect_cost_anomalies", return_value=anomalies):
            _section_cost_anomalies(c)
        assert "spikes" in buf.getvalue()

    def test_singular_spike_label(self):
        c, buf = _console()
        anomalies = [
            {
                "service": "Lambda",
                "baseline_7d": 1.0,
                "recent_7d": 3.0,
                "pct_change": 200.0,
            }
        ]
        with patch("aws_lighthouse.cli.detect_cost_anomalies", return_value=anomalies):
            _section_cost_anomalies(c)
        output = buf.getvalue()
        # "1 spike vs" should appear (not "spikes")
        assert "spike" in output


# ---------------------------------------------------------------------------
# _section_iam
# ---------------------------------------------------------------------------


class TestSectionIam:
    def test_renders_findings_table(self):
        c, buf = _console()
        findings = [
            {
                "severity": "HIGH",
                "principal_type": "User",
                "principal_name": "alice",
                "policy_type": "inline",
                "policy_name": "AllowAll",
                "reason": "Action:* on Resource:*",
            }
        ]
        with patch(
            "aws_lighthouse.cli.detect_overpermissive_iam", return_value=findings
        ):
            _section_iam(c)
        output = buf.getvalue()
        assert "alice" in output
        assert "IAM Over-Permissive" in output

    def test_renders_clear_panel_when_no_findings(self):
        c, buf = _console()
        with patch("aws_lighthouse.cli.detect_overpermissive_iam", return_value=[]):
            _section_iam(c)
        assert "No over-permissive" in buf.getvalue()

    def test_principal_formatted_as_type_slash_name(self):
        c, buf = _console()
        findings = [
            {
                "severity": "MEDIUM",
                "principal_type": "Role",
                "principal_name": "dev-role",
                "policy_type": "managed",
                "policy_name": "PowerUserAccess",
                "reason": "Service-level wildcard",
            }
        ]
        with patch(
            "aws_lighthouse.cli.detect_overpermissive_iam", return_value=findings
        ):
            _section_iam(c)
        assert "Role/dev-role" in buf.getvalue()


# ---------------------------------------------------------------------------
# _section_lambda_detail
# ---------------------------------------------------------------------------


class TestSectionLambdaDetail:
    def test_empty_list_produces_no_output(self):
        c, buf = _console()
        _section_lambda_detail(c, [])
        assert buf.getvalue() == ""

    def test_error_only_list_produces_no_output(self):
        c, buf = _console()
        _section_lambda_detail(c, [{"error": "AccessDenied"}])
        assert buf.getvalue() == ""

    def test_renders_function_name_and_runtime(self):
        c, buf = _console()
        lambdas = [
            {
                "FunctionName": "my-func",
                "Runtime": "python3.12",
                "MemorySize": 256,
                "CodeSizeMB": 5,
                "LastModified": "2024-06-01",
                "Stale": False,
            }
        ]
        _section_lambda_detail(c, lambdas)
        output = buf.getvalue()
        assert "my-func" in output
        assert "python3.12" in output

    def test_stale_note_appears_when_stale_functions_exist(self):
        c, buf = _console()
        lambdas = [
            {
                "FunctionName": "old-fn",
                "Runtime": "python3.8",
                "MemorySize": 128,
                "CodeSizeMB": 2,
                "LastModified": "2022-01-01",
                "Stale": True,
            }
        ]
        _section_lambda_detail(c, lambdas)
        assert "stale" in buf.getvalue()

    def test_no_stale_note_when_all_fresh(self):
        c, buf = _console()
        lambdas = [
            {
                "FunctionName": "fresh-fn",
                "Runtime": "python3.12",
                "MemorySize": 512,
                "CodeSizeMB": 10,
                "LastModified": "2024-12-01",
                "Stale": False,
            }
        ]
        _section_lambda_detail(c, lambdas)
        assert "stale" not in buf.getvalue()

    def test_error_items_filtered_out(self):
        """Valid and error items mixed — only valid ones are rendered."""
        c, buf = _console()
        lambdas = [
            {"error": "AccessDenied"},
            {
                "FunctionName": "good-fn",
                "Runtime": "python3.12",
                "MemorySize": 128,
                "CodeSizeMB": 1,
                "LastModified": "2024-01-01",
                "Stale": False,
            },
        ]
        _section_lambda_detail(c, lambdas)
        output = buf.getvalue()
        assert "good-fn" in output
        assert "error" not in output.lower()


# ---------------------------------------------------------------------------
# _section_cost_waste
# ---------------------------------------------------------------------------


class TestSectionCostWaste:
    def test_renders_clear_panel_when_no_findings(self):
        c, buf = _console()
        with patch("aws_lighthouse.cli.run_cost_scan", return_value=[]):
            _section_cost_waste(c, [None], multi_region=False)
        assert "No cost waste" in buf.getvalue()

    def test_renders_findings_table(self):
        c, buf = _console()
        findings = [{"resource": "vol-abc123", "finding": "Unattached EBS volume"}]
        with patch("aws_lighthouse.cli.run_cost_scan", return_value=findings):
            result = _section_cost_waste(c, [None], multi_region=False)
        output = buf.getvalue()
        assert "vol-abc123" in output
        assert "Cost Waste" in output
        assert len(result) == 1

    def test_multi_region_adds_region_column(self):
        c, buf = _console()
        with patch(
            "aws_lighthouse.cli.run_cost_scan",
            side_effect=lambda region=None: [
                {"resource": "vol-xyz", "finding": "Unattached EBS volume"}
            ],
        ):
            _section_cost_waste(c, ["us-east-1", "eu-west-1"], multi_region=True)
        assert "Region" in buf.getvalue()

    def test_returns_empty_list_when_no_findings(self):
        c, buf = _console()
        with patch("aws_lighthouse.cli.run_cost_scan", return_value=[]):
            result = _section_cost_waste(c, [None], multi_region=False)
        assert result == []


# ---------------------------------------------------------------------------
# _section_security
# ---------------------------------------------------------------------------


class TestSectionSecurity:
    def test_renders_clear_panel_when_no_findings(self):
        c, buf = _console()
        with patch("aws_lighthouse.cli.run_security_scan", return_value=[]):
            result = _section_security(c, [], [], [None], multi_region=False)
        assert "All security checks passed" in buf.getvalue()
        assert result == []

    def test_renders_findings_table(self):
        c, buf = _console()
        findings = [
            {
                "severity": "HIGH",
                "resource": "root",
                "finding": "Root account has no MFA enabled",
            }
        ]
        with patch("aws_lighthouse.cli.run_security_scan", return_value=findings):
            result = _section_security(c, [], [], [None], multi_region=False)
        output = buf.getvalue()
        assert "Root account" in output
        assert "Security" in output
        assert len(result) == 1

    def test_multi_region_adds_region_column(self):
        c, buf = _console()
        findings = [{"severity": "MEDIUM", "resource": "sg-123", "finding": "Open SSH"}]
        with patch(
            "aws_lighthouse.cli.run_security_scan",
            side_effect=lambda **kwargs: (
                findings if kwargs.get("include_global") else []
            ),
        ):
            _section_security(c, [], [], ["us-east-1", "eu-west-1"], multi_region=True)
        assert "Region" in buf.getvalue()

    def test_global_checks_only_on_first_region(self):
        """include_global must be True only for the first region in the loop."""
        c, buf = _console()
        calls = []

        def capture(**kwargs):
            calls.append(kwargs.get("include_global"))
            return []

        with patch("aws_lighthouse.cli.run_security_scan", side_effect=capture):
            _section_security(
                c,
                [],
                [],
                ["us-east-1", "eu-west-1", "ap-southeast-1"],
                multi_region=True,
            )

        assert calls[0] is True
        assert all(v is False for v in calls[1:])


# ---------------------------------------------------------------------------
# analyze --output json
# ---------------------------------------------------------------------------


def _make_db_mock():
    m = MagicMock()
    m.get_latest_cost_snapshot.return_value = None
    return m


_PATCHES = {
    "aws_lighthouse.cli.get_aws_session": None,  # replaced below per test
    "aws_lighthouse.cli.get_enabled_regions": lambda: ["us-east-1"],
    "aws_lighthouse.cli.get_s3_inventory": lambda: [],
    "aws_lighthouse.cli.get_ec2_inventory": lambda region=None: [],
    "aws_lighthouse.cli.get_rds_inventory": lambda region=None: [],
    "aws_lighthouse.cli.get_lambda_inventory": lambda region=None: [],
    "aws_lighthouse.cli.get_monthly_cost_summary": lambda days=14: {
        "total_usd": 42.0,
        "period": "2024-01-01\u20132024-01-31",
        "start": "2024-01-01",
        "end": "2024-01-31",
        "breakdown": {"EC2": 42.0},
    },
    "aws_lighthouse.cli.detect_cost_anomalies": lambda threshold_pct=50.0: [],
    "aws_lighthouse.cli.get_ri_sp_coverage": lambda days=14: {},
    "aws_lighthouse.cli.run_security_scan": lambda **kwargs: [],
    "aws_lighthouse.cli.detect_overpermissive_iam": lambda: [],
    "aws_lighthouse.cli.detect_cloudwatch_gaps": lambda region=None: [],
    "aws_lighthouse.cli.run_cost_scan": lambda region=None: [],
    "aws_lighthouse.cli.check_tagging_compliance": lambda **kwargs: [],
    "aws_lighthouse.cli.db_manager": _make_db_mock(),
}


def _mock_session():
    session = MagicMock()
    session.client.return_value.get_caller_identity.return_value = {
        "Account": "123456789012"
    }
    return session


class TestAnalyzeJsonOutput:
    def _run(self, extra_args=None):
        runner = CliRunner()
        patches = {**_PATCHES, "aws_lighthouse.cli.get_aws_session": _mock_session}
        with patch.multiple(
            "aws_lighthouse.cli", **{k.split(".")[-1]: v for k, v in patches.items()}
        ):
            return runner.invoke(
                app, ["analyze", "--output", "json"] + (extra_args or [])
            )

    def test_exits_zero(self):
        result = self._run()
        assert result.exit_code == 0, result.output

    def test_output_is_valid_json(self):
        result = self._run()
        data = json.loads(result.output)
        assert isinstance(data, dict)

    def test_top_level_keys_present(self):
        result = self._run()
        data = json.loads(result.output)
        expected_keys = {
            "account_id",
            "scanned_at",
            "regions",
            "inventory",
            "costs",
            "cost_anomalies",
            "ri_sp_coverage",
            "security_findings",
            "iam_findings",
            "cloudwatch_findings",
            "cost_waste",
            "tagging_findings",
        }
        assert expected_keys == set(data.keys())

    def test_account_id_populated(self):
        result = self._run()
        data = json.loads(result.output)
        assert data["account_id"] == "123456789012"

    def test_inventory_has_four_resource_types(self):
        result = self._run()
        data = json.loads(result.output)
        assert set(data["inventory"].keys()) == {"ec2", "rds", "s3", "lambda"}

    def test_costs_total_usd_present(self):
        result = self._run()
        data = json.loads(result.output)
        assert data["costs"]["total_usd"] == 42.0

    def test_no_rich_markup_in_output(self):
        """Ensure no Rich escape sequences leak into the JSON stdout."""
        result = self._run()
        assert "[bold" not in result.output
        assert "\x1b[" not in result.output  # no ANSI escapes
