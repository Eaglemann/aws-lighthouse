"""Tests for cli.py: pure helpers and section renderer functions."""

import io
import json
import re
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console
from typer.testing import CliRunner

from aws_lighthouse.cli import (
    _count,
    _dollar,
    _parse_profiles,
    _parse_remediation_selection,
    _pct_style,
    _scan_scope_key,
    _section_cost_anomalies,
    _section_cost_waste,
    _section_iam,
    _section_lambda_detail,
    _section_remediation,
    _section_security,
    _section_tagging,
    _translate_shell_command,
    app,
    shell,
)


def _ok(data):
    return {"ok": True, "data": data, "errors": []}


def _err(data, message="simulated error"):
    return {
        "ok": False,
        "data": data,
        "errors": [
            {
                "code": "SimulatedError",
                "message": message,
                "service": "test",
                "operation": "op",
            }
        ],
    }


def _scan_error(
    *,
    service: str,
    operation: str,
    code: str,
    message: str,
    region: str | None = None,
):
    error = {
        "code": code,
        "message": message,
        "service": service,
        "operation": operation,
    }
    if region is not None:
        error["region"] = region
    return error


# ---------------------------------------------------------------------------
# Helper: capture Rich output in a string buffer
# ---------------------------------------------------------------------------


def _console() -> tuple[Console, io.StringIO]:
    """Return (console, buffer) — the console writes plain text to the buffer."""
    buf = io.StringIO()
    c = Console(file=buf, no_color=True, highlight=False, width=120)
    return c, buf


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_TEST_LOG_PATH = "/Users/tester/.aws-lighthouse/logs/aws-lighthouse.log"


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


# ---------------------------------------------------------------------------
# _count
# ---------------------------------------------------------------------------


class TestCount:
    def test_normal_list_returns_length(self):
        assert _count([{"id": "i-1"}, {"id": "i-2"}]) == "2"

    def test_single_item_returns_one(self):
        assert _count([{"id": "i-1"}]) == "1"

    def test_empty_list_returns_zero(self):
        assert _count([]) == "0"

    def test_error_first_item_returns_error_markup(self):
        result = _count([{"error": "AccessDenied"}])
        assert result == "1"

    def test_error_key_in_first_item_regardless_of_length(self):
        # Even if there are more items, the first-item error wins
        result = _count([{"error": "msg"}, {"id": "i-1"}])
        assert result == "2"


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


class TestScanScopeKey:
    def test_multi_region_scope_includes_days(self):
        assert _scan_scope_key(None, 14) == "multi-region:days=14"

    def test_single_region_scope_includes_days(self):
        assert _scan_scope_key("us-east-1", 30) == "single-region:us-east-1:days=30"

    def test_policy_scope_token_is_appended(self):
        assert (
            _scan_scope_key(None, 14, policy_scope_token="abc123")  # noqa: S106
            == "multi-region:days=14:policy=abc123"
        )


# ---------------------------------------------------------------------------
# _section_cost_anomalies
# ---------------------------------------------------------------------------


class TestSectionCostAnomalies:
    def test_renders_spike_table_when_anomalies_present(self):
        c, buf = _console()
        anomalies = [
            {
                "service": "EC2",
                "baseline_30d": 100.0,
                "recent_30d": 200.0,
                "pct_change": 100.0,
            }
        ]
        with patch(
            "aws_lighthouse.cli.detect_cost_anomalies", return_value=_ok(anomalies)
        ):
            _section_cost_anomalies(c)
        output = buf.getvalue()
        assert "EC2" in output
        assert "Cost Anomalies" in output

    def test_renders_clear_panel_when_no_anomalies(self):
        c, buf = _console()
        with patch("aws_lighthouse.cli.detect_cost_anomalies", return_value=_ok([])):
            _section_cost_anomalies(c)
        assert "No cost spikes" in buf.getvalue()

    def test_plural_spike_label(self):
        c, buf = _console()
        anomalies = [
            {
                "service": "S3",
                "baseline_30d": 10.0,
                "recent_30d": 20.0,
                "pct_change": 100.0,
            },
            {
                "service": "RDS",
                "baseline_30d": 5.0,
                "recent_30d": 15.0,
                "pct_change": 200.0,
            },
        ]
        with patch(
            "aws_lighthouse.cli.detect_cost_anomalies", return_value=_ok(anomalies)
        ):
            _section_cost_anomalies(c)
        assert "spikes" in buf.getvalue()

    def test_singular_spike_label(self):
        c, buf = _console()
        anomalies = [
            {
                "service": "Lambda",
                "baseline_30d": 1.0,
                "recent_30d": 3.0,
                "pct_change": 200.0,
            }
        ]
        with patch(
            "aws_lighthouse.cli.detect_cost_anomalies", return_value=_ok(anomalies)
        ):
            _section_cost_anomalies(c)
        output = buf.getvalue()
        # "1 spike vs" should appear (not "spikes")
        assert "spike" in output

    def test_renders_degraded_panel_when_scanner_logs_errors(self):
        c, buf = _console()

        def _side_effect(threshold_pct=50.0):  # noqa: ARG001
            return _err([], "Cost Explorer throttled")

        with patch(
            "aws_lighthouse.cli.detect_cost_anomalies", side_effect=_side_effect
        ):
            _section_cost_anomalies(c)

        output = buf.getvalue()
        assert "Degraded" in output
        assert "incomplete" in output.lower() or "degraded" in output.lower()


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
            "aws_lighthouse.cli.detect_overpermissive_iam", return_value=_ok(findings)
        ):
            _section_iam(c)
        output = buf.getvalue()
        assert "alice" in output
        assert "IAM Over-Permissive" in output

    def test_renders_clear_panel_when_no_findings(self):
        c, buf = _console()
        with patch(
            "aws_lighthouse.cli.detect_overpermissive_iam", return_value=_ok([])
        ):
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
            "aws_lighthouse.cli.detect_overpermissive_iam", return_value=_ok(findings)
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
# _section_remediation
# ---------------------------------------------------------------------------


class TestSectionRemediation:
    def test_parse_selection_accepts_all(self):
        assert _parse_remediation_selection("all", 3) == [0, 1, 2]

    def test_parse_selection_accepts_top(self):
        assert _parse_remediation_selection("top", 3) == [0]

    def test_parse_selection_rejects_invalid_values(self):
        with pytest.raises(ValueError, match="Invalid selection"):
            _parse_remediation_selection("1,banana,5", 3)

    def test_regional_remediation_passes_region_to_action(self):
        # delete_ebs_volume is phase 3 (DESTRUCTIVE); approve phase "3" to execute it.
        c, _ = _console()
        sec_findings = [
            {
                "severity": "HIGH",
                "resource": "vol-abc123",
                "finding": "Unattached EBS volume",
                "remediation_type": "delete_ebs_volume",
                "remediation_label": "Delete EBS Volume",
                "region": "eu-west-1",
            }
        ]
        with (
            patch("aws_lighthouse.cli.Prompt.ask", return_value="3"),
            patch(
                "aws_lighthouse.tools.remediation_actions.delete_ebs_volume",
                return_value=True,
            ) as mock_action,
        ):
            _section_remediation(c, sec_findings, [])

        mock_action.assert_called_once_with("vol-abc123", region="eu-west-1")

    def test_regional_remediation_without_region_is_skipped(self):
        # delete_ebs_volume without a region should be skipped with an error.
        c, _ = _console()
        sec_findings = [
            {
                "severity": "HIGH",
                "resource": "vol-no-region",
                "finding": "Unattached EBS volume",
                "remediation_type": "delete_ebs_volume",
                "remediation_label": "Delete EBS Volume",
            }
        ]
        with (
            patch("aws_lighthouse.cli.Prompt.ask", return_value="3"),
            patch("aws_lighthouse.cli.logger.error") as mock_error,
            patch(
                "aws_lighthouse.tools.remediation_actions.delete_ebs_volume",
                return_value=True,
            ) as mock_action,
        ):
            _section_remediation(c, sec_findings, [])

        mock_action.assert_not_called()
        mock_error.assert_called_once()
        assert "Missing region for" in mock_error.call_args[0][0]

    def test_skipping_phases_blocks_remediation_execution(self):
        # Answering "none" skips all phases without executing any action.
        c, _ = _console()
        sec_findings = [
            {
                "severity": "HIGH",
                "resource": "vol-preview",
                "finding": "Unattached EBS volume",
                "remediation_type": "delete_ebs_volume",
                "remediation_label": "Delete EBS Volume",
                "region": "eu-west-1",
            }
        ]
        with (
            patch("aws_lighthouse.cli.Prompt.ask", return_value="none"),
            patch(
                "aws_lighthouse.tools.remediation_actions.delete_ebs_volume",
                return_value=True,
            ) as mock_action,
        ):
            _section_remediation(c, sec_findings, [])

        mock_action.assert_not_called()


# ---------------------------------------------------------------------------
# _section_cost_waste
# ---------------------------------------------------------------------------


class TestSectionCostWaste:
    def test_renders_clear_panel_when_no_findings(self):
        c, buf = _console()
        with patch("aws_lighthouse.cli.run_cost_scan", return_value=_ok([])):
            _section_cost_waste(c, [None], multi_region=False)
        assert "No cost waste" in buf.getvalue()

    def test_renders_findings_table(self):
        c, buf = _console()
        findings = [{"resource": "vol-abc123", "finding": "Unattached EBS volume"}]
        with patch("aws_lighthouse.cli.run_cost_scan", return_value=_ok(findings)):
            result = _section_cost_waste(c, [None], multi_region=False)
        output = buf.getvalue()
        assert "vol-abc123" in output
        assert "Cost Waste" in output
        assert len(result["data"]) == 1

    def test_multi_region_adds_region_column(self):
        c, buf = _console()
        with patch(
            "aws_lighthouse.cli.run_cost_scan",
            side_effect=lambda region=None: _ok(
                [{"resource": "vol-xyz", "finding": "Unattached EBS volume"}]
            ),
        ):
            _section_cost_waste(c, ["us-east-1", "eu-west-1"], multi_region=True)
        assert "Region" in buf.getvalue()

    def test_returns_empty_list_when_no_findings(self):
        c, buf = _console()
        with patch("aws_lighthouse.cli.run_cost_scan", return_value=_ok([])):
            result = _section_cost_waste(c, [None], multi_region=False)
        assert result["data"] == []


# ---------------------------------------------------------------------------
# _section_security
# ---------------------------------------------------------------------------


class TestSectionSecurity:
    def test_renders_clear_panel_when_no_findings(self):
        c, buf = _console()
        with patch("aws_lighthouse.cli.run_security_scan", return_value=_ok([])):
            result = _section_security(c, [], [], [None], multi_region=False)
        assert "All security checks passed" in buf.getvalue()
        assert result["data"] == []

    def test_renders_findings_table(self):
        c, buf = _console()
        findings = [
            {
                "severity": "HIGH",
                "resource": "root",
                "finding": "Root account has no MFA enabled",
            }
        ]
        with patch("aws_lighthouse.cli.run_security_scan", return_value=_ok(findings)):
            result = _section_security(c, [], [], [None], multi_region=False)
        output = buf.getvalue()
        assert "Root account" in output
        assert "Security" in output
        assert len(result["data"]) == 1

    def test_multi_region_adds_region_column(self):
        c, buf = _console()
        findings = [{"severity": "MEDIUM", "resource": "sg-123", "finding": "Open SSH"}]
        with patch(
            "aws_lighthouse.cli.run_security_scan",
            side_effect=lambda **kwargs: (
                _ok(findings) if kwargs.get("include_global") else _ok([])
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
            return _ok([])

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

    def test_multi_region_global_finding_renders_global_scope(self):
        c, buf = _console()
        finding = {
            "severity": "HIGH",
            "resource": "root",
            "finding": "Root account has no MFA enabled",
        }

        with patch(
            "aws_lighthouse.cli.run_security_scan",
            side_effect=lambda **kwargs: (
                _ok([finding]) if kwargs.get("include_global") else _ok([])
            ),
        ):
            _section_security(c, [], [], ["us-east-1", "eu-west-1"], multi_region=True)

        output = buf.getvalue()
        assert "global" in output
        assert "us-east-1" not in output
        assert "eu-west-1" not in output

    def test_renders_degraded_panel_when_scan_logs_errors(self):
        c, buf = _console()

        def _side_effect(**kwargs):  # noqa: ARG001
            return _err([], "AccessDenied on guardduty")

        with patch("aws_lighthouse.cli.run_security_scan", side_effect=_side_effect):
            result = _section_security(c, [], [], [None], multi_region=False)

        assert result["data"] == []
        output = buf.getvalue()
        assert "Security (Degraded)" in output
        assert "incomplete" in output.lower()


class TestSectionTagging:
    def test_multi_region_global_s3_finding_renders_global_scope(self):
        c, buf = _console()
        finding = {
            "resource_type": "S3",
            "resource_id": "bucket-1",
            "resource_name": "bucket-1",
            "missing_tags": ["Owner"],
        }

        with patch(
            "aws_lighthouse.cli.check_tagging_compliance",
            side_effect=lambda **kwargs: (
                _ok([finding]) if kwargs.get("include_s3") else _ok([])
            ),
        ):
            _section_tagging(c, ["us-east-1", "eu-west-1"], multi_region=True)

        output = buf.getvalue()
        assert "global" in output
        assert "us-east-1" not in output
        assert "eu-west-1" not in output


# ---------------------------------------------------------------------------
# analyze --output json
# ---------------------------------------------------------------------------


def _make_db_mock():
    m = MagicMock()
    m.get_latest_cost_snapshot.return_value = None
    m.get_latest_scan_snapshot.return_value = None
    m.get_latest_scan_activity.return_value = None
    m.get_health_status.return_value = {"ok": True, "issue_count": 0, "issues": []}
    m.summarize_opportunities.return_value = {
        "total": 0,
        "by_source": {},
        "by_severity": {},
        "by_status": {},
    }
    m.list_opportunities.return_value = []
    return m


def _opportunity(**overrides):
    opportunity = {
        "fingerprint": "opp-1",
        "source_kind": "security",
        "summary": "Root account has no MFA enabled",
        "severity": "HIGH",
        "resource_id": "root",
        "resource_name": "root",
        "region": None,
        "status": "open",
    }
    opportunity.update(overrides)
    return opportunity


def _ollama_ok(detail="ready"):
    return {
        "ok": True,
        "reason": "ok",
        "host": "http://localhost:11434",
        "model": "gpt-oss:120b-cloud",
        "detail": detail,
    }


def _ollama_unavailable(detail="Connection refused"):
    return {
        "ok": False,
        "reason": "unavailable",
        "host": "http://localhost:11434",
        "model": "gpt-oss:120b-cloud",
        "detail": detail,
    }


def _ollama_model_missing(detail="Installed models: llama3.2:latest"):
    return {
        "ok": False,
        "reason": "model_missing",
        "host": "http://localhost:11434",
        "model": "gpt-oss:120b-cloud",
        "detail": detail,
    }


_PATCHES = {
    "aws_lighthouse.cli.get_aws_session": None,  # replaced below per test
    "aws_lighthouse.cli.get_enabled_regions": lambda: _ok(["us-east-1"]),
    "aws_lighthouse.cli.get_s3_inventory": lambda: _ok([]),
    "aws_lighthouse.cli.get_ec2_inventory": lambda region=None: _ok([]),
    "aws_lighthouse.cli.get_rds_inventory": lambda region=None: _ok([]),
    "aws_lighthouse.cli.get_lambda_inventory": lambda region=None: _ok([]),
    "aws_lighthouse.cli.get_monthly_cost_summary": lambda days=14: _ok(
        {
            "total_usd": 42.0,
            "period": "2024-01-01\u20132024-01-31",
            "start": "2024-01-01",
            "end": "2024-01-31",
            "breakdown": {"EC2": 42.0},
        }
    ),
    "aws_lighthouse.cli.detect_cost_anomalies": lambda threshold_pct=50.0: _ok([]),
    "aws_lighthouse.cli.get_cost_forecast": lambda forecast_days=30: _ok(
        {
            "forecast_start": "2024-02-01",
            "forecast_end": "2024-03-02",
            "total_usd": 55.0,
            "lower_bound_usd": 50.0,
            "upper_bound_usd": 60.0,
        }
    ),
    "aws_lighthouse.cli.get_ri_sp_coverage": lambda days=14: _ok({}),
    "aws_lighthouse.cli.get_cost_attribution": lambda anomalies, **kw: _ok([]),
    "aws_lighthouse.cli.get_sg_blast_radius": lambda sg_ids, **kw: _ok([]),
    "aws_lighthouse.cli.get_ri_recommendations": lambda **kw: _ok([]),
    "aws_lighthouse.cli.get_sp_recommendations": lambda **kw: _ok([]),
    "aws_lighthouse.cli.run_security_scan": lambda **kwargs: _ok([]),
    "aws_lighthouse.cli.detect_overpermissive_iam": lambda: _ok([]),
    "aws_lighthouse.cli.detect_cloudwatch_gaps": lambda region=None: _ok([]),
    "aws_lighthouse.cli.run_cost_scan": lambda region=None: _ok([]),
    "aws_lighthouse.cli.check_tagging_compliance": lambda **kwargs: _ok([]),
    "aws_lighthouse.cli.db_manager": _make_db_mock(),
    "aws_lighthouse.cli.sync_opportunities_from_scan": lambda **kwargs: {
        "created": 0,
        "reopened": 0,
        "resolved": 0,
        "still_open": 0,
    },
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

    def test_explicit_v1_json_schema_preserves_legacy_keyset(self):
        result = self._run(["--json-schema", "v1"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert set(data.keys()) == {
            "account_id",
            "scanned_at",
            "regions",
            "inventory",
            "costs",
            "cost_forecast",
            "cost_anomalies",
            "cost_attribution",
            "ri_sp_coverage",
            "ri_recommendations",
            "sp_recommendations",
            "security_findings",
            "sg_blast_radius",
            "iam_findings",
            "cloudwatch_findings",
            "cost_waste",
            "tagging_findings",
        }

    def test_since_last_v1_adds_delta_object(self):
        result = self._run(["--json-schema", "v1", "--since-last"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert "delta" in data
        assert data["delta"]["baseline_found"] is False
        assert data["delta"]["summary"]["total_new"] == 0
        assert data["delta"]["summary"]["total_resolved"] == 0

    def test_since_last_v2_adds_delta_envelope(self):
        result = self._run(["--json-schema", "v2", "--since-last"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert "delta" in data
        assert data["delta"]["ok"] is True
        assert data["delta"]["data"]["baseline_found"] is False
        assert data["delta"]["errors"] == []

    def test_since_last_persists_snapshot(self):
        runner = CliRunner()
        db_mock = _make_db_mock()
        patches = {
            **_PATCHES,
            "aws_lighthouse.cli.get_aws_session": _mock_session,
            "aws_lighthouse.cli.db_manager": db_mock,
        }
        with patch.multiple(
            "aws_lighthouse.cli", **{k.split(".")[-1]: v for k, v in patches.items()}
        ):
            result = runner.invoke(
                app,
                ["analyze", "--output", "json", "--json-schema", "v1", "--since-last"],
            )

        assert result.exit_code == 0, result.output
        db_mock.get_latest_scan_snapshot.assert_called_once_with(
            "123456789012", "multi-region:days=14"
        )
        db_mock.record_scan_snapshot.assert_called_once()
        assert (
            db_mock.record_scan_snapshot.call_args.kwargs["scope_key"]
            == "multi-region:days=14"
        )

    def test_since_last_different_days_use_different_scope_keys(self):
        runner = CliRunner()
        db_mock = _make_db_mock()
        patches = {
            **_PATCHES,
            "aws_lighthouse.cli.get_aws_session": _mock_session,
            "aws_lighthouse.cli.db_manager": db_mock,
        }
        with patch.multiple(
            "aws_lighthouse.cli", **{k.split(".")[-1]: v for k, v in patches.items()}
        ):
            first = runner.invoke(
                app,
                [
                    "analyze",
                    "--output",
                    "json",
                    "--json-schema",
                    "v1",
                    "--since-last",
                    "--days",
                    "14",
                ],
            )
            second = runner.invoke(
                app,
                [
                    "analyze",
                    "--output",
                    "json",
                    "--json-schema",
                    "v1",
                    "--since-last",
                    "--days",
                    "30",
                ],
            )

        assert first.exit_code == 0, first.output
        assert second.exit_code == 0, second.output
        observed = [
            call.args for call in db_mock.get_latest_scan_snapshot.call_args_list
        ]
        assert observed == [
            ("123456789012", "multi-region:days=14"),
            ("123456789012", "multi-region:days=30"),
        ]

    def test_since_last_same_days_reuse_same_scope_key(self):
        runner = CliRunner()
        db_mock = _make_db_mock()
        patches = {
            **_PATCHES,
            "aws_lighthouse.cli.get_aws_session": _mock_session,
            "aws_lighthouse.cli.db_manager": db_mock,
        }
        with patch.multiple(
            "aws_lighthouse.cli", **{k.split(".")[-1]: v for k, v in patches.items()}
        ):
            first = runner.invoke(
                app,
                [
                    "analyze",
                    "--output",
                    "json",
                    "--json-schema",
                    "v1",
                    "--since-last",
                    "--days",
                    "14",
                ],
            )
            second = runner.invoke(
                app,
                [
                    "analyze",
                    "--output",
                    "json",
                    "--json-schema",
                    "v1",
                    "--since-last",
                    "--days",
                    "14",
                ],
            )

        assert first.exit_code == 0, first.output
        assert second.exit_code == 0, second.output
        observed = [
            call.args for call in db_mock.get_latest_scan_snapshot.call_args_list
        ]
        assert observed == [
            ("123456789012", "multi-region:days=14"),
            ("123456789012", "multi-region:days=14"),
        ]

    def test_since_last_second_run_reports_new_and_resolved(self):
        runner = CliRunner()
        db_mock = _make_db_mock()
        db_mock.get_latest_scan_snapshot.return_value = {
            "recorded_at": "2026-03-04T10:00:00",
            "data": {
                "inventory": {"ec2": [], "rds": [], "s3": [], "lambda": []},
                "costs": {
                    "total_usd": 42.0,
                    "period": "2024-01-01-2024-01-31",
                    "start": "2024-01-01",
                    "end": "2024-01-31",
                    "breakdown": {"EC2": 42.0},
                },
                "cost_anomalies": [],
                "ri_sp_coverage": {},
                "security_findings": [
                    {
                        "severity": "HIGH",
                        "resource": "old-resource",
                        "finding": "old finding",
                    }
                ],
                "iam_findings": [],
                "cloudwatch_findings": [],
                "cost_waste": [],
                "tagging_findings": [],
            },
        }

        def _security_now(**kwargs):  # noqa: ARG001
            return _ok(
                [
                    {
                        "severity": "HIGH",
                        "resource": "new-resource",
                        "finding": "new finding",
                    }
                ]
            )

        patches = {
            **_PATCHES,
            "aws_lighthouse.cli.get_aws_session": _mock_session,
            "aws_lighthouse.cli.db_manager": db_mock,
            "aws_lighthouse.cli.run_security_scan": _security_now,
        }
        with patch.multiple(
            "aws_lighthouse.cli", **{k.split(".")[-1]: v for k, v in patches.items()}
        ):
            result = runner.invoke(
                app,
                ["analyze", "--output", "json", "--json-schema", "v1", "--since-last"],
            )

        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        sec_delta = data["delta"]["sections"]["security_findings"]
        assert len(sec_delta["new"]) == 1
        assert len(sec_delta["resolved"]) == 1
        assert sec_delta["new"][0]["resource"] == "new-resource"
        assert sec_delta["resolved"][0]["resource"] == "old-resource"

    def test_v2_json_schema_returns_envelopes_and_overall(self):
        result = self._run(["--json-schema", "v2"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)

        assert "overall" in data
        assert "inventory" in data
        assert "security_findings" in data
        assert data["overall"]["ok"] is True
        assert data["overall"]["errors"] == []
        assert data["inventory"]["ok"] is True
        assert data["inventory"]["errors"] == []
        assert data["security_findings"]["ok"] is True
        assert isinstance(data["security_findings"]["data"], list)

    def test_top_level_keys_present(self):
        result = self._run()
        data = json.loads(result.output)
        expected_keys = {
            "account_id",
            "scanned_at",
            "regions",
            "inventory",
            "costs",
            "cost_forecast",
            "cost_anomalies",
            "cost_attribution",
            "ri_sp_coverage",
            "ri_recommendations",
            "sp_recommendations",
            "security_findings",
            "sg_blast_radius",
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

    def test_json_output_not_contaminated_by_logger_errors(self):
        """Even when a scan path logs an error, stdout must remain valid JSON."""
        runner = CliRunner()
        patches = {**_PATCHES, "aws_lighthouse.cli.get_aws_session": _mock_session}

        def noisy_security_scan(**kwargs):
            return _err([], "simulated scanner error")

        with patch.multiple(
            "aws_lighthouse.cli",
            **{
                k.split(".")[-1]: (
                    noisy_security_scan if k.endswith("run_security_scan") else v
                )
                for k, v in patches.items()
            },
        ):
            result = runner.invoke(app, ["analyze", "--output", "json"])

        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["account_id"] == "123456789012"

    def test_analyze_json_error_includes_log_path_and_stays_parseable(self):
        runner = CliRunner()
        with (
            patch(
                "aws_lighthouse.cli._run_analyze_cycle",
                side_effect=RuntimeError("boom"),
            ),
            patch(
                "aws_lighthouse.cli.logger.record_exception",
                return_value=_TEST_LOG_PATH,
            ) as mock_record,
        ):
            result = runner.invoke(app, ["analyze", "--output", "json"])

        assert result.exit_code == 1
        payload = json.loads(result.output)
        assert payload["event"] == "error"
        assert payload["message"] == "boom"
        assert payload["log_path"] == _TEST_LOG_PATH
        mock_record.assert_called_once()
        assert "[bold" not in result.output

    def test_v2_overall_marks_degraded_when_any_section_errors(self):
        runner = CliRunner()
        patches = {**_PATCHES, "aws_lighthouse.cli.get_aws_session": _mock_session}

        def degraded_security_scan(**kwargs):  # noqa: ARG001
            return _err([], "security scan degraded")

        with patch.multiple(
            "aws_lighthouse.cli",
            **{
                k.split(".")[-1]: (
                    degraded_security_scan if k.endswith("run_security_scan") else v
                )
                for k, v in patches.items()
            },
        ):
            result = runner.invoke(
                app, ["analyze", "--output", "json", "--json-schema", "v2"]
            )

        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["overall"]["ok"] is False
        assert "security_findings" in data["overall"]["data"]["degraded_sections"]
        assert len(data["overall"]["errors"]) >= 1

    def test_v2_delta_marks_degraded_when_section_errors_exist(self):
        runner = CliRunner()
        patches = {**_PATCHES, "aws_lighthouse.cli.get_aws_session": _mock_session}

        def degraded_security_scan(**kwargs):  # noqa: ARG001
            return _err([], "security scan degraded")

        with patch.multiple(
            "aws_lighthouse.cli",
            **{
                k.split(".")[-1]: (
                    degraded_security_scan if k.endswith("run_security_scan") else v
                )
                for k, v in patches.items()
            },
        ):
            result = runner.invoke(
                app,
                [
                    "analyze",
                    "--output",
                    "json",
                    "--json-schema",
                    "v2",
                    "--since-last",
                ],
            )

        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["delta"]["ok"] is False
        assert data["delta"]["data"]["summary"]["degraded"] is True
        assert data["delta"]["data"]["summary"]["error_count"] >= 1

    def test_invalid_json_schema_rejected(self):
        runner = CliRunner()
        with patch("aws_lighthouse.cli.get_aws_session", _mock_session):
            result = runner.invoke(
                app, ["analyze", "--output", "json", "--json-schema", "v3"]
            )

        assert result.exit_code != 0
        plain = _strip_ansi(result.output).lower()
        assert "json-schema" in plain
        assert (
            "--json-schema must be either 'v1' or 'v2'" in plain
            or "invalid value for '--json-schema'" in plain
        )

    def test_invalid_output_rejected(self):
        runner = CliRunner()
        with patch("aws_lighthouse.cli.get_aws_session", _mock_session):
            result = runner.invoke(app, ["analyze", "--output", "xml"])
        assert result.exit_code != 0
        plain = _strip_ansi(result.output).lower()
        assert "output" in plain
        assert (
            "--output must be either 'text' or 'json'" in plain
            or "invalid value for '--output'" in plain
        )

    def test_config_invalid_toml_is_rejected(self, tmp_path):
        config = tmp_path / "policy.toml"
        config.write_text("required_tags = [", encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(
            app,
            ["analyze", "--output", "json", "--config", str(config)],
        )

        assert result.exit_code != 0
        plain = _strip_ansi(result.output)
        assert "Invalid --config file" in plain
        assert "TOML parse error" in plain

    def test_config_validation_error_is_rejected(self, tmp_path):
        config = tmp_path / "policy.toml"
        config.write_text("cost_anomaly_threshold_pct = -1\n", encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(
            app,
            ["analyze", "--output", "json", "--config", str(config)],
        )

        assert result.exit_code != 0
        plain = _strip_ansi(result.output)
        assert "Invalid --config file" in plain
        assert "cost_anomaly_threshold_pct" in plain

    def test_config_required_tags_are_passed_to_tagging(self, tmp_path):
        config = tmp_path / "policy.toml"
        config.write_text(
            'required_tags = ["Environment", "Owner", "CostCenter"]\n',
            encoding="utf-8",
        )

        runner = CliRunner()
        patches = {**_PATCHES, "aws_lighthouse.cli.get_aws_session": _mock_session}
        with (
            patch.multiple(
                "aws_lighthouse.cli",
                **{k.split(".")[-1]: v for k, v in patches.items()},
            ),
            patch(
                "aws_lighthouse.cli.check_tagging_compliance", return_value=_ok([])
            ) as mock_tagging,
        ):
            result = runner.invoke(
                app,
                ["analyze", "--output", "json", "--config", str(config)],
            )

        assert result.exit_code == 0, result.output
        required_tags = mock_tagging.call_args.kwargs["required_tags"]
        assert required_tags == ["Environment", "Owner", "CostCenter"]

    def test_config_threshold_is_passed_to_cost_anomalies(self, tmp_path):
        config = tmp_path / "policy.toml"
        config.write_text("cost_anomaly_threshold_pct = 75\n", encoding="utf-8")

        runner = CliRunner()
        patches = {**_PATCHES, "aws_lighthouse.cli.get_aws_session": _mock_session}
        with (
            patch.multiple(
                "aws_lighthouse.cli",
                **{k.split(".")[-1]: v for k, v in patches.items()},
            ),
            patch(
                "aws_lighthouse.cli.detect_cost_anomalies", return_value=_ok([])
            ) as mock_anomalies,
        ):
            result = runner.invoke(
                app,
                ["analyze", "--output", "json", "--config", str(config)],
            )

        assert result.exit_code == 0, result.output
        assert mock_anomalies.call_args.kwargs["threshold_pct"] == 75.0

    def test_json_output_with_config_remains_machine_clean(self, tmp_path):
        config = tmp_path / "policy.toml"
        config.write_text("cost_anomaly_threshold_pct = 75\n", encoding="utf-8")

        result = self._run(["--config", str(config)])

        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["account_id"] == "123456789012"
        assert "[bold" not in result.output
        assert "\x1b[" not in result.output

    def test_config_can_disable_sections_without_breaking_json_shape(self, tmp_path):
        config = tmp_path / "policy.toml"
        config.write_text(
            """
[scans]
security = false
tagging = false
""".strip(),
            encoding="utf-8",
        )

        runner = CliRunner()
        patches = {**_PATCHES, "aws_lighthouse.cli.get_aws_session": _mock_session}
        with (
            patch.multiple(
                "aws_lighthouse.cli",
                **{k.split(".")[-1]: v for k, v in patches.items()},
            ),
            patch("aws_lighthouse.cli.run_security_scan") as mock_security,
            patch("aws_lighthouse.cli.check_tagging_compliance") as mock_tagging,
        ):
            result = runner.invoke(
                app,
                [
                    "analyze",
                    "--output",
                    "json",
                    "--json-schema",
                    "v1",
                    "--config",
                    str(config),
                ],
            )

        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["security_findings"] == []
        assert payload["tagging_findings"] == []
        mock_security.assert_not_called()
        mock_tagging.assert_not_called()

    def test_config_region_filters_limit_multi_region_runs(self, tmp_path):
        config = tmp_path / "policy.toml"
        config.write_text(
            """
[regions]
include = ["us-west-2"]
""".strip(),
            encoding="utf-8",
        )

        runner = CliRunner()
        db_mock = _make_db_mock()
        patches = {
            **_PATCHES,
            "aws_lighthouse.cli.get_aws_session": _mock_session,
            "aws_lighthouse.cli.get_enabled_regions": lambda: _ok(
                ["us-east-1", "us-west-2"]
            ),
            "aws_lighthouse.cli.db_manager": db_mock,
        }
        with patch.multiple(
            "aws_lighthouse.cli", **{k.split(".")[-1]: v for k, v in patches.items()}
        ):
            result = runner.invoke(
                app,
                [
                    "analyze",
                    "--output",
                    "json",
                    "--json-schema",
                    "v1",
                    "--since-last",
                    "--config",
                    str(config),
                ],
            )

        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["regions"] == ["us-west-2"]
        scope_key = db_mock.record_scan_snapshot.call_args.kwargs["scope_key"]
        assert scope_key.startswith("multi-region:days=14:policy=")

    def test_explicit_region_overrides_config_region_filters_for_scope(self, tmp_path):
        config = tmp_path / "policy.toml"
        config.write_text(
            """
[regions]
include = ["us-west-2"]
""".strip(),
            encoding="utf-8",
        )

        runner = CliRunner()
        db_mock = _make_db_mock()
        patches = {
            **_PATCHES,
            "aws_lighthouse.cli.get_aws_session": _mock_session,
            "aws_lighthouse.cli.db_manager": db_mock,
        }
        with patch.multiple(
            "aws_lighthouse.cli", **{k.split(".")[-1]: v for k, v in patches.items()}
        ):
            result = runner.invoke(
                app,
                [
                    "analyze",
                    "--output",
                    "json",
                    "--json-schema",
                    "v1",
                    "--since-last",
                    "--region",
                    "us-east-1",
                    "--config",
                    str(config),
                ],
            )

        assert result.exit_code == 0, result.output
        db_mock.get_latest_scan_snapshot.assert_called_once_with(
            "123456789012", "single-region:us-east-1:days=14"
        )

    def test_default_value_config_reuses_existing_scope_key(self, tmp_path):
        config = tmp_path / "policy.toml"
        config.write_text(
            """
required_tags = ["Environment", "Owner"]
cost_anomaly_threshold_pct = 50

[scans]
cost_anomalies = true
ri_sp_coverage = true
security = true
iam = true
cloudwatch = true
cost_waste = true
tagging = true
""".strip(),
            encoding="utf-8",
        )

        runner = CliRunner()
        db_mock = _make_db_mock()
        patches = {
            **_PATCHES,
            "aws_lighthouse.cli.get_aws_session": _mock_session,
            "aws_lighthouse.cli.db_manager": db_mock,
        }
        with patch.multiple(
            "aws_lighthouse.cli", **{k.split(".")[-1]: v for k, v in patches.items()}
        ):
            result = runner.invoke(
                app,
                [
                    "analyze",
                    "--output",
                    "json",
                    "--json-schema",
                    "v1",
                    "--since-last",
                    "--config",
                    str(config),
                ],
            )

        assert result.exit_code == 0, result.output
        assert (
            db_mock.record_scan_snapshot.call_args.kwargs["scope_key"]
            == "multi-region:days=14"
        )

    def test_config_region_filter_unknown_enabled_region_is_rejected(self, tmp_path):
        config = tmp_path / "policy.toml"
        config.write_text(
            """
[regions]
include = ["eu-west-1"]
""".strip(),
            encoding="utf-8",
        )

        runner = CliRunner()
        patches = {
            **_PATCHES,
            "aws_lighthouse.cli.get_aws_session": _mock_session,
            "aws_lighthouse.cli.get_enabled_regions": lambda: _ok(["us-east-1"]),
        }
        with patch.multiple(
            "aws_lighthouse.cli", **{k.split(".")[-1]: v for k, v in patches.items()}
        ):
            result = runner.invoke(
                app,
                ["analyze", "--output", "json", "--config", str(config)],
            )

        assert result.exit_code != 0
        plain = _strip_ansi(result.output)
        assert "region filter error" in plain
        assert "configured regions are not" in plain
        assert "enabled for this account" in plain


class TestWatchCommand:
    @staticmethod
    def _payload(account_id: str = "123456789012") -> dict:
        return {
            "v1": {"account_id": account_id, "delta": {"baseline_found": False}},
            "v2": {
                "account_id": account_id,
                "overall": {"ok": True, "data": {}, "errors": []},
                "delta": {"ok": True, "data": {}, "errors": []},
            },
        }

    def test_watch_json_emits_valid_json_line(self):
        runner = CliRunner()
        with (
            patch(
                "aws_lighthouse.cli._run_analyze_cycle",
                return_value=self._payload(),
            ),
            patch("aws_lighthouse.cli.time.sleep", side_effect=KeyboardInterrupt),
        ):
            result = runner.invoke(
                app,
                [
                    "watch",
                    "--output",
                    "json",
                    "--json-schema",
                    "v1",
                    "--interval-hours",
                    "0.001",
                ],
            )

        assert result.exit_code == 0, result.output
        lines = [line for line in result.output.splitlines() if line.strip()]
        assert len(lines) == 1
        payload = json.loads(lines[0])
        assert payload["account_id"] == "123456789012"
        assert "delta" in payload
        assert payload["delta"]["baseline_found"] is False

    def test_watch_json_v2_emits_valid_json_line(self):
        runner = CliRunner()
        with (
            patch(
                "aws_lighthouse.cli._run_analyze_cycle",
                return_value=self._payload(),
            ),
            patch("aws_lighthouse.cli.time.sleep", side_effect=KeyboardInterrupt),
        ):
            result = runner.invoke(
                app,
                [
                    "watch",
                    "--output",
                    "json",
                    "--json-schema",
                    "v2",
                    "--interval-hours",
                    "0.001",
                ],
            )

        assert result.exit_code == 0, result.output
        lines = [line for line in result.output.splitlines() if line.strip()]
        assert len(lines) == 1
        payload = json.loads(lines[0])
        assert payload["account_id"] == "123456789012"
        assert payload["overall"]["ok"] is True
        assert payload["delta"]["ok"] is True

    def test_watch_text_continues_after_cycle_error(self):
        runner = CliRunner()
        with (
            patch(
                "aws_lighthouse.cli._run_analyze_cycle",
                side_effect=[RuntimeError("boom"), self._payload()],
            ) as mock_cycle,
            patch(
                "aws_lighthouse.cli.logger.exception",
                return_value=_TEST_LOG_PATH,
            ) as mock_exception,
            patch(
                "aws_lighthouse.cli.time.sleep", side_effect=[None, KeyboardInterrupt]
            ),
        ):
            result = runner.invoke(app, ["watch", "--interval-hours", "0.001"])

        assert result.exit_code == 0, result.output
        assert mock_cycle.call_count == 2
        mock_exception.assert_called_once()
        assert "Watch cycle 1 failed" in mock_exception.call_args[0][0]

    def test_watch_json_emits_error_line_then_success_line(self):
        runner = CliRunner()
        with (
            patch(
                "aws_lighthouse.cli._run_analyze_cycle",
                side_effect=[RuntimeError("boom"), self._payload()],
            ),
            patch(
                "aws_lighthouse.cli.time.sleep", side_effect=[None, KeyboardInterrupt]
            ),
        ):
            result = runner.invoke(
                app,
                [
                    "watch",
                    "--output",
                    "json",
                    "--json-schema",
                    "v1",
                    "--interval-hours",
                    "0.001",
                ],
            )

        assert result.exit_code == 0, result.output
        lines = [line for line in result.output.splitlines() if line.strip()]
        assert len(lines) == 2
        first = json.loads(lines[0])
        second = json.loads(lines[1])
        assert first["event"] == "error"
        assert first["cycle"] == 1
        assert first["message"] == "boom"
        assert "log_path" in first
        assert second["account_id"] == "123456789012"

    def test_watch_json_v2_mixed_stream_lines_are_parseable(self):
        runner = CliRunner()
        with (
            patch(
                "aws_lighthouse.cli._run_analyze_cycle",
                side_effect=[RuntimeError("boom"), self._payload()],
            ),
            patch(
                "aws_lighthouse.cli.time.sleep", side_effect=[None, KeyboardInterrupt]
            ),
        ):
            result = runner.invoke(
                app,
                [
                    "watch",
                    "--output",
                    "json",
                    "--json-schema",
                    "v2",
                    "--interval-hours",
                    "0.001",
                ],
            )

        assert result.exit_code == 0, result.output
        lines = [line for line in result.output.splitlines() if line.strip()]
        assert len(lines) == 2
        first = json.loads(lines[0])
        second = json.loads(lines[1])
        assert first["event"] == "error"
        assert first["cycle"] == 1
        assert first["message"] == "boom"
        assert "log_path" in first
        assert second["account_id"] == "123456789012"
        assert second["overall"]["ok"] is True

    def test_watch_rejects_invalid_interval(self):
        runner = CliRunner()
        result = runner.invoke(app, ["watch", "--interval-hours", "0"])
        assert result.exit_code != 0
        plain = _strip_ansi(result.output).lower()
        assert "interval-hours" in plain
        assert (
            "--interval-hours must be greater than zero" in plain
            or "invalid value for '--interval-hours'" in plain
        )

    def test_watch_loads_and_passes_policy_config(self, tmp_path):
        config = tmp_path / "policy.toml"
        config.write_text("cost_anomaly_threshold_pct = 75\n", encoding="utf-8")

        runner = CliRunner()
        with (
            patch(
                "aws_lighthouse.cli._run_analyze_cycle",
                return_value=self._payload(),
            ) as mock_cycle,
            patch("aws_lighthouse.cli.time.sleep", side_effect=KeyboardInterrupt),
        ):
            result = runner.invoke(
                app,
                [
                    "watch",
                    "--output",
                    "json",
                    "--json-schema",
                    "v1",
                    "--interval-hours",
                    "0.001",
                    "--config",
                    str(config),
                ],
            )

        assert result.exit_code == 0, result.output
        policy = mock_cycle.call_args.kwargs["policy"]
        assert policy is not None
        assert policy.cost_anomaly_threshold_pct == 75.0

    def test_watch_text_defaults_to_compact_view(self):
        runner = CliRunner()
        with (
            patch(
                "aws_lighthouse.cli._run_analyze_cycle",
                return_value=self._payload(),
            ) as mock_cycle,
            patch("aws_lighthouse.cli.time.sleep", side_effect=KeyboardInterrupt),
        ):
            result = runner.invoke(app, ["watch", "--interval-hours", "0.001"])

        assert result.exit_code == 0, result.output
        assert mock_cycle.call_args.kwargs["watch_view"] == "compact"

    def test_watch_text_passes_full_view(self):
        runner = CliRunner()
        with (
            patch(
                "aws_lighthouse.cli._run_analyze_cycle",
                return_value=self._payload(),
            ) as mock_cycle,
            patch("aws_lighthouse.cli.time.sleep", side_effect=KeyboardInterrupt),
        ):
            result = runner.invoke(
                app, ["watch", "--interval-hours", "0.001", "--view", "full"]
            )

        assert result.exit_code == 0, result.output
        assert mock_cycle.call_args.kwargs["watch_view"] == "full"

    def test_watch_rejects_invalid_view(self):
        runner = CliRunner()
        result = runner.invoke(
            app,
            ["watch", "--interval-hours", "0.001", "--view", "wide"],
        )

        assert result.exit_code != 0
        plain = _strip_ansi(result.output)
        assert "--view must be either 'compact' or 'full'" in plain

    def test_watch_compact_renders_digest_without_full_panels(self):
        runner = CliRunner()
        patches = {**_PATCHES, "aws_lighthouse.cli.get_aws_session": _mock_session}
        with (
            patch.multiple(
                "aws_lighthouse.cli",
                **{k.split(".")[-1]: v for k, v in patches.items()},
            ),
            patch("aws_lighthouse.cli.time.sleep", side_effect=KeyboardInterrupt),
        ):
            result = runner.invoke(app, ["watch", "--interval-hours", "0.001"])

        assert result.exit_code == 0, result.output
        assert "Watch Digest" in result.output
        assert "Tagging Compliance" not in result.output

    def test_watch_full_renders_detailed_panels(self):
        runner = CliRunner()
        patches = {**_PATCHES, "aws_lighthouse.cli.get_aws_session": _mock_session}
        with (
            patch.multiple(
                "aws_lighthouse.cli",
                **{k.split(".")[-1]: v for k, v in patches.items()},
            ),
            patch("aws_lighthouse.cli.time.sleep", side_effect=KeyboardInterrupt),
        ):
            result = runner.invoke(
                app,
                ["watch", "--interval-hours", "0.001", "--view", "full"],
            )

        assert result.exit_code == 0, result.output
        assert "Tagging Compliance" in result.output


class TestAnalyzeInteractiveMode:
    def _run_text(self, args=None, extra_patches=None):
        runner = CliRunner()
        patches = {**_PATCHES, "aws_lighthouse.cli.get_aws_session": _mock_session}
        if extra_patches:
            patches.update(extra_patches)
        with patch.multiple(
            "aws_lighthouse.cli", **{k.split(".")[-1]: v for k, v in patches.items()}
        ):
            return runner.invoke(app, ["analyze"] + (args or []))

    def test_default_analyze_skips_interactive_sections(self):
        with (
            patch("aws_lighthouse.cli._section_remediation") as mock_remediation,
            patch("aws_lighthouse.cli._section_cur_upsell") as mock_cur,
        ):
            result = self._run_text()

        assert result.exit_code == 0, result.output
        mock_remediation.assert_not_called()
        mock_cur.assert_not_called()

    def test_interactive_flag_executes_interactive_sections(self):
        with (
            patch("aws_lighthouse.cli._section_remediation") as mock_remediation,
            patch("aws_lighthouse.cli._section_cur_upsell") as mock_cur,
        ):
            result = self._run_text(args=["--interactive"])

        assert result.exit_code == 0, result.output
        mock_remediation.assert_called_once()
        mock_cur.assert_called_once()

    def test_empty_inventory_renders_zero_counts_not_error(self):
        result = self._run_text()
        assert result.exit_code == 0, result.output
        assert "Error" not in result.output
        assert "EC2 Instances" in result.output

    def test_text_output_renders_opportunity_sync_summary(self):
        result = self._run_text(
            extra_patches={
                "aws_lighthouse.cli.sync_opportunities_from_scan": lambda **kwargs: {
                    "created": 2,
                    "reopened": 1,
                    "resolved": 3,
                    "still_open": 4,
                }
            }
        )

        assert result.exit_code == 0, result.output
        assert (
            "Opportunities synced: 2 new, 1 reopened, 3 resolved, 4 still open."
            in result.output
        )

    def test_text_output_includes_executive_summary_and_top_opportunities(self):
        db_mock = _make_db_mock()
        db_mock.summarize_opportunities.return_value = {
            "total": 1,
            "by_source": {"security": 1},
            "by_severity": {"HIGH": 1},
            "by_status": {"open": 1},
        }
        db_mock.list_opportunities.return_value = [_opportunity()]

        result = self._run_text(
            extra_patches={"aws_lighthouse.cli.db_manager": db_mock}
        )

        assert result.exit_code == 0, result.output
        assert "Executive Summary" in result.output
        assert "Top Opportunities" in result.output
        assert "Root account has no MFA enabled" in result.output

    def test_text_output_surfaces_local_state_degradation(self):
        db_mock = _make_db_mock()
        db_mock.get_health_status.return_value = {
            "ok": False,
            "issue_count": 2,
            "issues": [
                {
                    "operation": "record_scan_snapshot",
                    "detail": "OperationalError: unable to open database file",
                },
                {
                    "operation": "record_audit_log",
                    "detail": "OperationalError: database is locked",
                },
            ],
        }

        result = self._run_text(
            extra_patches={"aws_lighthouse.cli.db_manager": db_mock}
        )

        assert result.exit_code == 0, result.output
        assert "Local State Degraded" in result.output
        assert "Scan snapshot writes" in result.output
        assert "Audit log writes" in result.output
        assert "unable to open database file" in result.output

    def test_summary_separates_degraded_and_skipped_sections(self, tmp_path):
        config = tmp_path / "policy.toml"
        config.write_text(
            """
[scans]
tagging = false
""".strip(),
            encoding="utf-8",
        )

        result = self._run_text(
            args=["--config", str(config)],
            extra_patches={
                "aws_lighthouse.cli.run_security_scan": lambda **kwargs: _err(
                    [], "security degraded"
                )
            },
        )

        assert result.exit_code == 0, result.output
        assert "Section Health" in result.output
        assert "Degraded" in result.output
        assert "Security" in result.output
        assert "Skipped" in result.output
        assert "Tagging" in result.output

    def test_expected_unavailable_errors_render_aggregated_degraded_services(self):
        ri_sp_result = {
            "ok": False,
            "data": {
                "period": "2026-02-20 → 2026-03-06",
                "ri_coverage_pct": 0.0,
                "ri_on_demand_cost": 0.0,
                "ri_utilization_pct": 0.0,
                "ri_unused_cost": 0.0,
                "sp_coverage_pct": None,
                "sp_on_demand_cost": None,
                "sp_utilization_pct": None,
                "sp_unused_commitment": None,
            },
            "errors": [
                _scan_error(
                    service="ce",
                    operation="GetSavingsPlansCoverage",
                    code="DataUnavailableException",
                    message="Savings Plans data is unavailable",
                ),
                _scan_error(
                    service="ce",
                    operation="GetSavingsPlansUtilization",
                    code="DataUnavailableException",
                    message="Savings Plans data is unavailable",
                ),
            ],
        }
        security_result = {
            "ok": False,
            "data": [],
            "errors": [
                _scan_error(
                    service="guardduty",
                    operation="ListDetectors",
                    code="SubscriptionRequiredException",
                    message="subscription required",
                    region="us-east-1",
                ),
                _scan_error(
                    service="guardduty",
                    operation="ListDetectors",
                    code="SubscriptionRequiredException",
                    message="subscription required",
                    region="us-west-2",
                ),
            ],
        }

        result = self._run_text(
            extra_patches={
                "aws_lighthouse.cli.get_ri_sp_coverage": lambda days=14: ri_sp_result,
                "aws_lighthouse.cli.run_security_scan": lambda **kwargs: (
                    security_result
                ),
            }
        )

        assert result.exit_code == 0, result.output
        assert "Degraded Services" in result.output
        assert "Savings Plans data unavailable for this account/period" in result.output
        assert "GuardDuty" in result.output
        assert "2 regions" in result.output
        assert "us-east-1" in result.output
        assert "us-west-2" in result.output
        assert (
            "GuardDuty checks unavailable in 2 regions (subscription required)."
            in result.output
        )
        assert "Failed to fetch SP coverage" not in result.output
        assert "Failed to check GuardDuty" not in result.output

    def test_json_output_preserves_expected_unavailable_errors(self):
        runner = CliRunner()
        patches = {**_PATCHES, "aws_lighthouse.cli.get_aws_session": _mock_session}
        with patch.multiple(
            "aws_lighthouse.cli",
            **{
                k.split(".")[-1]: (
                    (
                        lambda days=14: {
                            "ok": False,
                            "data": {},
                            "errors": [
                                _scan_error(
                                    service="ce",
                                    operation="GetSavingsPlansCoverage",
                                    code="DataUnavailableException",
                                    message="Savings Plans data is unavailable",
                                )
                            ],
                        }
                    )
                    if k.endswith("get_ri_sp_coverage")
                    else v
                )
                for k, v in patches.items()
            },
        ):
            result = runner.invoke(
                app, ["analyze", "--output", "json", "--json-schema", "v2"]
            )

        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["ri_sp_coverage"]["errors"][0]["code"] == "DataUnavailableException"
        assert data["overall"]["ok"] is False

    def test_json_output_does_not_emit_opportunity_summary_text(self):
        runner = CliRunner()
        patches = {**_PATCHES, "aws_lighthouse.cli.get_aws_session": _mock_session}
        with patch.multiple(
            "aws_lighthouse.cli", **{k.split(".")[-1]: v for k, v in patches.items()}
        ):
            result = runner.invoke(app, ["analyze", "--output", "json"])

        assert result.exit_code == 0, result.output
        assert "Opportunities synced:" not in result.output


class TestShellCommands:
    def test_translate_shell_command_maps_slash_commands(self):
        assert _translate_shell_command("/help") == ("help", None)
        assert _translate_shell_command("/status") == ("status", None)
        assert _translate_shell_command("/opps") == ("opps", None)
        assert _translate_shell_command("/plan") == ("plan", None)
        assert _translate_shell_command("/logs") == ("logs", None)
        assert _translate_shell_command("/clear") == ("clear", None)
        assert _translate_shell_command("/exit") == ("exit", None)

    def test_translate_shell_command_rewrites_analyze(self):
        action, content = _translate_shell_command("/analyze")
        assert action == "analyze"
        assert content is not None
        assert content == "analyze"

    def test_translate_shell_command_keeps_analyze_flags(self):
        action, content = _translate_shell_command("analyze --days 30 --since-last")
        assert action == "analyze"
        assert content == "analyze --days 30 --since-last"

    def test_shell_startup_alerts_when_ollama_is_unreachable(self, capsys):
        with (
            patch(
                "aws_lighthouse.agent.check_ollama_runtime",
                return_value=_ollama_unavailable(),
            ),
            patch("aws_lighthouse.agent.create_agent_graph") as mock_create,
            patch("aws_lighthouse.cli.Prompt.ask", side_effect=["/exit"]),
        ):
            shell()

        output = capsys.readouterr().out
        assert "Ollama Unavailable" in output
        mock_create.assert_not_called()

    def test_shell_startup_alerts_when_ollama_model_is_missing(self, capsys):
        with (
            patch(
                "aws_lighthouse.agent.check_ollama_runtime",
                return_value=_ollama_model_missing(),
            ),
            patch("aws_lighthouse.agent.create_agent_graph") as mock_create,
            patch("aws_lighthouse.cli.Prompt.ask", side_effect=["/exit"]),
        ):
            shell()

        output = capsys.readouterr().out
        assert "Ollama Model Missing" in output
        mock_create.assert_not_called()

    def test_local_shell_commands_do_not_invoke_agent_stream(self):
        graph = MagicMock()
        db_mock = _make_db_mock()
        db_mock.get_latest_scan_activity.return_value = {
            "recorded_at": "2026-03-06T12:00:00+00:00",
            "account_id": "123456789012",
            "scope_key": "multi-region:days=14",
        }
        db_mock.summarize_opportunities.return_value = {
            "total": 2,
            "by_source": {"security": 1, "tagging": 1},
            "by_severity": {"HIGH": 1, "UNSPECIFIED": 1},
            "by_status": {"open": 2},
        }
        db_mock.list_opportunities.return_value = [
            _opportunity(),
            _opportunity(
                fingerprint="opp-2",
                source_kind="tagging",
                summary="Bucket is missing Owner",
                severity=None,
                resource_id="bucket-1",
                resource_name="bucket-1",
            ),
        ]

        with (
            patch(
                "aws_lighthouse.agent.check_ollama_runtime",
                return_value=_ollama_unavailable(),
            ),
            patch(
                "aws_lighthouse.agent.create_agent_graph", return_value=graph
            ) as mock_create,
            patch(
                "aws_lighthouse.cli.Prompt.ask",
                side_effect=["/status", "/opps", "/plan", "/logs", "/exit"],
            ),
            patch("aws_lighthouse.cli.db_manager", db_mock),
            patch(
                "aws_lighthouse.cli.logger.tail_log",
                return_value="latest traceback",
            ),
            patch(
                "aws_lighthouse.cli.logger.get_log_path",
                return_value=_TEST_LOG_PATH,
            ),
        ):
            shell()

        mock_create.assert_not_called()
        graph.stream.assert_not_called()
        db_mock.summarize_opportunities.assert_called_once_with(
            account_id="123456789012",
            statuses=["open", "triaged", "in_progress", "snoozed"],
        )
        db_mock.list_opportunities.assert_any_call(
            account_id="123456789012",
            statuses=["open", "triaged", "in_progress", "snoozed"],
            limit=5,
        )
        db_mock.list_opportunities.assert_any_call(
            account_id="123456789012",
            statuses=["open", "triaged", "in_progress", "snoozed"],
            limit=10,
        )

    def test_agent_calls_alert_each_time_when_ollama_is_unhealthy(self, capsys):
        with (
            patch(
                "aws_lighthouse.agent.check_ollama_runtime",
                return_value=_ollama_unavailable(),
            ),
            patch("aws_lighthouse.agent.create_agent_graph") as mock_create,
            patch(
                "aws_lighthouse.cli.Prompt.ask",
                side_effect=["scan all my regions", "/exit"],
            ),
        ):
            shell()

        output = capsys.readouterr().out
        assert output.count("Ollama Unavailable") >= 2
        mock_create.assert_not_called()

    def test_shell_analyze_bypasses_agent_even_when_ollama_is_unavailable(self):
        with (
            patch(
                "aws_lighthouse.agent.check_ollama_runtime",
                return_value=_ollama_unavailable(),
            ),
            patch("aws_lighthouse.agent.create_agent_graph") as mock_create,
            patch("aws_lighthouse.cli._run_analyze_command") as mock_run_analyze,
            patch(
                "aws_lighthouse.cli.Prompt.ask",
                side_effect=["analyze --days 30 --since-last", "/exit"],
            ),
        ):
            shell()

        mock_create.assert_not_called()
        mock_run_analyze.assert_called_once_with(
            days=30,
            region=None,
            output="text",
            json_schema="v1",
            since_last=True,
            config=None,
            interactive=False,
        )

    def test_shell_slash_analyze_bypasses_agent(self):
        graph = MagicMock()
        with (
            patch(
                "aws_lighthouse.agent.check_ollama_runtime",
                return_value=_ollama_ok(),
            ),
            patch(
                "aws_lighthouse.agent.create_agent_graph", return_value=graph
            ) as mock_create,
            patch("aws_lighthouse.cli._run_analyze_command") as mock_run_analyze,
            patch(
                "aws_lighthouse.cli.Prompt.ask",
                side_effect=["/analyze --region us-east-1 --output json", "/exit"],
            ),
        ):
            shell()

        mock_create.assert_called_once()
        graph.stream.assert_not_called()
        mock_run_analyze.assert_called_once_with(
            days=14,
            region="us-east-1",
            output="json",
            json_schema="v1",
            since_last=False,
            config=None,
            interactive=False,
        )

    def test_shell_analyze_invalid_flags_keep_shell_running(self, capsys):
        with (
            patch(
                "aws_lighthouse.agent.check_ollama_runtime",
                return_value=_ollama_unavailable(),
            ),
            patch(
                "aws_lighthouse.cli.Prompt.ask",
                side_effect=["analyze --bogus", "/exit"],
            ),
        ):
            shell()

        output = capsys.readouterr().out
        assert "Unknown analyze option: --bogus" in output

    def test_shell_recovers_when_ollama_returns(self):
        graph = MagicMock()
        graph.stream.return_value = []

        with (
            patch(
                "aws_lighthouse.agent.check_ollama_runtime",
                side_effect=[_ollama_unavailable(), _ollama_ok()],
            ),
            patch(
                "aws_lighthouse.agent.create_agent_graph", return_value=graph
            ) as mock_create,
            patch(
                "aws_lighthouse.cli.Prompt.ask",
                side_effect=["scan all my regions", "/exit"],
            ),
        ):
            shell()

        mock_create.assert_called_once()
        graph.stream.assert_called_once()

    def test_runtime_loss_during_stream_shows_ollama_alert(self, capsys):
        graph = MagicMock()
        graph.stream.side_effect = RuntimeError("connection refused")

        with (
            patch(
                "aws_lighthouse.agent.check_ollama_runtime",
                side_effect=[
                    _ollama_ok(),
                    _ollama_ok(),
                    _ollama_unavailable(),
                ],
            ),
            patch("aws_lighthouse.agent.create_agent_graph", return_value=graph),
            patch(
                "aws_lighthouse.cli.Prompt.ask",
                side_effect=["scan all my regions", "/exit"],
            ),
            patch("aws_lighthouse.cli.logger.error") as mock_error,
        ):
            shell()

        output = capsys.readouterr().out
        assert "Ollama Unavailable" in output
        mock_error.assert_not_called()

    def test_shell_generic_agent_error_points_to_logs(self, capsys):
        graph = MagicMock()
        graph.stream.side_effect = RuntimeError("boom")

        with (
            patch(
                "aws_lighthouse.agent.check_ollama_runtime",
                side_effect=[_ollama_ok(), _ollama_ok(), _ollama_ok()],
            ),
            patch("aws_lighthouse.agent.create_agent_graph", return_value=graph),
            patch(
                "aws_lighthouse.cli.Prompt.ask",
                side_effect=["scan all my regions", "/exit"],
            ),
            patch(
                "aws_lighthouse.cli.logger.exception",
                return_value=_TEST_LOG_PATH,
            ) as mock_exception,
            patch(
                "aws_lighthouse.cli.logger.get_log_path",
                return_value=_TEST_LOG_PATH,
            ),
        ):
            shell()

        output = capsys.readouterr().out
        assert "Use /logs to inspect the latest traceback" in output
        mock_exception.assert_called_once()


# ---------------------------------------------------------------------------
# Multi-profile support
# ---------------------------------------------------------------------------


class TestParseProfiles:
    """Unit tests for _parse_profiles helper."""

    def test_single_profile(self) -> None:
        assert _parse_profiles("dev") == ["dev"]

    def test_multiple_profiles(self) -> None:
        assert _parse_profiles("dev,staging,prod") == ["dev", "staging", "prod"]

    def test_strips_whitespace(self) -> None:
        assert _parse_profiles(" dev , staging ") == ["dev", "staging"]

    def test_deduplicates_preserving_order(self) -> None:
        assert _parse_profiles("dev,dev,staging") == ["dev", "staging"]

    def test_empty_string_returns_empty(self) -> None:
        assert _parse_profiles("") == []

    def test_commas_only_returns_empty(self) -> None:
        assert _parse_profiles(",,,") == []


class TestAnalyzeMultiProfile:
    """Integration tests for analyze --profiles."""

    def test_profiles_flag_runs_per_profile(self) -> None:
        runner = CliRunner()
        calls: list[dict] = []

        def fake_cycle(**kwargs: object) -> dict:
            calls.append(dict(kwargs))
            return {
                "v1": {
                    "account_id": "123456789012",
                    "security_findings": [],
                    "iam_findings": [],
                    "cost_waste": [],
                    "tagging_findings": [],
                },
                "v2": {},
            }

        with (
            patch("aws_lighthouse.cli._run_analyze_cycle", side_effect=fake_cycle),
            patch("aws_lighthouse.cli.profile_context") as mock_ctx,
            patch.multiple(
                "aws_lighthouse.cli",
                **{k.split(".")[-1]: v for k, v in _PATCHES.items()},
            ),
        ):
            mock_ctx.return_value.__enter__ = lambda s: None
            mock_ctx.return_value.__exit__ = lambda s, *a: False
            result = runner.invoke(app, ["analyze", "--profiles", "dev,staging"])

        assert result.exit_code == 0, result.output
        assert len(calls) == 2

    def test_profiles_and_region_are_mutually_exclusive(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            app, ["analyze", "--profiles", "dev", "--region", "us-east-1"]
        )
        assert result.exit_code != 0

    def test_profiles_empty_string_is_rejected(self) -> None:
        runner = CliRunner()
        result = runner.invoke(app, ["analyze", "--profiles", ""])
        assert result.exit_code != 0

    def test_profiles_json_output_wraps_in_profiles_key(self) -> None:
        runner = CliRunner()

        def fake_cycle(**kwargs: object) -> dict:
            return {
                "v1": {
                    "account_id": "111111111111",
                    "security_findings": [],
                    "iam_findings": [],
                    "cost_waste": [],
                    "tagging_findings": [],
                },
                "v2": {},
            }

        with (
            patch("aws_lighthouse.cli._run_analyze_cycle", side_effect=fake_cycle),
            patch("aws_lighthouse.cli.profile_context") as mock_ctx,
            patch.multiple(
                "aws_lighthouse.cli",
                **{k.split(".")[-1]: v for k, v in _PATCHES.items()},
            ),
        ):
            mock_ctx.return_value.__enter__ = lambda s: None
            mock_ctx.return_value.__exit__ = lambda s, *a: False
            result = runner.invoke(
                app, ["analyze", "--profiles", "dev", "--output", "json"]
            )

        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert "profiles" in data
        assert data["profiles"][0]["profile"] == "dev"

    def test_profiles_failed_profile_shows_error_in_summary(self) -> None:
        runner = CliRunner()

        def fake_cycle(**kwargs: object) -> dict:
            raise RuntimeError("NoCredentialsError")

        with (
            patch("aws_lighthouse.cli._run_analyze_cycle", side_effect=fake_cycle),
            patch("aws_lighthouse.cli.profile_context") as mock_ctx,
            patch.multiple(
                "aws_lighthouse.cli",
                **{k.split(".")[-1]: v for k, v in _PATCHES.items()},
            ),
        ):
            mock_ctx.return_value.__enter__ = lambda s: None
            mock_ctx.return_value.__exit__ = lambda s, *a: False
            result = runner.invoke(app, ["analyze", "--profiles", "bad-profile"])

        assert result.exit_code == 0, result.output
