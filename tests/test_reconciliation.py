from aws_lighthouse.reconciliation import (
    build_delta_payload,
    build_persistable_snapshot,
    source_errors_from_section_results,
)
from aws_lighthouse.scan_contract import error_result, ok_result


def _error(*, region: str | None = None) -> dict:
    error = {
        "code": "AccessDeniedException",
        "message": "denied",
        "service": "ec2",
        "operation": "DescribeSecurityGroups",
        "retryable": False,
    }
    if region is not None:
        error["region"] = region
    return error


def test_degraded_delta_reports_positive_evidence_without_false_resolutions():
    baseline = {
        "recorded_at": "2026-08-12T10:00:00+00:00",
        "data": {
            "security_findings": [
                {"resource": "sg-old", "finding": "open ssh", "region": "eu-west-1"}
            ]
        },
    }
    section_results = {
        "security_findings": error_result(
            data=[{"resource": "sg-new", "finding": "open rdp", "region": "us-east-1"}],
            errors=[_error(region="eu-west-1")],
        )
    }

    delta = build_delta_payload(
        baseline_snapshot=baseline,
        section_results=section_results,
        scope_key="multi-region:days=14",
        delta_section_keys=("security_findings",),
    )

    security = delta["sections"]["security_findings"]
    assert security == {
        "new": [{"resource": "sg-new", "finding": "open rdp", "region": "us-east-1"}],
        "resolved": [],
        "unchanged_count": 0,
        "trusted": False,
        "error_count": 1,
    }
    assert delta["summary"]["total_new"] == 1
    assert delta["summary"]["total_resolved"] == 0
    assert delta["summary"]["degraded_sections"] == ["security_findings"]


def test_degraded_list_snapshot_unions_prior_and_current_positive_evidence():
    baseline = {
        "data": {
            "security_findings": [
                {"resource": "sg-old", "finding": "open ssh", "region": "eu-west-1"}
            ],
            "iam_findings": [{"principal_name": "old-admin"}],
        }
    }
    section_results = {
        "security_findings": error_result(
            data=[{"resource": "sg-new", "finding": "open rdp", "region": "us-east-1"}],
            errors=[_error(region="eu-west-1")],
        ),
        "iam_findings": ok_result([]),
    }

    snapshot = build_persistable_snapshot(
        baseline_snapshot=baseline,
        section_results=section_results,
    )

    assert snapshot["security_findings"] == [
        {"resource": "sg-old", "finding": "open ssh", "region": "eu-west-1"},
        {"resource": "sg-new", "finding": "open rdp", "region": "us-east-1"},
    ]
    assert snapshot["iam_findings"] == []


def test_degraded_mapping_snapshot_keeps_last_trustworthy_value():
    baseline = {"data": {"costs": {"total_usd": 123.45}}}
    section_results = {
        "costs": error_result(data={"total_usd": 0.0}, errors=[_error()])
    }

    snapshot = build_persistable_snapshot(
        baseline_snapshot=baseline,
        section_results=section_results,
    )

    assert snapshot["costs"] == {"total_usd": 123.45}


def test_source_errors_are_mapped_from_section_contracts():
    regional_error = _error(region="eu-west-1")
    section_results = {
        "security_findings": error_result(data=[], errors=[regional_error]),
        "iam_findings": ok_result([]),
        "inventory": error_result(data={}, errors=[_error()]),
    }

    assert source_errors_from_section_results(section_results) == {
        "security": [regional_error]
    }


def test_region_discovery_failure_blocks_resolution_for_regional_sources():
    discovery_error = _error()
    section_results = {
        "security_findings": ok_result([]),
        "iam_findings": ok_result([]),
        "cost_waste": ok_result([]),
    }

    errors = source_errors_from_section_results(
        section_results,
        region_discovery_errors=[discovery_error],
        enabled_source_kinds=["security", "iam", "cost_waste"],
    )

    assert errors == {
        "security": [discovery_error],
        "cost_waste": [discovery_error],
    }
