"""Unit tests for aws_lighthouse/tools/remediation_plan.py."""

import pytest

from aws_lighthouse.tools.remediation_plan import (
    build_remediation_plan,
    parse_phase_selection,
)

pytestmark = [pytest.mark.unit]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    remediation_type: str,
    resource: str = "res-1",
    remediation_label: str | None = None,
    region: str | None = None,
    source: str = "security",
) -> dict:
    return {
        "remediation_type": remediation_type,
        "resource": resource,
        "remediation_label": remediation_label or remediation_type,
        "region": region,
        "_source": source,
    }


# ---------------------------------------------------------------------------
# build_remediation_plan — structure tests
# ---------------------------------------------------------------------------


def test_build_plan_empty_returns_empty() -> None:
    plan = build_remediation_plan([])
    assert plan["total"] == 0
    assert plan["phases"] == []


def test_build_plan_phase1_reversible_types() -> None:
    findings = [
        _make_finding("s3_block_public_access", "bucket-1"),
        _make_finding("s3_default_encryption", "bucket-2"),
        _make_finding("enforce_imdsv2", "i-abc"),
    ]
    plan = build_remediation_plan(findings)
    phase_numbers = [ph["phase"] for ph in plan["phases"]]
    assert phase_numbers == [1]
    assert len(plan["phases"][0]["actions"]) == 3


def test_build_plan_phase1_includes_guardduty_and_cloudtrail() -> None:
    findings = [
        _make_finding("enable_guardduty", "detector-1"),
        _make_finding("enable_cloudtrail_logging", "trail-1"),
    ]
    plan = build_remediation_plan(findings)
    assert len(plan["phases"]) == 1
    assert plan["phases"][0]["phase"] == 1
    assert plan["phases"][0]["risk"] == "REVERSIBLE"


def test_build_plan_phase2_permanent() -> None:
    findings = [_make_finding("release_eip", "eipalloc-abc")]
    plan = build_remediation_plan(findings)
    assert len(plan["phases"]) == 1
    phase = plan["phases"][0]
    assert phase["phase"] == 2
    assert phase["risk"] == "PERMANENT"
    assert phase["color"] == "yellow"


def test_build_plan_phase3_destructive() -> None:
    findings = [
        _make_finding("delete_ebs_volume", "vol-001"),
        _make_finding("terminate_ec2", "i-001"),
    ]
    plan = build_remediation_plan(findings)
    assert len(plan["phases"]) == 1
    phase = plan["phases"][0]
    assert phase["phase"] == 3
    assert phase["risk"] == "DESTRUCTIVE"
    assert phase["color"] == "red"


def test_build_plan_groups_by_phase() -> None:
    findings = [
        _make_finding("s3_block_public_access", "bucket-1"),
        _make_finding("release_eip", "eipalloc-1"),
        _make_finding("delete_ebs_volume", "vol-1"),
        _make_finding("enable_guardduty", "detector-1"),
        _make_finding("terminate_ec2", "i-1"),
    ]
    plan = build_remediation_plan(findings)
    by_phase = {ph["phase"]: ph for ph in plan["phases"]}
    assert set(by_phase.keys()) == {1, 2, 3}
    assert len(by_phase[1]["actions"]) == 2
    assert len(by_phase[2]["actions"]) == 1
    assert len(by_phase[3]["actions"]) == 2


def test_build_plan_total_count_is_sum() -> None:
    findings = [
        _make_finding("s3_block_public_access", "bucket-1"),
        _make_finding("release_eip", "eipalloc-1"),
        _make_finding("delete_ebs_volume", "vol-1"),
    ]
    plan = build_remediation_plan(findings)
    expected = sum(len(ph["actions"]) for ph in plan["phases"])
    assert plan["total"] == expected
    assert plan["total"] == 3


def test_build_plan_preserves_source_field() -> None:
    findings = [
        _make_finding("s3_block_public_access", "bucket-1", source="security"),
        _make_finding("release_eip", "eipalloc-1", source="cost_waste"),
    ]
    plan = build_remediation_plan(findings)
    sources_by_resource = {
        action["resource"]: action["source"]
        for ph in plan["phases"]
        for action in ph["actions"]
    }
    assert sources_by_resource["bucket-1"] == "security"
    assert sources_by_resource["eipalloc-1"] == "cost_waste"


def test_build_plan_skips_non_remediable() -> None:
    findings = [
        {"resource": "bucket-no-type", "remediation_label": "unused"},
        _make_finding("s3_block_public_access", "bucket-ok"),
    ]
    # The first dict has no "remediation_type" key — the caller is responsible
    # for filtering before passing to build_remediation_plan.
    # build_remediation_plan itself will still process it with rtype = "".
    # Test that a finding whose remediation_type is "" falls into phase 2 (unknown → 2).
    plan = build_remediation_plan(findings)
    # bucket-ok is phase 1; bucket-no-type ("" type) defaults to phase 2
    assert plan["total"] == 2
    phase_numbers = sorted(ph["phase"] for ph in plan["phases"])
    assert 1 in phase_numbers
    assert 2 in phase_numbers


def test_build_plan_unknown_type_goes_to_phase2() -> None:
    findings = [_make_finding("some_new_future_action", "resource-x")]
    plan = build_remediation_plan(findings)
    assert len(plan["phases"]) == 1
    assert plan["phases"][0]["phase"] == 2
    assert plan["phases"][0]["risk"] == "PERMANENT"


def test_build_plan_action_id_is_unique_per_index() -> None:
    findings = [
        _make_finding("s3_block_public_access", "bucket-1"),
        _make_finding("s3_block_public_access", "bucket-2"),
    ]
    plan = build_remediation_plan(findings)
    action_ids = [
        action["action_id"] for ph in plan["phases"] for action in ph["actions"]
    ]
    assert len(action_ids) == len(set(action_ids)), "action_ids must be unique"


def test_build_plan_phase_metadata_matches() -> None:
    findings = [_make_finding("enforce_imdsv2", "i-1")]
    plan = build_remediation_plan(findings)
    phase = plan["phases"][0]
    assert phase["title"] == "Phase 1 — Reversible"
    assert phase["color"] == "green"


# ---------------------------------------------------------------------------
# parse_phase_selection
# ---------------------------------------------------------------------------


def test_parse_phase_selection_all() -> None:
    result = parse_phase_selection("all", [1, 2, 3])
    assert result == [1, 2, 3]


def test_parse_phase_selection_single() -> None:
    result = parse_phase_selection("1", [1, 2, 3])
    assert result == [1]


def test_parse_phase_selection_multi_space() -> None:
    result = parse_phase_selection("1 2", [1, 2, 3])
    assert result == [1, 2]


def test_parse_phase_selection_empty_string() -> None:
    result = parse_phase_selection("", [1, 2, 3])
    assert result == []


def test_parse_phase_selection_whitespace_only() -> None:
    result = parse_phase_selection("   ", [1, 2, 3])
    assert result == []


def test_parse_phase_selection_none_keyword() -> None:
    result = parse_phase_selection("none", [1, 2, 3])
    assert result == []


def test_parse_phase_selection_none_keyword_case_insensitive() -> None:
    result = parse_phase_selection("NONE", [1, 2, 3])
    assert result == []


def test_parse_phase_selection_all_only_available() -> None:
    result = parse_phase_selection("all", [1, 3])
    assert result == [1, 3]


def test_parse_phase_selection_invalid_raises() -> None:
    with pytest.raises(ValueError, match="Phase 4 is not in this plan"):
        parse_phase_selection("4", [1, 2])


def test_parse_phase_selection_non_digit_raises() -> None:
    with pytest.raises(ValueError, match="Invalid phase"):
        parse_phase_selection("abc", [1, 2, 3])


def test_parse_phase_selection_deduplicates() -> None:
    result = parse_phase_selection("1 1 2", [1, 2, 3])
    assert result == [1, 2]


def test_parse_phase_selection_result_is_sorted() -> None:
    result = parse_phase_selection("3 1", [1, 2, 3])
    assert result == [1, 3]
