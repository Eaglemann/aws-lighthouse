"""Tests for opportunity mapping and lifecycle sync."""

import pytest

import aws_lighthouse.db as db_module
from aws_lighthouse.db import DatabaseManager
from aws_lighthouse.opportunities import (
    TRACKED_SOURCE_KINDS,
    build_scan_opportunities,
    sync_opportunities_from_scan,
)


@pytest.fixture()
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(db_module, "DB_DIR", tmp_path)
    monkeypatch.setattr(db_module, "DB_PATH", tmp_path / "test.db")
    return DatabaseManager()


def _sections(**overrides):
    base = {
        "cost_anomalies": [],
        "cost_waste": [],
        "security_findings": [],
        "iam_findings": [],
        "cloudwatch_findings": [],
        "tagging_findings": [],
    }
    base.update(overrides)
    return base


def _sync(db: DatabaseManager, *, sections, regions=("us-east-1",), enabled=None):
    enabled_source_kinds = list(enabled or TRACKED_SOURCE_KINDS)
    return sync_opportunities_from_scan(
        db=db,
        account_id="123456789012",
        scanned_at="2026-03-06T10:00:00+00:00",
        scan_scope="multi-region:days=14",
        section_payloads=sections,
        scanned_regions=regions,
        enabled_source_kinds=enabled_source_kinds,
    )


def test_fingerprint_is_stable_for_equivalent_tag_findings():
    first = build_scan_opportunities(
        account_id="123456789012",
        scanned_at="2026-03-06T10:00:00+00:00",
        scan_scope="multi-region:days=14",
        scanned_regions=["us-east-1"],
        section_payloads=_sections(
            tagging_findings=[
                {
                    "resource_type": "EC2",
                    "resource_id": "i-123",
                    "resource_name": "web",
                    "missing_tags": ["Owner", "Environment"],
                }
            ]
        ),
    )
    second = build_scan_opportunities(
        account_id="123456789012",
        scanned_at="2026-03-06T10:00:00+00:00",
        scan_scope="multi-region:days=14",
        scanned_regions=["us-east-1"],
        section_payloads=_sections(
            tagging_findings=[
                {
                    "resource_type": "EC2",
                    "resource_id": "i-123",
                    "resource_name": "web",
                    "missing_tags": ["Environment", "Owner"],
                }
            ]
        ),
    )

    assert first[0]["fingerprint"] == second[0]["fingerprint"]


def test_sync_promotes_all_supported_sources_into_opportunities(db):
    summary = _sync(
        db,
        sections=_sections(
            cost_anomalies=[
                {
                    "service": "AmazonEC2",
                    "baseline_7d": 100.0,
                    "recent_7d": 220.0,
                    "pct_change": 120.0,
                }
            ],
            cost_waste=[
                {
                    "resource": "vol-123",
                    "finding": "Unattached EBS volume (100 GB gp3) — paying for storage with no instance",
                }
            ],
            security_findings=[
                {
                    "severity": "HIGH",
                    "resource": "sg-123",
                    "finding": "Security group 'web' allows port 22 from 0.0.0.0/0",
                }
            ],
            iam_findings=[
                {
                    "severity": "HIGH",
                    "principal_type": "Role",
                    "principal_name": "AdminRole",
                    "policy_type": "AWS Managed",
                    "policy_name": "AdministratorAccess",
                    "reason": "Known over-permissive AWS policy: AdministratorAccess",
                }
            ],
            cloudwatch_findings=[
                {
                    "resource_type": "EC2",
                    "resource_id": "i-123",
                    "resource_name": "web",
                    "missing_alarms": ["CPUUtilization", "StatusCheckFailed"],
                }
            ],
            tagging_findings=[
                {
                    "resource_type": "S3",
                    "resource_id": "bucket-1",
                    "resource_name": "bucket-1",
                    "missing_tags": ["Owner"],
                }
            ],
        ),
    )

    opportunities = db.list_opportunities(account_id="123456789012", limit=20)
    assert summary == {"created": 6, "reopened": 0, "resolved": 0, "still_open": 6}
    assert {opportunity["source_kind"] for opportunity in opportunities} == set(
        TRACKED_SOURCE_KINDS
    )


def test_repeat_sync_refreshes_existing_rows_without_duplication(db):
    sections = _sections(
        cloudwatch_findings=[
            {
                "resource_type": "EC2",
                "resource_id": "i-123",
                "resource_name": "web",
                "missing_alarms": ["CPUUtilization"],
            }
        ]
    )

    first = _sync(db, sections=sections, enabled=["cloudwatch"])
    second = _sync(db, sections=sections, enabled=["cloudwatch"])
    opportunities = db.list_opportunities(
        account_id="123456789012",
        statuses=["open"],
        source_kinds=["cloudwatch"],
        limit=10,
    )

    assert first["created"] == 1
    assert second == {"created": 0, "reopened": 0, "resolved": 0, "still_open": 1}
    assert len(opportunities) == 1
    assert opportunities[0]["seen_count"] == 2


def test_missing_finding_auto_resolves_when_coverage_matches(db):
    sections = _sections(
        security_findings=[
            {
                "severity": "HIGH",
                "resource": "sg-123",
                "finding": "Security group 'web' allows port 22 from 0.0.0.0/0",
            }
        ]
    )
    _sync(db, sections=sections, enabled=["security"])

    summary = _sync(db, sections=_sections(), enabled=["security"])
    opportunities = db.list_opportunities(
        account_id="123456789012",
        source_kinds=["security"],
        limit=10,
    )

    assert summary["resolved"] == 1
    assert opportunities[0]["status"] == "resolved"
    assert opportunities[0]["resolution_reason"] == "not_seen_in_scan"


def test_reappearing_ignored_or_resolved_finding_reopens(db):
    sections = _sections(
        cost_waste=[
            {
                "resource": "vol-123",
                "finding": "Unattached EBS volume (100 GB gp3) — paying for storage with no instance",
            }
        ]
    )
    _sync(db, sections=sections, enabled=["cost_waste"])
    opportunity = db.list_opportunities(
        account_id="123456789012",
        source_kinds=["cost_waste"],
        limit=10,
    )[0]
    db.update_opportunity_state(
        fingerprint=opportunity["fingerprint"],
        account_id="123456789012",
        status="ignored",
    )

    summary = _sync(db, sections=sections, enabled=["cost_waste"])
    refreshed = db.get_opportunity(
        fingerprint=opportunity["fingerprint"],
        account_id="123456789012",
    )

    assert summary["reopened"] == 1
    assert refreshed is not None
    assert refreshed["status"] == "open"


def test_snooze_owner_and_notes_persist_across_refreshes(db):
    sections = _sections(
        tagging_findings=[
            {
                "resource_type": "EC2",
                "resource_id": "i-123",
                "resource_name": "web",
                "missing_tags": ["Owner"],
            }
        ]
    )
    _sync(db, sections=sections, enabled=["tagging"])
    opportunity = db.list_opportunities(
        account_id="123456789012",
        source_kinds=["tagging"],
        limit=10,
    )[0]
    db.update_opportunity_state(
        fingerprint=opportunity["fingerprint"],
        account_id="123456789012",
        owner="platform",
        snooze_until="2026-03-13T00:00:00+00:00",
        note="Waiting on service owner",
    )

    _sync(db, sections=sections, enabled=["tagging"])
    refreshed = db.get_opportunity(
        fingerprint=opportunity["fingerprint"],
        account_id="123456789012",
    )

    assert refreshed is not None
    assert refreshed["status"] == "snoozed"
    assert refreshed["owner"] == "platform"
    assert refreshed["snooze_until"] == "2026-03-13T00:00:00+00:00"
    assert "Waiting on service owner" in refreshed["notes"]
