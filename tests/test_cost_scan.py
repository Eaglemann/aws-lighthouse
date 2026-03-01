from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

from aws_lighthouse.tools.cost_scan import (
    _check_old_snapshots,
    _check_stopped_ec2,
    _check_unassociated_eips,
    _check_unattached_ebs,
    run_cost_scan,
)

MOD = "aws_lighthouse.tools.cost_scan"


# ── _check_unattached_ebs ─────────────────────────────────────────────────────


def _make_volumes_ec2(volumes):
    ec2 = MagicMock()
    ec2.get_paginator.return_value.paginate.return_value = [{"Volumes": volumes}]
    return ec2


def test_unattached_ebs_found():
    ec2 = _make_volumes_ec2([{"VolumeId": "vol-abc", "Size": 100, "VolumeType": "gp3"}])
    findings = _check_unattached_ebs(ec2)
    assert len(findings) == 1
    assert findings[0]["resource"] == "vol-abc"
    assert "100 GB" in findings[0]["finding"]
    assert findings[0]["remediation_type"] == "delete_ebs_volume"


def test_unattached_ebs_none():
    ec2 = _make_volumes_ec2([])
    assert _check_unattached_ebs(ec2) == []


def test_unattached_ebs_api_error_returns_empty():
    ec2 = MagicMock()
    ec2.get_paginator.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": ""}}, "DescribeVolumes"
    )
    assert _check_unattached_ebs(ec2) == []


# ── _check_stopped_ec2 ────────────────────────────────────────────────────────


def _make_instances_ec2(reservations):
    ec2 = MagicMock()
    ec2.get_paginator.return_value.paginate.return_value = [
        {"Reservations": reservations}
    ]
    return ec2


def test_stopped_ec2_found():
    ec2 = _make_instances_ec2(
        [
            {
                "Instances": [
                    {
                        "InstanceId": "i-111",
                        "InstanceType": "t3.micro",
                        "Tags": [{"Key": "Name", "Value": "my-server"}],
                    }
                ]
            }
        ]
    )
    findings = _check_stopped_ec2(ec2)
    assert len(findings) == 1
    assert findings[0]["resource"] == "i-111"
    assert "my-server" in findings[0]["finding"]


def test_stopped_ec2_uses_instance_id_when_no_name():
    ec2 = _make_instances_ec2(
        [
            {
                "Instances": [
                    {"InstanceId": "i-222", "InstanceType": "t3.small", "Tags": []}
                ]
            }
        ]
    )
    findings = _check_stopped_ec2(ec2)
    assert len(findings) == 1
    assert "i-222" in findings[0]["finding"]


def test_stopped_ec2_none():
    ec2 = _make_instances_ec2([])
    assert _check_stopped_ec2(ec2) == []


def test_stopped_ec2_api_error_returns_empty():
    ec2 = MagicMock()
    ec2.get_paginator.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": ""}}, "DescribeInstances"
    )
    assert _check_stopped_ec2(ec2) == []


# ── _check_old_snapshots ──────────────────────────────────────────────────────


def _make_snapshots_ec2(snapshots):
    ec2 = MagicMock()
    ec2.get_paginator.return_value.paginate.return_value = [{"Snapshots": snapshots}]
    return ec2


def test_old_snapshot_flagged():
    old = datetime.now(timezone.utc) - timedelta(days=100)
    ec2 = _make_snapshots_ec2(
        [
            {
                "SnapshotId": "snap-abc",
                "StartTime": old,
                "VolumeSize": 50,
                "Description": "old backup",
            }
        ]
    )
    findings = _check_old_snapshots(ec2)
    assert len(findings) == 1
    assert findings[0]["resource"] == "snap-abc"
    assert "50 GB" in findings[0]["finding"]


def test_recent_snapshot_not_flagged():
    recent = datetime.now(timezone.utc) - timedelta(days=10)
    ec2 = _make_snapshots_ec2(
        [
            {
                "SnapshotId": "snap-xyz",
                "StartTime": recent,
                "VolumeSize": 20,
                "Description": "fresh",
            }
        ]
    )
    assert _check_old_snapshots(ec2) == []


def test_old_snapshots_api_error_returns_empty():
    ec2 = MagicMock()
    ec2.get_paginator.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": ""}}, "DescribeSnapshots"
    )
    assert _check_old_snapshots(ec2) == []


# ── _check_unassociated_eips ──────────────────────────────────────────────────


def test_unassociated_eip_flagged():
    ec2 = MagicMock()
    ec2.describe_addresses.return_value = {
        "Addresses": [{"AllocationId": "eipalloc-123", "PublicIp": "1.2.3.4"}]
    }
    findings = _check_unassociated_eips(ec2)
    assert len(findings) == 1
    assert findings[0]["resource"] == "eipalloc-123"
    assert "1.2.3.4" in findings[0]["finding"]
    assert findings[0]["remediation_type"] == "release_eip"


def test_associated_eip_not_flagged():
    ec2 = MagicMock()
    ec2.describe_addresses.return_value = {
        "Addresses": [
            {
                "AllocationId": "eipalloc-456",
                "PublicIp": "5.6.7.8",
                "AssociationId": "eipassoc-999",
            }
        ]
    }
    assert _check_unassociated_eips(ec2) == []


def test_unassociated_eips_api_error_returns_empty():
    ec2 = MagicMock()
    ec2.describe_addresses.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": ""}}, "DescribeAddresses"
    )
    assert _check_unassociated_eips(ec2) == []


# ── run_cost_scan wiring ──────────────────────────────────────────────────────

MOD = "aws_lighthouse.tools.cost_scan"


def _make_clean_ec2():
    _pages = {
        "describe_volumes": {"Volumes": []},
        "describe_instances": {"Reservations": []},
        "describe_snapshots": {"Snapshots": []},
    }

    def _get_paginator(name):
        pag = MagicMock()
        pag.paginate.return_value = [_pages[name]]
        return pag

    ec2 = MagicMock()
    ec2.get_paginator.side_effect = _get_paginator
    ec2.describe_addresses.return_value = {"Addresses": []}
    return ec2


def test_run_cost_scan_clean_returns_empty():
    ec2 = _make_clean_ec2()
    with patch(f"{MOD}.get_aws_client", return_value=ec2):
        findings = run_cost_scan()
    assert findings == []


def test_run_cost_scan_aggregates_all_checks():
    _pages = {
        "describe_volumes": {
            "Volumes": [{"VolumeId": "vol-aaa", "Size": 10, "VolumeType": "gp2"}]
        },
        "describe_instances": {
            "Reservations": [
                {
                    "Instances": [
                        {"InstanceId": "i-bbb", "InstanceType": "t3.micro", "Tags": []}
                    ]
                }
            ]
        },
        "describe_snapshots": {
            "Snapshots": [
                {
                    "SnapshotId": "snap-ccc",
                    "StartTime": datetime.now(timezone.utc) - timedelta(days=100),
                    "VolumeSize": 20,
                    "Description": "old",
                }
            ]
        },
    }

    def _get_paginator(name):
        pag = MagicMock()
        pag.paginate.return_value = [_pages[name]]
        return pag

    ec2 = MagicMock()
    ec2.get_paginator.side_effect = _get_paginator
    ec2.describe_addresses.return_value = {
        "Addresses": [{"AllocationId": "eipalloc-ddd", "PublicIp": "1.2.3.4"}]
    }
    with patch(f"{MOD}.get_aws_client", return_value=ec2):
        findings = run_cost_scan()

    resources = [f["resource"] for f in findings]
    assert "vol-aaa" in resources
    assert "i-bbb" in resources
    assert "snap-ccc" in resources
    assert "eipalloc-ddd" in resources
