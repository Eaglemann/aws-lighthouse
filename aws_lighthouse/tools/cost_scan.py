from datetime import UTC, datetime, timedelta

from botocore.exceptions import BotoCoreError, ClientError

from ..auth import get_client
from ..logger import logger
from ..types import CostFinding

_SNAPSHOT_AGE_DAYS = 90


def _check_unattached_ebs(ec2) -> list[CostFinding]:
    """Flag EBS volumes that are not attached to any instance."""
    findings: list[CostFinding] = []
    try:
        paginator = ec2.get_paginator("describe_volumes")
        for page in paginator.paginate(
            Filters=[{"Name": "status", "Values": ["available"]}]
        ):
            for vol in page.get("Volumes", []):
                size = vol.get("Size", 0)
                vol_type = vol.get("VolumeType", "unknown")
                findings.append(
                    {
                        "resource": vol["VolumeId"],
                        "finding": f"Unattached EBS volume ({size} GB {vol_type}) — paying for storage with no instance",
                        "remediation_type": "delete_ebs_volume",
                        "remediation_label": "Delete EBS Volume",
                    }
                )
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to check unattached EBS volumes: {e}")
    return findings


def _check_stopped_ec2(ec2) -> list[CostFinding]:
    """Flag EC2 instances that are stopped but still incurring EBS costs."""
    findings: list[CostFinding] = []
    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}]
        ):
            for reservation in page.get("Reservations", []):
                for inst in reservation.get("Instances", []):
                    name = next(
                        (
                            t["Value"]
                            for t in inst.get("Tags", [])
                            if t["Key"] == "Name"
                        ),
                        inst["InstanceId"],
                    )
                    findings.append(
                        {
                            "resource": inst["InstanceId"],
                            "finding": f"Stopped EC2 instance '{name}' ({inst.get('InstanceType')}) — EBS volumes still billed",
                        }
                    )
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to check stopped EC2 instances: {e}")
    return findings


def _check_old_snapshots(ec2) -> list[CostFinding]:
    """Flag owned EBS snapshots older than 90 days."""
    findings: list[CostFinding] = []
    try:
        paginator = ec2.get_paginator("describe_snapshots")
        cutoff = datetime.now(UTC) - timedelta(days=_SNAPSHOT_AGE_DAYS)
        for page in paginator.paginate(OwnerIds=["self"]):
            for snap in page.get("Snapshots", []):
                start_time = snap.get("StartTime")
                if start_time and start_time < cutoff:
                    age = (datetime.now(UTC) - start_time).days
                    size = snap.get("VolumeSize", 0)
                    description = snap.get("Description", "")
                    findings.append(
                        {
                            "resource": snap["SnapshotId"],
                            "finding": f"EBS snapshot is {age} days old ({size} GB) — '{description}'",
                        }
                    )
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to check old EBS snapshots: {e}")
    return findings


def _check_unassociated_eips(ec2) -> list[CostFinding]:
    """Flag Elastic IPs that are allocated but not associated with any resource."""
    findings: list[CostFinding] = []
    try:
        response = ec2.describe_addresses()
        for addr in response.get("Addresses", []):
            if "AssociationId" not in addr:
                findings.append(
                    {
                        "resource": addr.get("AllocationId", addr.get("PublicIp")),
                        "finding": f"Elastic IP {addr['PublicIp']} is allocated but not associated — ~$0.005/hr wasted",
                        "remediation_type": "release_eip",
                        "remediation_label": "Release Elastic IP",
                    }
                )
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to check unassociated Elastic IPs: {e}")
    return findings


def run_cost_scan(region: str | None = None) -> list[CostFinding]:
    """Run all cost waste checks and return a unified list of findings."""
    ec2 = get_client("ec2", region)
    findings: list[CostFinding] = []
    findings.extend(_check_unattached_ebs(ec2))
    findings.extend(_check_stopped_ec2(ec2))
    findings.extend(_check_old_snapshots(ec2))
    findings.extend(_check_unassociated_eips(ec2))
    return findings
