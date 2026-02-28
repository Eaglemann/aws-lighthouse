from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List

from ..auth import get_aws_client
from ..logger import logger

_SNAPSHOT_AGE_DAYS = 90


def _check_unattached_ebs() -> List[Dict[str, Any]]:
    """Flag EBS volumes that are not attached to any instance."""
    findings = []
    try:
        ec2 = get_aws_client("ec2")
        response = ec2.describe_volumes(
            Filters=[{"Name": "status", "Values": ["available"]}]
        )
        for vol in response.get("Volumes", []):
            size = vol.get("Size", 0)
            vol_type = vol.get("VolumeType", "unknown")
            findings.append({
                "resource": vol["VolumeId"],
                "finding": f"Unattached EBS volume ({size} GB {vol_type}) — paying for storage with no instance",
                "remediation_type": "delete_ebs_volume",
                "remediation_label": "Delete EBS Volume",
            })
    except Exception as e:
        logger.error(f"Failed to check unattached EBS volumes: {e}")
    return findings


def _check_stopped_ec2() -> List[Dict[str, Any]]:
    """Flag EC2 instances that are stopped but still incurring EBS costs."""
    findings = []
    try:
        ec2 = get_aws_client("ec2")
        response = ec2.describe_instances(
            Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}]
        )
        for reservation in response.get("Reservations", []):
            for inst in reservation.get("Instances", []):
                name = next(
                    (t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"),
                    inst["InstanceId"],
                )
                findings.append({
                    "resource": inst["InstanceId"],
                    "finding": f"Stopped EC2 instance '{name}' ({inst.get('InstanceType')}) — EBS volumes still billed",
                })
    except Exception as e:
        logger.error(f"Failed to check stopped EC2 instances: {e}")
    return findings


def _check_old_snapshots() -> List[Dict[str, Any]]:
    """Flag owned EBS snapshots older than 90 days."""
    findings = []
    try:
        ec2 = get_aws_client("ec2")
        response = ec2.describe_snapshots(OwnerIds=["self"])
        cutoff = datetime.now(timezone.utc) - timedelta(days=_SNAPSHOT_AGE_DAYS)
        for snap in response.get("Snapshots", []):
            start_time = snap.get("StartTime")
            if start_time and start_time < cutoff:
                age = (datetime.now(timezone.utc) - start_time).days
                size = snap.get("VolumeSize", 0)
                description = snap.get("Description", "")
                findings.append({
                    "resource": snap["SnapshotId"],
                    "finding": f"EBS snapshot is {age} days old ({size} GB) — '{description}'",
                })
    except Exception as e:
        logger.error(f"Failed to check old EBS snapshots: {e}")
    return findings


def _check_unassociated_eips() -> List[Dict[str, Any]]:
    """Flag Elastic IPs that are allocated but not associated with any resource."""
    findings = []
    try:
        ec2 = get_aws_client("ec2")
        response = ec2.describe_addresses()
        for addr in response.get("Addresses", []):
            if "AssociationId" not in addr:
                findings.append({
                    "resource": addr.get("AllocationId", addr.get("PublicIp")),
                    "finding": f"Elastic IP {addr['PublicIp']} is allocated but not associated — ~$0.005/hr wasted",
                    "remediation_type": "release_eip",
                    "remediation_label": "Release Elastic IP",
                })
    except Exception as e:
        logger.error(f"Failed to check unassociated Elastic IPs: {e}")
    return findings


def run_cost_scan() -> List[Dict[str, Any]]:
    """Run all cost waste checks and return a unified list of findings."""
    findings = []
    findings.extend(_check_unattached_ebs())
    findings.extend(_check_stopped_ec2())
    findings.extend(_check_old_snapshots())
    findings.extend(_check_unassociated_eips())
    return findings
