from typing import Any, Dict, List, Set, Tuple

from ..auth import get_aws_client
from ..logger import logger

# (namespace, metric_name, dimension_name) tuples required per resource type.
# A resource is flagged only for the metrics it is actually missing.
_EC2_REQUIRED: List[Tuple[str, str, str]] = [
    ("AWS/EC2", "CPUUtilization",  "InstanceId"),
    ("AWS/EC2", "StatusCheckFailed", "InstanceId"),
]

_RDS_REQUIRED: List[Tuple[str, str, str]] = [
    ("AWS/RDS", "CPUUtilization",  "DBInstanceIdentifier"),
    ("AWS/RDS", "FreeStorageSpace", "DBInstanceIdentifier"),
]


def _build_alarm_index(cw) -> Set[Tuple[str, str, str, str]]:
    """
    Return a set of (namespace, metric_name, dimension_name, dimension_value)
    tuples representing every metric currently covered by at least one alarm.
    """
    index: Set[Tuple[str, str, str, str]] = set()
    try:
        paginator = cw.get_paginator("describe_alarms")
        for page in paginator.paginate(AlarmTypes=["MetricAlarm"]):
            for alarm in page.get("MetricAlarms", []):
                ns     = alarm.get("Namespace", "")
                metric = alarm.get("MetricName", "")
                for dim in alarm.get("Dimensions", []):
                    index.add((ns, metric, dim["Name"], dim["Value"]))
    except Exception as e:
        logger.error(f"Failed to fetch CloudWatch alarms: {e}")
    return index


def detect_cloudwatch_gaps() -> List[Dict[str, Any]]:
    """
    Find EC2 instances and RDS databases that have no CloudWatch alarm
    configured for one or more key metrics:

      EC2  — CPUUtilization, StatusCheckFailed
      RDS  — CPUUtilization, FreeStorageSpace

    Terminated EC2 instances are skipped.
    Returns one finding per resource, listing every missing metric.
    """
    cw  = get_aws_client("cloudwatch")
    ec2 = get_aws_client("ec2")
    rds = get_aws_client("rds")

    alarm_index = _build_alarm_index(cw)
    findings: List[Dict[str, Any]] = []

    # ── EC2 ──────────────────────────────────────────────────────────────────
    try:
        for reservation in ec2.describe_instances().get("Reservations", []):
            for inst in reservation.get("Instances", []):
                if inst.get("State", {}).get("Name") == "terminated":
                    continue
                instance_id = inst["InstanceId"]
                name = next(
                    (t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"),
                    instance_id,
                )
                missing = [
                    metric
                    for ns, metric, dim in _EC2_REQUIRED
                    if (ns, metric, dim, instance_id) not in alarm_index
                ]
                if missing:
                    findings.append({
                        "resource_type":  "EC2",
                        "resource_id":    instance_id,
                        "resource_name":  name,
                        "missing_alarms": missing,
                    })
    except Exception as e:
        logger.error(f"Failed to check EC2 alarm gaps: {e}")

    # ── RDS ──────────────────────────────────────────────────────────────────
    try:
        for db in rds.describe_db_instances().get("DBInstances", []):
            db_id = db["DBInstanceIdentifier"]
            missing = [
                metric
                for ns, metric, dim in _RDS_REQUIRED
                if (ns, metric, dim, db_id) not in alarm_index
            ]
            if missing:
                findings.append({
                    "resource_type":  "RDS",
                    "resource_id":    db_id,
                    "resource_name":  db_id,
                    "missing_alarms": missing,
                })
    except Exception as e:
        logger.error(f"Failed to check RDS alarm gaps: {e}")

    return findings
