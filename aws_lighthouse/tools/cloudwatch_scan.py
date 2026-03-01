from ..auth import get_client
from ..logger import logger
from ..types import CloudWatchFinding

# (namespace, metric_name, dimension_name) tuples required per resource type.
# A resource is flagged only for the metrics it is actually missing.
_EC2_REQUIRED: list[tuple[str, str, str]] = [
    ("AWS/EC2", "CPUUtilization", "InstanceId"),
    ("AWS/EC2", "StatusCheckFailed", "InstanceId"),
]

_RDS_REQUIRED: list[tuple[str, str, str]] = [
    ("AWS/RDS", "CPUUtilization", "DBInstanceIdentifier"),
    ("AWS/RDS", "FreeStorageSpace", "DBInstanceIdentifier"),
]

_LAMBDA_REQUIRED: list[tuple[str, str, str]] = [
    ("AWS/Lambda", "Errors", "FunctionName"),
    ("AWS/Lambda", "Throttles", "FunctionName"),
]


def _build_alarm_index(cw) -> set[tuple[str, str, str, str]]:
    """
    Return a set of (namespace, metric_name, dimension_name, dimension_value)
    tuples representing every metric currently covered by at least one alarm.
    """
    index: set[tuple[str, str, str, str]] = set()
    try:
        paginator = cw.get_paginator("describe_alarms")
        for page in paginator.paginate(AlarmTypes=["MetricAlarm"]):
            for alarm in page.get("MetricAlarms", []):
                ns = alarm.get("Namespace", "")
                metric = alarm.get("MetricName", "")
                for dim in alarm.get("Dimensions", []):
                    index.add((ns, metric, dim["Name"], dim["Value"]))
    except Exception as e:
        logger.error(f"Failed to fetch CloudWatch alarms: {e}")
    return index


def detect_cloudwatch_gaps(region: str | None = None) -> list[CloudWatchFinding]:
    """
    Find EC2 instances, RDS databases, and Lambda functions that have no
    CloudWatch alarm configured for one or more key metrics:

      EC2     — CPUUtilization, StatusCheckFailed
      RDS     — CPUUtilization, FreeStorageSpace
      Lambda  — Errors, Throttles

    Terminated EC2 instances are skipped.
    Returns one finding per resource, listing every missing metric.
    """

    def _cl(svc):
        return get_client(svc, region)

    cw = _cl("cloudwatch")
    ec2 = _cl("ec2")
    rds = _cl("rds")

    alarm_index = _build_alarm_index(cw)
    findings: list[CloudWatchFinding] = []

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
                    findings.append(
                        {
                            "resource_type": "EC2",
                            "resource_id": instance_id,
                            "resource_name": name,
                            "missing_alarms": missing,
                        }
                    )
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
                findings.append(
                    {
                        "resource_type": "RDS",
                        "resource_id": db_id,
                        "resource_name": db_id,
                        "missing_alarms": missing,
                    }
                )
    except Exception as e:
        logger.error(f"Failed to check RDS alarm gaps: {e}")

    # ── Lambda ────────────────────────────────────────────────────────────────
    try:
        lmb = _cl("lambda")
        paginator = lmb.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page.get("Functions", []):
                fn_name = fn["FunctionName"]
                missing = [
                    metric
                    for ns, metric, dim in _LAMBDA_REQUIRED
                    if (ns, metric, dim, fn_name) not in alarm_index
                ]
                if missing:
                    findings.append(
                        {
                            "resource_type": "Lambda",
                            "resource_id": fn_name,
                            "resource_name": fn_name,
                            "missing_alarms": missing,
                        }
                    )
    except Exception as e:
        logger.error(f"Failed to check Lambda alarm gaps: {e}")

    return findings
