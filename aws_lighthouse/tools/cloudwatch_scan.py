from botocore.exceptions import BotoCoreError, ClientError

from ..auth import get_client
from ..logger import logger
from ..scan_contract import error_result, ok_result, scan_error_from_exception
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
    ("AWS/RDS", "DatabaseConnections", "DBInstanceIdentifier"),
    ("AWS/RDS", "ReadLatency", "DBInstanceIdentifier"),
    ("AWS/RDS", "WriteLatency", "DBInstanceIdentifier"),
    ("AWS/RDS", "ReplicaLag", "DBInstanceIdentifier"),
]

_ELASTICACHE_REQUIRED: list[tuple[str, str, str]] = [
    ("AWS/ElastiCache", "CPUUtilization", "CacheClusterId"),
    ("AWS/ElastiCache", "CurrConnections", "CacheClusterId"),
    ("AWS/ElastiCache", "Evictions", "CacheClusterId"),
    ("AWS/ElastiCache", "FreeableMemory", "CacheClusterId"),
]

_REDSHIFT_REQUIRED: list[tuple[str, str, str]] = [
    ("AWS/Redshift", "CPUUtilization", "ClusterIdentifier"),
    ("AWS/Redshift", "PercentageDiskSpaceUsed", "ClusterIdentifier"),
    ("AWS/Redshift", "DatabaseConnections", "ClusterIdentifier"),
]

_LAMBDA_REQUIRED: list[tuple[str, str, str]] = [
    ("AWS/Lambda", "Errors", "FunctionName"),
    ("AWS/Lambda", "Throttles", "FunctionName"),
]


def _build_alarm_index(cw, region: str | None = None):
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
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to fetch CloudWatch alarms: {e}")
        return error_result(
            data=index,
            errors=[
                scan_error_from_exception(
                    service="cloudwatch",
                    operation="DescribeAlarms",
                    exc=e,
                    region=region,
                )
            ],
        )
    return ok_result(index)


def detect_cloudwatch_gaps(region: str | None = None):
    """
    Find resources that have no CloudWatch alarm for one or more key metrics:

      EC2         — CPUUtilization, StatusCheckFailed
      RDS         — CPUUtilization, FreeStorageSpace, DatabaseConnections,
                    ReadLatency, WriteLatency, ReplicaLag
      ElastiCache — CPUUtilization, CurrConnections, Evictions, FreeableMemory
      Redshift    — CPUUtilization, PercentageDiskSpaceUsed, DatabaseConnections
      Lambda      — Errors, Throttles

    Terminated EC2 instances are skipped.
    Returns one finding per resource, listing every missing metric.
    """

    def _cl(svc):
        return get_client(svc, region)

    cw = _cl("cloudwatch")
    ec2 = _cl("ec2")
    rds = _cl("rds")

    alarm_index_result = _build_alarm_index(cw, region)
    alarm_index = alarm_index_result["data"]
    findings: list[CloudWatchFinding] = []
    errors = list(alarm_index_result["errors"])

    # ── EC2 ──────────────────────────────────────────────────────────────────
    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for inst in reservation.get("Instances", []):
                    if inst.get("State", {}).get("Name") == "terminated":
                        continue
                    instance_id = inst["InstanceId"]
                    name = next(
                        (
                            t["Value"]
                            for t in inst.get("Tags", [])
                            if t["Key"] == "Name"
                        ),
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
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to check EC2 alarm gaps: {e}")
        errors.append(
            scan_error_from_exception(
                service="ec2",
                operation="DescribeInstances",
                exc=e,
                region=region,
            )
        )

    # ── RDS ──────────────────────────────────────────────────────────────────
    try:
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
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
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to check RDS alarm gaps: {e}")
        errors.append(
            scan_error_from_exception(
                service="rds",
                operation="DescribeDBInstances",
                exc=e,
                region=region,
            )
        )

    # ── ElastiCache ───────────────────────────────────────────────────────────
    try:
        elc = _cl("elasticache")
        paginator = elc.get_paginator("describe_cache_clusters")
        for page in paginator.paginate():
            for cluster in page.get("CacheClusters", []):
                cluster_id = cluster["CacheClusterId"]
                missing = [
                    metric
                    for ns, metric, dim in _ELASTICACHE_REQUIRED
                    if (ns, metric, dim, cluster_id) not in alarm_index
                ]
                if missing:
                    findings.append(
                        {
                            "resource_type": "ElastiCache",
                            "resource_id": cluster_id,
                            "resource_name": cluster_id,
                            "missing_alarms": missing,
                        }
                    )
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to check ElastiCache alarm gaps: {e}")
        errors.append(
            scan_error_from_exception(
                service="elasticache",
                operation="DescribeCacheClusters",
                exc=e,
                region=region,
            )
        )

    # ── Redshift ──────────────────────────────────────────────────────────────
    try:
        rs = _cl("redshift")
        paginator = rs.get_paginator("describe_clusters")
        for page in paginator.paginate():
            for cluster in page.get("Clusters", []):
                cluster_id = cluster["ClusterIdentifier"]
                missing = [
                    metric
                    for ns, metric, dim in _REDSHIFT_REQUIRED
                    if (ns, metric, dim, cluster_id) not in alarm_index
                ]
                if missing:
                    findings.append(
                        {
                            "resource_type": "Redshift",
                            "resource_id": cluster_id,
                            "resource_name": cluster_id,
                            "missing_alarms": missing,
                        }
                    )
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to check Redshift alarm gaps: {e}")
        errors.append(
            scan_error_from_exception(
                service="redshift",
                operation="DescribeClusters",
                exc=e,
                region=region,
            )
        )

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
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to check Lambda alarm gaps: {e}")
        errors.append(
            scan_error_from_exception(
                service="lambda",
                operation="ListFunctions",
                exc=e,
                region=region,
            )
        )

    return error_result(data=findings, errors=errors)
