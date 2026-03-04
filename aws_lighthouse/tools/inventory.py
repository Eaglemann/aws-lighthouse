from datetime import UTC, datetime, timedelta
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from ..auth import get_client
from ..logger import logger
from ..scan_contract import error_result, ok_result, scan_error_from_exception
from ..types import ScanResult

_LAMBDA_STALE_DAYS = 180


def get_s3_inventory() -> ScanResult:
    """List S3 buckets and basic stats."""
    s3 = get_client("s3")
    buckets: list[dict[str, Any]] = []
    try:
        response = s3.list_buckets()
        for bucket in response.get("Buckets", []):
            buckets.append(
                {
                    "BucketName": bucket["Name"],
                    "CreationDate": bucket["CreationDate"].strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                }
            )
        return ok_result(buckets)
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to list S3 buckets: {str(e)}")
        return error_result(
            data=buckets,
            errors=[
                scan_error_from_exception(
                    service="s3",
                    operation="ListBuckets",
                    exc=e,
                )
            ],
        )


def get_ec2_inventory(region: str | None = None) -> ScanResult:
    """Retrieve all EC2 instances and state."""
    ec2 = get_client("ec2", region)
    instances: list[dict[str, Any]] = []
    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for res in page.get("Reservations", []):
                for inst in res.get("Instances", []):
                    # Safely extract Name tag
                    name = "Unknown"
                    for tag in inst.get("Tags", []):
                        if tag["Key"] == "Name":
                            name = tag["Value"]
                            break

                    instances.append(
                        {
                            "InstanceId": inst.get("InstanceId"),
                            "Name": name,
                            "Type": inst.get("InstanceType"),
                            "State": inst.get("State", {}).get("Name"),
                            "LaunchTime": inst.get("LaunchTime").strftime(
                                "%Y-%m-%d %H:%M:%S"
                            ),
                            "KeyName": inst.get("KeyName", "None"),
                        }
                    )
        return ok_result(instances)
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to list EC2 instances: {str(e)}")
        return error_result(
            data=instances,
            errors=[
                scan_error_from_exception(
                    service="ec2",
                    operation="DescribeInstances",
                    exc=e,
                    region=region,
                )
            ],
        )


def get_rds_inventory(region: str | None = None) -> ScanResult:
    """Retrieve all RDS instances and basic metrics."""
    rds = get_client("rds", region)
    instances: list[dict[str, Any]] = []
    try:
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                instances.append(
                    {
                        "DBInstanceIdentifier": db.get("DBInstanceIdentifier"),
                        "Engine": db.get("Engine"),
                        "Class": db.get("DBInstanceClass"),
                        "Status": db.get("DBInstanceStatus"),
                            "PubliclyAccessible": db.get("PubliclyAccessible", False),
                        }
                    )
        return ok_result(instances)
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to list RDS instances: {str(e)}")
        return error_result(
            data=instances,
            errors=[
                scan_error_from_exception(
                    service="rds",
                    operation="DescribeDBInstances",
                    exc=e,
                    region=region,
                )
            ],
        )


def get_lambda_inventory(region: str | None = None) -> ScanResult:
    """List all Lambda functions with runtime, memory, timeout, code size, and staleness flag."""
    lmb = get_client("lambda", region)
    functions: list[dict[str, Any]] = []
    cutoff = datetime.now(UTC) - timedelta(days=_LAMBDA_STALE_DAYS)
    try:
        paginator = lmb.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page.get("Functions", []):
                raw_modified = fn.get("LastModified", "")
                # Lambda returns ISO-8601 with offset, e.g. "2025-09-01T12:00:00.000+0000"
                try:
                    last_modified_dt = datetime.fromisoformat(
                        raw_modified.replace("+0000", "+00:00")
                    )
                    last_modified = last_modified_dt.strftime("%Y-%m-%d")
                    stale = last_modified_dt < cutoff
                except ValueError:
                    last_modified = raw_modified[:10]
                    stale = False

                functions.append(
                    {
                        "FunctionName": fn.get("FunctionName"),
                        "Runtime": fn.get("Runtime", "unknown"),
                        "MemorySize": fn.get("MemorySize", 128),
                        "Timeout": fn.get("Timeout", 3),
                        "CodeSizeMB": round(fn.get("CodeSize", 0) / 1_048_576, 2),
                        "LastModified": last_modified,
                        "Stale": stale,
                        }
                    )
        return ok_result(functions)
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to list Lambda functions: {str(e)}")
        return error_result(
            data=functions,
            errors=[
                scan_error_from_exception(
                    service="lambda",
                    operation="ListFunctions",
                    exc=e,
                    region=region,
                )
            ],
        )
