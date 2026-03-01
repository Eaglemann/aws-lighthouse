from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any
from botocore.exceptions import BotoCoreError, ClientError

from ..auth import get_aws_client, get_aws_client_for_region
from ..logger import logger


def _client(service: str, region: str | None):
    return (
        get_aws_client_for_region(service, region)
        if region
        else get_aws_client(service)
    )


_LAMBDA_STALE_DAYS = 180


def get_s3_inventory() -> List[Dict[str, Any]]:
    """List S3 buckets and basic stats."""
    s3 = get_aws_client("s3")
    try:
        response = s3.list_buckets()
        buckets = []
        for bucket in response.get("Buckets", []):
            buckets.append(
                {
                    "BucketName": bucket["Name"],
                    "CreationDate": bucket["CreationDate"].strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                }
            )
        return buckets
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to list S3 buckets: {str(e)}")
        return [{"error": str(e)}]


def get_ec2_inventory(region: str | None = None) -> List[Dict[str, Any]]:
    """Retrieve all EC2 instances and state."""
    ec2 = _client("ec2", region)
    instances = []
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
        return instances
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to list EC2 instances: {str(e)}")
        return [{"error": str(e)}]


def get_rds_inventory(region: str | None = None) -> List[Dict[str, Any]]:
    """Retrieve all RDS instances and basic metrics."""
    rds = _client("rds", region)
    instances = []
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
        return instances
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to list RDS instances: {str(e)}")
        return [{"error": str(e)}]


def get_lambda_inventory(region: str | None = None) -> List[Dict[str, Any]]:
    """List all Lambda functions with runtime, memory, timeout, code size, and staleness flag."""
    lmb = _client("lambda", region)
    functions = []
    cutoff = datetime.now(timezone.utc) - timedelta(days=_LAMBDA_STALE_DAYS)
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
        return functions
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to list Lambda functions: {str(e)}")
        return [{"error": str(e)}]
