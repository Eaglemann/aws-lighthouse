from typing import Any, Dict, List

from botocore.exceptions import ClientError

from ..auth import get_aws_client, get_aws_client_for_region
from ..logger import logger

# Default tags every resource should carry
DEFAULT_REQUIRED_TAGS = ["Environment", "Owner"]


def check_tagging_compliance(
    required_tags: List[str] | None = None,
    region: str | None = None,
    include_s3: bool = True,
) -> List[Dict[str, Any]]:
    """
    Check EC2 instances, RDS databases, and S3 buckets for missing required tags.
    Returns one finding per resource that is missing at least one required tag.

    include_s3 can be set to False when looping over multiple regions to avoid
    duplicate S3 findings (S3 is a global service).
    """
    if required_tags is None:
        required_tags = DEFAULT_REQUIRED_TAGS

    _cl = (lambda svc: get_aws_client_for_region(svc, region)) if region else get_aws_client
    findings: List[Dict[str, Any]] = []

    # ── EC2 ──────────────────────────────────────────────────────────────────
    try:
        ec2 = _cl("ec2")
        for reservation in ec2.describe_instances().get("Reservations", []):
            for inst in reservation.get("Instances", []):
                # Skip terminated instances — they can't be tagged anyway
                if inst.get("State", {}).get("Name") == "terminated":
                    continue
                existing = {t["Key"] for t in inst.get("Tags", [])}
                missing = [tag for tag in required_tags if tag not in existing]
                if missing:
                    name = next(
                        (t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"),
                        inst["InstanceId"],
                    )
                    findings.append({
                        "resource_type": "EC2",
                        "resource_id":   inst["InstanceId"],
                        "resource_name": name,
                        "missing_tags":  missing,
                    })
    except Exception as e:
        logger.error(f"Failed to check EC2 tags: {e}")

    # ── RDS ──────────────────────────────────────────────────────────────────
    try:
        rds = _cl("rds")
        for db in rds.describe_db_instances().get("DBInstances", []):
            existing = {t["Key"] for t in db.get("TagList", [])}
            missing = [tag for tag in required_tags if tag not in existing]
            if missing:
                findings.append({
                    "resource_type": "RDS",
                    "resource_id":   db["DBInstanceIdentifier"],
                    "resource_name": db["DBInstanceIdentifier"],
                    "missing_tags":  missing,
                })
    except Exception as e:
        logger.error(f"Failed to check RDS tags: {e}")

    # ── S3 (global service — skip when iterating per-region to avoid duplicates) ──
    if not include_s3:
        return findings
    try:
        s3 = get_aws_client("s3")
        for bucket in s3.list_buckets().get("Buckets", []):
            name = bucket["Name"]
            try:
                tag_set = s3.get_bucket_tagging(Bucket=name).get("TagSet", [])
                existing = {t["Key"] for t in tag_set}
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchTagSet":
                    existing = set()
                else:
                    continue  # permission or other transient error — skip bucket
            missing = [tag for tag in required_tags if tag not in existing]
            if missing:
                findings.append({
                    "resource_type": "S3",
                    "resource_id":   name,
                    "resource_name": name,
                    "missing_tags":  missing,
                })
    except Exception as e:
        logger.error(f"Failed to check S3 tags: {e}")

    return findings
