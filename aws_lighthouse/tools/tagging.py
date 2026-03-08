from botocore.exceptions import BotoCoreError, ClientError

from ..auth import get_client
from ..logger import logger
from ..scan_contract import error_result, scan_error_from_exception
from ..types import ScanError, ScanResult, TagFinding

# Default tags every resource should carry
DEFAULT_REQUIRED_TAGS = ["Environment", "Owner"]


def check_tagging_compliance(
    required_tags: list[str] | None = None,
    region: str | None = None,
    include_s3: bool = True,
) -> ScanResult:
    """
    Check EC2 instances, RDS databases, Lambda functions, and S3 buckets for
    missing required tags. Returns one finding per resource that is missing at
    least one required tag.

    include_s3 can be set to False when looping over multiple regions to avoid
    duplicate S3 findings (S3 is a global service).
    """
    if required_tags is None:
        required_tags = DEFAULT_REQUIRED_TAGS

    def _cl(svc: str):  # type: ignore[no-untyped-def]
        return get_client(svc, region)

    findings: list[TagFinding] = []
    errors: list[ScanError] = []

    # ── EC2 ──────────────────────────────────────────────────────────────────
    try:
        ec2 = _cl("ec2")
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for inst in reservation.get("Instances", []):
                    # Skip terminated instances — they can't be tagged anyway
                    if inst.get("State", {}).get("Name") == "terminated":
                        continue
                    existing = {t["Key"] for t in inst.get("Tags", [])}
                    missing = [tag for tag in required_tags if tag not in existing]
                    if missing:
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
                                "resource_type": "EC2",
                                "resource_id": inst["InstanceId"],
                                "resource_name": name,
                                "missing_tags": missing,
                            }
                        )
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to check EC2 tags: {e}")
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
        rds = _cl("rds")
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                existing = {t["Key"] for t in db.get("TagList", [])}
                missing = [tag for tag in required_tags if tag not in existing]
                if missing:
                    findings.append(
                        {
                            "resource_type": "RDS",
                            "resource_id": db["DBInstanceIdentifier"],
                            "resource_name": db["DBInstanceIdentifier"],
                            "missing_tags": missing,
                        }
                    )
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to check RDS tags: {e}")
        errors.append(
            scan_error_from_exception(
                service="rds",
                operation="DescribeDBInstances",
                exc=e,
                region=region,
            )
        )

    # ── Lambda ────────────────────────────────────────────────────────────────
    try:
        # Bulk-fetch all Lambda tags in one paginated call (O(1) calls vs N)
        tags_by_arn: dict[str, set[str]] = {}
        bulk_lambda_tag_fetch_failed = False
        try:
            tagging_client = _cl("resourcegroupstaggingapi")
            tag_paginator = tagging_client.get_paginator("get_resources")
            for page in tag_paginator.paginate(ResourceTypeFilters=["lambda:function"]):
                for resource in page.get("ResourceTagMappingList", []):
                    tags_by_arn[resource["ResourceARN"]] = {
                        t["Key"] for t in resource.get("Tags", [])
                    }
        except (ClientError, BotoCoreError) as e:
            logger.error(
                f"Bulk Lambda tag fetch failed, falling back to per-function tag lookup: {e}"
            )
            bulk_lambda_tag_fetch_failed = True
            errors.append(
                scan_error_from_exception(
                    service="resourcegroupstaggingapi",
                    operation="GetResources",
                    exc=e,
                    region=region,
                )
            )

        lmb = _cl("lambda")
        paginator = lmb.get_paginator("list_functions")
        skipped_lambdas: list[str] = []
        for page in paginator.paginate():
            for fn in page.get("Functions", []):
                name = fn["FunctionName"]
                if bulk_lambda_tag_fetch_failed:
                    try:
                        tag_map = lmb.list_tags(Resource=fn["FunctionArn"]).get(
                            "Tags", {}
                        )
                    except (ClientError, BotoCoreError) as e:
                        logger.error(f"Failed to look up Lambda tags for {name}: {e}")
                        errors.append(
                            scan_error_from_exception(
                                service="lambda",
                                operation="ListTags",
                                exc=e,
                                region=region,
                            )
                        )
                        skipped_lambdas.append(name)
                        continue
                    existing = set(tag_map.keys())
                else:
                    existing = tags_by_arn.get(fn["FunctionArn"], set())
                missing = [tag for tag in required_tags if tag not in existing]
                if missing:
                    findings.append(
                        {
                            "resource_type": "Lambda",
                            "resource_id": name,
                            "resource_name": name,
                            "missing_tags": missing,
                        }
                    )
        if skipped_lambdas:
            logger.warn(
                f"Skipped {len(skipped_lambdas)} Lambda function(s) due to tag lookup failure: "
                + ", ".join(skipped_lambdas)
            )
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to check Lambda tags: {e}")
        errors.append(
            scan_error_from_exception(
                service="lambda",
                operation="ListFunctions",
                exc=e,
                region=region,
            )
        )

    # ── S3 (global service — skip when iterating per-region to avoid duplicates) ──
    if not include_s3:
        return error_result(data=findings, errors=errors)
    try:
        s3 = get_client("s3")
        for bucket in s3.list_buckets().get("Buckets", []):
            name = bucket["Name"]
            try:
                tag_set = s3.get_bucket_tagging(Bucket=name).get("TagSet", [])
                existing = {t["Key"] for t in tag_set}
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchTagSet":
                    existing = set()
                else:
                    errors.append(
                        scan_error_from_exception(
                            service="s3",
                            operation="GetBucketTagging",
                            exc=e,
                        )
                    )
                    continue  # permission or other transient error — skip bucket
            missing = [tag for tag in required_tags if tag not in existing]
            if missing:
                findings.append(
                    {
                        "resource_type": "S3",
                        "resource_id": name,
                        "resource_name": name,
                        "missing_tags": missing,
                    }
                )
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to check S3 tags: {e}")
        errors.append(
            scan_error_from_exception(
                service="s3",
                operation="ListBuckets",
                exc=e,
            )
        )

    return error_result(data=findings, errors=errors)
