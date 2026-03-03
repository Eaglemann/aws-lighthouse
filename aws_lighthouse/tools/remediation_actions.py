from botocore.exceptions import BotoCoreError, ClientError

from ..auth import get_client
from ..logger import logger


def apply_s3_block_public_access(bucket_name: str, region: str | None = None) -> bool:
    """Enable all four Block Public Access flags on an S3 bucket.

    Sets BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and
    RestrictPublicBuckets to True in a single PutPublicAccessBlock call.

    Reversibility: reversible — flags can be individually disabled later via
    the AWS console or CLI. Does not modify the bucket's existing objects or ACLs.

    Region: S3 is a global service; the bucket name is sufficient. The ``region``
    parameter controls which regional endpoint the client connects to, not which
    bucket is targeted. Pass the bucket's home region for lowest latency; when
    ``None``, the session's default region is used.

    Returns True on success, False if the API call fails (error is logged).
    """
    try:
        s3 = get_client("s3", region)
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        return True
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to enable Block Public Access on {bucket_name}: {e}")
        return False


def delete_ebs_volume(volume_id: str, region: str | None = None) -> bool:
    """Permanently delete an unattached EBS volume.

    **IRREVERSIBLE** — once deleted, the volume and all data stored on it are
    gone. AWS does not provide a restore path for deleted volumes. Snapshots
    created from the volume are unaffected and remain available.

    The volume must be in the ``available`` state (not attached to any instance).
    Attempting to delete an ``in-use`` volume raises a ClientError and returns False.

    Region: EBS volumes are regional resources. Pass the region that contains the
    volume, or ``None`` to use the session's default region.

    Returns True on success, False if the API call fails (error is logged).
    """
    try:
        ec2 = get_client("ec2", region)
        ec2.delete_volume(VolumeId=volume_id)
        return True
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to delete EBS volume {volume_id}: {e}")
        return False


def release_eip(allocation_id: str, region: str | None = None) -> bool:
    """Release an Elastic IP address back to the AWS pool.

    **IRREVERSIBLE** — the specific IP address is returned to AWS and you are no
    longer guaranteed to recover the same address. If the address was associated
    with a running instance or network interface the association is automatically
    removed first.

    Accepts either a VPC Allocation ID (``eipalloc-…``) or an EC2-Classic Public IP
    address string. The correct release method is chosen automatically.

    Region: EIPs are regional resources. Pass the region that owns the address, or
    ``None`` to use the session's default region.

    Returns True on success, False if the API call fails (error is logged).
    """
    try:
        ec2 = get_client("ec2", region)
        if allocation_id.startswith("eipalloc-"):
            ec2.release_address(AllocationId=allocation_id)
        else:
            ec2.release_address(PublicIp=allocation_id)
        return True
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to release Elastic IP {allocation_id}: {e}")
        return False


def enable_guardduty(resource: str, region: str | None = None) -> bool:
    """Enable GuardDuty threat detection in a region.

    If ``resource`` is the literal string ``"guardduty"``, a brand-new detector is
    created (CreateDetector). Otherwise ``resource`` is treated as an existing
    detector ID and re-enabled with UpdateDetector.

    Reversibility: reversible — GuardDuty can be paused (UpdateDetector with
    Enable=False) or fully disabled/deleted later. Enabling incurs per-event costs.

    Region: GuardDuty is a regional service. Each region has its own detector.
    Pass the target region explicitly, or ``None`` to act in the session's default
    region. To enable GuardDuty in all regions, call this function once per region.

    Returns True on success, False if the API call fails (error is logged).
    """
    try:
        gd = get_client("guardduty", region)
        if resource == "guardduty":
            gd.create_detector(Enable=True)
        else:
            gd.update_detector(DetectorId=resource, Enable=True)
        return True
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to enable GuardDuty ({resource}): {e}")
        return False


def enable_cloudtrail_logging(trail_name: str, region: str | None = None) -> bool:
    """Resume logging on a CloudTrail trail that has logging stopped.

    Calls StartLogging on the named trail. The trail must already exist — this
    function does not create trails. If the trail is already logging, the call is a
    no-op (AWS returns success).

    Reversibility: reversible — logging can be stopped again with StopLogging at
    any time. Enabling logging incurs S3 storage and optional CloudWatch Logs costs.

    Region: CloudTrail trails are regional (unless they are organisation or
    multi-region trails). Pass the region that owns the trail, or ``None`` for the
    session's default region. For multi-region trails, any home-region client
    suffices; ``trail_name`` can be either the short name or the full ARN.

    Returns True on success, False if the API call fails (error is logged).
    """
    try:
        ct = get_client("cloudtrail", region)
        ct.start_logging(Name=trail_name)
        return True
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to start CloudTrail logging for {trail_name}: {e}")
        return False


def enforce_imdsv2(instance_id: str, region: str | None = None) -> bool:
    """Require IMDSv2 (token-based) metadata access on an EC2 instance.

    Sets HttpTokens=required and HttpEndpoint=enabled via
    ModifyInstanceMetadataOptions. After this call, requests to the instance
    metadata service (169.254.169.254) without a session token are rejected.
    Applications that rely on IMDSv1 (direct unauthenticated requests) will break.

    Reversibility: reversible — HttpTokens can be set back to ``optional`` via
    the same API or the console. The instance does not need to be stopped; the
    change takes effect immediately on the running instance.

    Region: EC2 instances are regional resources. Pass the region that contains
    the instance, or ``None`` to use the session's default region.

    Returns True on success, False if the API call fails (error is logged).
    """
    try:
        ec2 = get_client("ec2", region)
        ec2.modify_instance_metadata_options(
            InstanceId=instance_id,
            HttpTokens="required",
            HttpEndpoint="enabled",
        )
        return True
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to enforce IMDSv2 on {instance_id}: {e}")
        return False


def apply_s3_default_encryption(bucket_name: str, region: str | None = None) -> bool:
    """Set AES-256 (SSE-S3) as the default server-side encryption for an S3 bucket.

    Calls PutBucketEncryption with SSEAlgorithm=AES256. New objects uploaded
    without an explicit encryption header will be encrypted automatically.
    Existing objects are NOT retroactively re-encrypted; use an S3 Batch Operations
    job to re-encrypt existing content.

    Reversibility: reversible — the encryption configuration can be changed to a
    different algorithm (e.g., aws:kms) or removed via DeleteBucketEncryption.

    Region: S3 is a global service; the bucket name is sufficient. The ``region``
    parameter controls which regional endpoint the client connects to. Pass the
    bucket's home region for lowest latency; when ``None``, the session's default
    region is used.

    Returns True on success, False if the API call fails (error is logged).
    """
    try:
        s3 = get_client("s3", region)
        s3.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                ]
            },
        )
        return True
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to apply default encryption to {bucket_name}: {e}")
        return False
