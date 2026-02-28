from ..auth import get_aws_client
from ..logger import logger


def apply_s3_block_public_access(bucket_name: str) -> bool:
    """Fully enable Block Public Access on an S3 bucket."""
    try:
        s3 = get_aws_client("s3")
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
    except Exception as e:
        logger.error(f"Failed to enable Block Public Access on {bucket_name}: {e}")
        return False


def delete_ebs_volume(volume_id: str) -> bool:
    """Permanently delete an EBS volume."""
    try:
        ec2 = get_aws_client("ec2")
        ec2.delete_volume(VolumeId=volume_id)
        return True
    except Exception as e:
        logger.error(f"Failed to delete EBS volume {volume_id}: {e}")
        return False


def release_eip(allocation_id: str) -> bool:
    """Release an Elastic IP (VPC AllocationId or EC2-Classic PublicIp)."""
    try:
        ec2 = get_aws_client("ec2")
        if allocation_id.startswith("eipalloc-"):
            ec2.release_address(AllocationId=allocation_id)
        else:
            ec2.release_address(PublicIp=allocation_id)
        return True
    except Exception as e:
        logger.error(f"Failed to release Elastic IP {allocation_id}: {e}")
        return False


def enable_guardduty(resource: str) -> bool:
    """Enable GuardDuty: create a new detector or re-enable an existing one."""
    try:
        gd = get_aws_client("guardduty")
        if resource == "guardduty":
            gd.create_detector(Enable=True)
        else:
            gd.update_detector(DetectorId=resource, Enable=True)
        return True
    except Exception as e:
        logger.error(f"Failed to enable GuardDuty ({resource}): {e}")
        return False


def enable_cloudtrail_logging(trail_name: str) -> bool:
    """Start logging on an existing CloudTrail trail that has logging stopped."""
    try:
        ct = get_aws_client("cloudtrail")
        ct.start_logging(Name=trail_name)
        return True
    except Exception as e:
        logger.error(f"Failed to start CloudTrail logging for {trail_name}: {e}")
        return False


def enforce_imdsv2(instance_id: str) -> bool:
    """Set HttpTokens=required on an EC2 instance to enforce IMDSv2."""
    try:
        ec2 = get_aws_client("ec2")
        ec2.modify_instance_metadata_options(
            InstanceId=instance_id,
            HttpTokens="required",
            HttpEndpoint="enabled",
        )
        return True
    except Exception as e:
        logger.error(f"Failed to enforce IMDSv2 on {instance_id}: {e}")
        return False


def apply_s3_default_encryption(bucket_name: str) -> bool:
    """Apply AES256 default server-side encryption to an S3 bucket."""
    try:
        s3 = get_aws_client("s3")
        s3.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                ]
            },
        )
        return True
    except Exception as e:
        logger.error(f"Failed to apply default encryption to {bucket_name}: {e}")
        return False
