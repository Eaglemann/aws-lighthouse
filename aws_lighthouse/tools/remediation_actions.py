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
