from langchain_core.tools import tool
from pydantic import BaseModel, Field

from ..auth import get_client
from ..logger import logger


class S3BlockPublicAccessInput(BaseModel):
    bucket_name: str = Field(
        description="The name of the S3 bucket to configure Block Public Access on."
    )


@tool("s3_block_public_access")
def s3_block_public_access(args: S3BlockPublicAccessInput) -> str:
    """Applies the strictest S3 Block Public Access configuration to a bucket."""
    try:
        s3 = get_client("s3")
        s3.put_public_access_block(
            Bucket=args.bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        logger.success(f"Applied Block Public Access to S3 bucket: {args.bucket_name}")
        return f"Success applying block public access to {args.bucket_name}"
    except Exception as e:
        logger.error(
            f"Failed to apply Block Public Access to {args.bucket_name}: {str(e)}"
        )
        return f"Error: {str(e)}"
