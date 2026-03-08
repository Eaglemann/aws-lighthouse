from langchain_core.tools import tool
from pydantic import BaseModel, Field

from ..logger import logger
from .remediation_actions import apply_s3_block_public_access


class S3BlockPublicAccessInput(BaseModel):
    bucket_name: str = Field(
        description="The name of the S3 bucket to configure Block Public Access on."
    )


@tool("s3_block_public_access")
def s3_block_public_access(args: S3BlockPublicAccessInput) -> str:
    """Applies the strictest S3 Block Public Access configuration to a bucket."""
    ok = apply_s3_block_public_access(args.bucket_name)
    if ok:
        logger.success(f"Applied Block Public Access to S3 bucket: {args.bucket_name}")
        return f"Success applying block public access to {args.bucket_name}"
    return f"Error: failed to apply Block Public Access to {args.bucket_name}"
