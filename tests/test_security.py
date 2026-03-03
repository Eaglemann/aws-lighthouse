from unittest.mock import MagicMock, patch

from botocore.exceptions import BotoCoreError

from aws_lighthouse.tools.security import (
    S3BlockPublicAccessInput,
    s3_block_public_access,
)

MOD = "aws_lighthouse.tools.security"


def test_s3_block_public_access_success():
    s3 = MagicMock()
    with patch(f"{MOD}.get_client", return_value=s3):
        result = s3_block_public_access.func(
            S3BlockPublicAccessInput(bucket_name="my-bucket")
        )
    assert "my-bucket" in result
    assert "Error" not in result
    s3.put_public_access_block.assert_called_once_with(
        Bucket="my-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )


def test_s3_block_public_access_api_error_returns_error_string():
    s3 = MagicMock()
    s3.put_public_access_block.side_effect = BotoCoreError()
    with patch(f"{MOD}.get_client", return_value=s3):
        result = s3_block_public_access.func(
            S3BlockPublicAccessInput(bucket_name="bad-bucket")
        )
    assert result.startswith("Error:")
