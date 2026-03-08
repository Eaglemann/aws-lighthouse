from unittest.mock import patch

from aws_lighthouse.tools.security import (
    S3BlockPublicAccessInput,
    s3_block_public_access,
)

MOD = "aws_lighthouse.tools.security"


def test_s3_block_public_access_success():
    with patch(f"{MOD}.apply_s3_block_public_access", return_value=True) as mock_apply:
        result = s3_block_public_access.func(
            S3BlockPublicAccessInput(bucket_name="my-bucket")
        )
    assert "my-bucket" in result
    assert "Error" not in result
    mock_apply.assert_called_once_with("my-bucket")


def test_s3_block_public_access_api_error_returns_error_string():
    with patch(f"{MOD}.apply_s3_block_public_access", return_value=False):
        result = s3_block_public_access.func(
            S3BlockPublicAccessInput(bucket_name="bad-bucket")
        )
    assert result.startswith("Error:")
