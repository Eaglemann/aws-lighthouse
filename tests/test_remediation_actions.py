from unittest.mock import MagicMock, patch

from aws_lighthouse.tools.remediation_actions import (
    apply_s3_block_public_access,
    delete_ebs_volume,
    release_eip,
)

MOD = "aws_lighthouse.tools.remediation_actions"


# ── apply_s3_block_public_access ──────────────────────────────────────────────


def test_s3_block_public_access_success():
    mock_s3 = MagicMock()
    with patch(f"{MOD}.get_aws_client", return_value=mock_s3):
        result = apply_s3_block_public_access("my-bucket")
    assert result is True
    mock_s3.put_public_access_block.assert_called_once_with(
        Bucket="my-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )


def test_s3_block_public_access_failure_returns_false():
    mock_s3 = MagicMock()
    mock_s3.put_public_access_block.side_effect = Exception("access denied")
    with patch(f"{MOD}.get_aws_client", return_value=mock_s3):
        result = apply_s3_block_public_access("bad-bucket")
    assert result is False


# ── delete_ebs_volume ─────────────────────────────────────────────────────────


def test_delete_ebs_volume_success():
    mock_ec2 = MagicMock()
    with patch(f"{MOD}.get_aws_client", return_value=mock_ec2):
        result = delete_ebs_volume("vol-abc123")
    assert result is True
    mock_ec2.delete_volume.assert_called_once_with(VolumeId="vol-abc123")


def test_delete_ebs_volume_failure_returns_false():
    mock_ec2 = MagicMock()
    mock_ec2.delete_volume.side_effect = Exception("volume in use")
    with patch(f"{MOD}.get_aws_client", return_value=mock_ec2):
        result = delete_ebs_volume("vol-xyz")
    assert result is False


# ── release_eip ───────────────────────────────────────────────────────────────


def test_release_eip_allocation_id():
    mock_ec2 = MagicMock()
    with patch(f"{MOD}.get_aws_client", return_value=mock_ec2):
        result = release_eip("eipalloc-0123456789abcdef0")
    assert result is True
    mock_ec2.release_address.assert_called_once_with(
        AllocationId="eipalloc-0123456789abcdef0"
    )


def test_release_eip_public_ip():
    mock_ec2 = MagicMock()
    with patch(f"{MOD}.get_aws_client", return_value=mock_ec2):
        result = release_eip("1.2.3.4")
    assert result is True
    mock_ec2.release_address.assert_called_once_with(PublicIp="1.2.3.4")


def test_release_eip_failure_returns_false():
    mock_ec2 = MagicMock()
    mock_ec2.release_address.side_effect = Exception("not found")
    with patch(f"{MOD}.get_aws_client", return_value=mock_ec2):
        result = release_eip("eipalloc-bad")
    assert result is False
