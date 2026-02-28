from unittest.mock import MagicMock, patch

from aws_lighthouse.tools.remediation_actions import (
    apply_s3_block_public_access,
    apply_s3_default_encryption,
    delete_ebs_volume,
    enable_cloudtrail_logging,
    enable_guardduty,
    enforce_imdsv2,
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


# ── enable_guardduty ──────────────────────────────────────────────────────────


def test_enable_guardduty_no_detector_calls_create():
    mock_gd = MagicMock()
    with patch(f"{MOD}.get_aws_client", return_value=mock_gd):
        result = enable_guardduty("guardduty")
    assert result is True
    mock_gd.create_detector.assert_called_once_with(Enable=True)
    mock_gd.update_detector.assert_not_called()


def test_enable_guardduty_existing_detector_calls_update():
    mock_gd = MagicMock()
    with patch(f"{MOD}.get_aws_client", return_value=mock_gd):
        result = enable_guardduty("abc123")
    assert result is True
    mock_gd.update_detector.assert_called_once_with(DetectorId="abc123", Enable=True)
    mock_gd.create_detector.assert_not_called()


def test_enable_guardduty_create_raises_returns_false():
    mock_gd = MagicMock()
    mock_gd.create_detector.side_effect = Exception("denied")
    with patch(f"{MOD}.get_aws_client", return_value=mock_gd):
        result = enable_guardduty("guardduty")
    assert result is False


def test_enable_guardduty_update_raises_returns_false():
    mock_gd = MagicMock()
    mock_gd.update_detector.side_effect = Exception("denied")
    with patch(f"{MOD}.get_aws_client", return_value=mock_gd):
        result = enable_guardduty("abc123")
    assert result is False


# ── enable_cloudtrail_logging ─────────────────────────────────────────────────


def test_enable_cloudtrail_logging_success():
    mock_ct = MagicMock()
    with patch(f"{MOD}.get_aws_client", return_value=mock_ct):
        result = enable_cloudtrail_logging("my-trail")
    assert result is True
    mock_ct.start_logging.assert_called_once_with(Name="my-trail")


def test_enable_cloudtrail_logging_failure_returns_false():
    mock_ct = MagicMock()
    mock_ct.start_logging.side_effect = Exception("trail not found")
    with patch(f"{MOD}.get_aws_client", return_value=mock_ct):
        result = enable_cloudtrail_logging("bad-trail")
    assert result is False


# ── enforce_imdsv2 ────────────────────────────────────────────────────────────


def test_enforce_imdsv2_success():
    mock_ec2 = MagicMock()
    with patch(f"{MOD}.get_aws_client", return_value=mock_ec2):
        result = enforce_imdsv2("i-0abc1234")
    assert result is True
    mock_ec2.modify_instance_metadata_options.assert_called_once_with(
        InstanceId="i-0abc1234",
        HttpTokens="required",
        HttpEndpoint="enabled",
    )


def test_enforce_imdsv2_failure_returns_false():
    mock_ec2 = MagicMock()
    mock_ec2.modify_instance_metadata_options.side_effect = Exception("access denied")
    with patch(f"{MOD}.get_aws_client", return_value=mock_ec2):
        result = enforce_imdsv2("i-bad")
    assert result is False


# ── apply_s3_default_encryption ───────────────────────────────────────────────


def test_apply_s3_default_encryption_success():
    mock_s3 = MagicMock()
    with patch(f"{MOD}.get_aws_client", return_value=mock_s3):
        result = apply_s3_default_encryption("my-bucket")
    assert result is True
    mock_s3.put_bucket_encryption.assert_called_once_with(
        Bucket="my-bucket",
        ServerSideEncryptionConfiguration={
            "Rules": [
                {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
            ]
        },
    )


def test_apply_s3_default_encryption_failure_returns_false():
    mock_s3 = MagicMock()
    mock_s3.put_bucket_encryption.side_effect = Exception("access denied")
    with patch(f"{MOD}.get_aws_client", return_value=mock_s3):
        result = apply_s3_default_encryption("bad-bucket")
    assert result is False
