from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

from aws_lighthouse.tools.security_scan import (
    _check_cloudtrail,
    _check_ebs_encryption,
    _check_iam_key_age,
    _check_imdsv2,
    _check_open_security_groups,
    _check_public_rds,
    _check_root_mfa,
    _check_s3_block_public_access,
)

MOD = "aws_lighthouse.tools.security_scan"


def make_client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "msg"}}, "Op")


# ── _check_root_mfa ───────────────────────────────────────────────────────────


def test_root_mfa_disabled():
    mock_iam = MagicMock()
    mock_iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 0}}
    with patch(f"{MOD}.get_aws_client", return_value=mock_iam):
        findings = _check_root_mfa()
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert "MFA" in findings[0]["finding"]


def test_root_mfa_enabled():
    mock_iam = MagicMock()
    mock_iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
    with patch(f"{MOD}.get_aws_client", return_value=mock_iam):
        findings = _check_root_mfa()
    assert findings == []


def test_root_mfa_api_error_returns_empty():
    mock_iam = MagicMock()
    mock_iam.get_account_summary.side_effect = Exception("denied")
    with patch(f"{MOD}.get_aws_client", return_value=mock_iam):
        findings = _check_root_mfa()
    assert findings == []


# ── _check_open_security_groups ───────────────────────────────────────────────


def test_open_sg_ssh_flagged():
    ec2 = MagicMock()
    ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-111",
                "GroupName": "wide-open",
                "IpPermissions": [
                    {
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        "Ipv6Ranges": [],
                    }
                ],
            }
        ]
    }
    findings = _check_open_security_groups(ec2)
    assert len(findings) == 1
    assert findings[0]["resource"] == "sg-111"
    assert "22" in findings[0]["finding"]


def test_open_sg_rdp_flagged():
    ec2 = MagicMock()
    ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-222",
                "GroupName": "rdp-open",
                "IpPermissions": [
                    {
                        "FromPort": 3389,
                        "ToPort": 3389,
                        "IpRanges": [],
                        "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                    }
                ],
            }
        ]
    }
    findings = _check_open_security_groups(ec2)
    assert len(findings) == 1
    assert "3389" in findings[0]["finding"]


def test_open_sg_restricted_not_flagged():
    ec2 = MagicMock()
    ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-333",
                "GroupName": "restricted",
                "IpPermissions": [
                    {
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                        "Ipv6Ranges": [],
                    }
                ],
            }
        ]
    }
    findings = _check_open_security_groups(ec2)
    assert findings == []


def test_open_sg_api_error_returns_empty():
    ec2 = MagicMock()
    ec2.describe_security_groups.side_effect = Exception("denied")
    findings = _check_open_security_groups(ec2)
    assert findings == []


# ── _check_iam_key_age ────────────────────────────────────────────────────────


def test_iam_key_old_flagged():
    mock_iam = MagicMock()
    old_date = datetime.now(timezone.utc) - timedelta(days=91)
    mock_iam.list_users.return_value = {"Users": [{"UserName": "alice"}]}
    mock_iam.list_access_keys.return_value = {
        "AccessKeyMetadata": [
            {
                "AccessKeyId": "AKIA123",
                "Status": "Active",
                "CreateDate": old_date,
            }
        ]
    }
    with patch(f"{MOD}.get_aws_client", return_value=mock_iam):
        findings = _check_iam_key_age()
    assert len(findings) == 1
    assert findings[0]["resource"] == "alice"
    assert "AKIA123" in findings[0]["finding"]


def test_iam_key_recent_not_flagged():
    mock_iam = MagicMock()
    recent_date = datetime.now(timezone.utc) - timedelta(days=10)
    mock_iam.list_users.return_value = {"Users": [{"UserName": "bob"}]}
    mock_iam.list_access_keys.return_value = {
        "AccessKeyMetadata": [
            {"AccessKeyId": "AKIA456", "Status": "Active", "CreateDate": recent_date}
        ]
    }
    with patch(f"{MOD}.get_aws_client", return_value=mock_iam):
        findings = _check_iam_key_age()
    assert findings == []


def test_iam_key_inactive_skipped():
    mock_iam = MagicMock()
    old_date = datetime.now(timezone.utc) - timedelta(days=200)
    mock_iam.list_users.return_value = {"Users": [{"UserName": "carol"}]}
    mock_iam.list_access_keys.return_value = {
        "AccessKeyMetadata": [
            {"AccessKeyId": "AKIA789", "Status": "Inactive", "CreateDate": old_date}
        ]
    }
    with patch(f"{MOD}.get_aws_client", return_value=mock_iam):
        findings = _check_iam_key_age()
    assert findings == []


# ── _check_public_rds ─────────────────────────────────────────────────────────


def test_public_rds_flagged():
    rdss = [
        {
            "DBInstanceIdentifier": "prod-db",
            "Engine": "mysql",
            "Class": "db.t3.micro",
            "PubliclyAccessible": True,
        }
    ]
    findings = _check_public_rds(rdss)
    assert len(findings) == 1
    assert findings[0]["resource"] == "prod-db"
    assert findings[0]["severity"] == "HIGH"


def test_private_rds_not_flagged():
    rdss = [
        {
            "DBInstanceIdentifier": "private-db",
            "Engine": "postgres",
            "Class": "db.t3.micro",
            "PubliclyAccessible": False,
        }
    ]
    assert _check_public_rds(rdss) == []


def test_rds_with_error_skipped():
    rdss = [{"error": "AccessDenied"}]
    assert _check_public_rds(rdss) == []


# ── _check_s3_block_public_access ─────────────────────────────────────────────


def test_s3_block_missing_flagged():
    mock_s3 = MagicMock()
    mock_s3.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
    }
    s3s = [{"BucketName": "my-bucket"}]
    with patch(f"{MOD}.get_aws_client", return_value=mock_s3):
        findings = _check_s3_block_public_access(s3s)
    assert len(findings) == 1
    assert findings[0]["resource"] == "my-bucket"


def test_s3_block_fully_enabled_not_flagged():
    mock_s3 = MagicMock()
    mock_s3.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
    }
    s3s = [{"BucketName": "safe-bucket"}]
    with patch(f"{MOD}.get_aws_client", return_value=mock_s3):
        findings = _check_s3_block_public_access(s3s)
    assert findings == []


def test_s3_no_block_config_flagged():
    from botocore.exceptions import ClientError

    mock_s3 = MagicMock()
    mock_s3.get_public_access_block.side_effect = ClientError(
        {"Error": {"Code": "NoSuchPublicAccessBlockConfiguration", "Message": ""}},
        "GetPublicAccessBlock",
    )
    s3s = [{"BucketName": "no-config-bucket"}]
    with patch(f"{MOD}.get_aws_client", return_value=mock_s3):
        findings = _check_s3_block_public_access(s3s)
    assert len(findings) == 1
    assert findings[0]["resource"] == "no-config-bucket"


def test_s3_error_bucket_skipped():
    s3s = [{"error": "AccessDenied"}]
    mock_s3 = MagicMock()
    with patch(f"{MOD}.get_aws_client", return_value=mock_s3):
        findings = _check_s3_block_public_access(s3s)
    assert findings == []


# ── _check_cloudtrail ─────────────────────────────────────────────────────────


def test_cloudtrail_no_trails_flagged():
    ct = MagicMock()
    ct.describe_trails.return_value = {"trailList": []}
    findings = _check_cloudtrail(ct)
    assert len(findings) == 1
    assert "No CloudTrail" in findings[0]["finding"]


def test_cloudtrail_not_logging_flagged():
    ct = MagicMock()
    ct.describe_trails.return_value = {
        "trailList": [
            {"TrailARN": "arn:aws:cloudtrail:us-east-1:123:trail/main", "Name": "main"}
        ]
    }
    ct.get_trail_status.return_value = {"IsLogging": False}
    findings = _check_cloudtrail(ct)
    assert len(findings) == 1
    assert "not actively logging" in findings[0]["finding"]


def test_cloudtrail_logging_ok():
    ct = MagicMock()
    ct.describe_trails.return_value = {
        "trailList": [
            {"TrailARN": "arn:aws:cloudtrail:us-east-1:123:trail/main", "Name": "main"}
        ]
    }
    ct.get_trail_status.return_value = {"IsLogging": True}
    findings = _check_cloudtrail(ct)
    assert findings == []


# ── _check_imdsv2 ─────────────────────────────────────────────────────────────


def _make_ec2_instance(instance_id, http_tokens, state="running", name=None):
    tags = [{"Key": "Name", "Value": name}] if name else []
    return {
        "InstanceId": instance_id,
        "State": {"Name": state},
        "MetadataOptions": {"HttpTokens": http_tokens},
        "Tags": tags,
    }


def _ec2_with_instances(instances):
    ec2 = MagicMock()
    ec2.describe_instances.return_value = {"Reservations": [{"Instances": instances}]}
    return ec2


def test_imdsv2_optional_flagged():
    ec2 = _ec2_with_instances([_make_ec2_instance("i-111", "optional", name="web")])
    findings = _check_imdsv2(ec2)
    assert len(findings) == 1
    assert findings[0]["resource"] == "i-111"
    assert findings[0]["severity"] == "MEDIUM"
    assert "IMDSv1" in findings[0]["finding"]
    assert "web" in findings[0]["finding"]


def test_imdsv2_required_not_flagged():
    ec2 = _ec2_with_instances([_make_ec2_instance("i-222", "required")])
    assert _check_imdsv2(ec2) == []


def test_imdsv2_terminated_skipped():
    ec2 = _ec2_with_instances(
        [_make_ec2_instance("i-333", "optional", state="terminated")]
    )
    assert _check_imdsv2(ec2) == []


def test_imdsv2_no_name_uses_instance_id():
    ec2 = _ec2_with_instances([_make_ec2_instance("i-444", "optional")])
    findings = _check_imdsv2(ec2)
    assert "i-444" in findings[0]["finding"]


def test_imdsv2_api_error_returns_empty():
    ec2 = MagicMock()
    ec2.describe_instances.side_effect = Exception("denied")
    assert _check_imdsv2(ec2) == []


# ── _check_ebs_encryption ─────────────────────────────────────────────────────


def test_ebs_unencrypted_flagged():
    ec2 = MagicMock()
    ec2.describe_volumes.return_value = {
        "Volumes": [
            {"VolumeId": "vol-abc", "Encrypted": False, "Size": 50, "VolumeType": "gp3"}
        ]
    }
    findings = _check_ebs_encryption(ec2)
    assert len(findings) == 1
    assert findings[0]["resource"] == "vol-abc"
    assert findings[0]["severity"] == "MEDIUM"
    assert "50 GB" in findings[0]["finding"]


def test_ebs_encrypted_not_flagged():
    ec2 = MagicMock()
    ec2.describe_volumes.return_value = {
        "Volumes": [
            {"VolumeId": "vol-xyz", "Encrypted": True, "Size": 100, "VolumeType": "gp3"}
        ]
    }
    assert _check_ebs_encryption(ec2) == []


def test_ebs_mixed_only_flags_unencrypted():
    ec2 = MagicMock()
    ec2.describe_volumes.return_value = {
        "Volumes": [
            {
                "VolumeId": "vol-bad",
                "Encrypted": False,
                "Size": 20,
                "VolumeType": "gp2",
            },
            {"VolumeId": "vol-ok", "Encrypted": True, "Size": 20, "VolumeType": "gp2"},
        ]
    }
    findings = _check_ebs_encryption(ec2)
    assert len(findings) == 1
    assert findings[0]["resource"] == "vol-bad"


def test_ebs_api_error_returns_empty():
    ec2 = MagicMock()
    ec2.describe_volumes.side_effect = Exception("denied")
    assert _check_ebs_encryption(ec2) == []
