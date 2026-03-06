from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

from aws_lighthouse.tools.security_scan import (
    _check_cloudtrail,
    _check_ebs_encryption,
    _check_guardduty_enabled,
    _check_iam_key_age,
    _check_iam_users_mfa,
    _check_imdsv2,
    _check_open_security_groups,
    _check_public_rds,
    _check_root_mfa,
    _check_s3_block_public_access,
    _check_s3_encryption,
    _get_credential_report,
    run_security_scan,
)

MOD = "aws_lighthouse.tools.security_scan"


def _data(result):
    assert set(result.keys()) == {"ok", "data", "errors"}
    return result["data"]


def make_client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "msg"}}, "Op")


# ── _check_root_mfa ───────────────────────────────────────────────────────────


def test_root_mfa_disabled():
    mock_iam = MagicMock()
    mock_iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 0}}
    with patch(f"{MOD}.get_aws_client", return_value=mock_iam):
        findings = _data(_check_root_mfa())
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert "MFA" in findings[0]["finding"]


def test_root_mfa_enabled():
    mock_iam = MagicMock()
    mock_iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
    with patch(f"{MOD}.get_aws_client", return_value=mock_iam):
        findings = _data(_check_root_mfa())
    assert findings == []


def test_root_mfa_api_error_returns_empty():
    mock_iam = MagicMock()
    mock_iam.get_account_summary.side_effect = make_client_error("AccessDenied")
    with patch(f"{MOD}.get_aws_client", return_value=mock_iam):
        findings = _data(_check_root_mfa())
    assert findings == []


# ── _check_open_security_groups ───────────────────────────────────────────────


def _make_sg_ec2(security_groups):
    ec2 = MagicMock()
    ec2.get_paginator.return_value.paginate.return_value = [
        {"SecurityGroups": security_groups}
    ]
    return ec2


def test_open_sg_ssh_flagged():
    ec2 = _make_sg_ec2(
        [
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
    )
    findings = _data(_check_open_security_groups(ec2))
    assert len(findings) == 1
    assert findings[0]["resource"] == "sg-111"
    assert "22" in findings[0]["finding"]


def test_open_sg_rdp_flagged():
    ec2 = _make_sg_ec2(
        [
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
    )
    findings = _data(_check_open_security_groups(ec2))
    assert len(findings) == 1
    assert "3389" in findings[0]["finding"]


def test_open_sg_restricted_not_flagged():
    ec2 = _make_sg_ec2(
        [
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
    )
    findings = _data(_check_open_security_groups(ec2))
    assert findings == []


def test_open_sg_api_error_returns_empty():
    ec2 = MagicMock()
    ec2.get_paginator.side_effect = make_client_error("AccessDenied")
    findings = _data(_check_open_security_groups(ec2))
    assert findings == []


# ── _get_credential_report ────────────────────────────────────────────────────

_CRED_HEADER = (
    "user,password_enabled,mfa_active,"
    "access_key_1_active,access_key_1_last_rotated,"
    "access_key_2_active,access_key_2_last_rotated"
)


def _make_cred_iam(csv_body: str) -> MagicMock:
    """IAM mock that returns csv_body as the credential report."""
    iam = MagicMock()
    iam.generate_credential_report.return_value = {"State": "COMPLETE"}
    iam.get_credential_report.return_value = {
        "Content": f"{_CRED_HEADER}\n{csv_body}".encode()
    }
    return iam


def test_get_credential_report_complete_immediately():
    iam = _make_cred_iam("alice,true,true,false,N/A,false,N/A")
    rows = _data(_get_credential_report(iam))
    assert len(rows) == 1
    assert rows[0]["user"] == "alice"
    iam.generate_credential_report.assert_called_once()


def test_get_credential_report_polls_until_complete():
    iam = MagicMock()
    iam.generate_credential_report.side_effect = [
        {"State": "STARTED"},
        {"State": "INPROGRESS"},
        {"State": "COMPLETE"},
    ]
    iam.get_credential_report.return_value = {
        "Content": f"{_CRED_HEADER}\nbob,false,false,false,N/A,false,N/A".encode()
    }
    with patch(f"{MOD}.time") as mock_time:
        rows = _data(_get_credential_report(iam))
    assert mock_time.sleep.call_count == 2
    assert rows[0]["user"] == "bob"


def test_get_credential_report_timeout_returns_empty():
    iam = MagicMock()
    iam.generate_credential_report.return_value = {"State": "INPROGRESS"}
    with patch(f"{MOD}.time"):
        rows = _data(_get_credential_report(iam))
    assert rows == []


def test_get_credential_report_api_error_returns_empty():
    iam = MagicMock()
    iam.generate_credential_report.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "denied"}}, "Op"
    )
    rows = _data(_get_credential_report(iam))
    assert rows == []


# ── _check_iam_users_mfa ──────────────────────────────────────────────────────


def test_iam_user_console_no_mfa_flagged():
    iam = _make_cred_iam("alice,true,false,false,N/A,false,N/A")
    with patch(f"{MOD}.get_aws_client", return_value=iam):
        findings = _data(_check_iam_users_mfa())
    assert len(findings) == 1
    assert findings[0]["resource"] == "alice"
    assert findings[0]["severity"] == "HIGH"


def test_iam_user_console_with_mfa_not_flagged():
    iam = _make_cred_iam("bob,true,true,false,N/A,false,N/A")
    with patch(f"{MOD}.get_aws_client", return_value=iam):
        findings = _data(_check_iam_users_mfa())
    assert findings == []


def test_iam_user_no_console_not_flagged():
    iam = _make_cred_iam("charlie,false,false,false,N/A,false,N/A")
    with patch(f"{MOD}.get_aws_client", return_value=iam):
        findings = _data(_check_iam_users_mfa())
    assert findings == []


def test_iam_root_account_skipped_for_mfa():
    iam = _make_cred_iam("<root_account>,not_supported,false,false,N/A,false,N/A")
    with patch(f"{MOD}.get_aws_client", return_value=iam):
        findings = _data(_check_iam_users_mfa())
    assert findings == []


# ── _check_iam_key_age ────────────────────────────────────────────────────────


def test_iam_key_old_flagged():
    old_ts = (datetime.now(UTC) - timedelta(days=91)).isoformat()
    iam = _make_cred_iam(f"alice,false,false,true,{old_ts},false,N/A")
    with patch(f"{MOD}.get_aws_client", return_value=iam):
        findings = _data(_check_iam_key_age())
    assert len(findings) == 1
    assert findings[0]["resource"] == "alice"
    assert "key 1" in findings[0]["finding"]


def test_iam_key_recent_not_flagged():
    recent_ts = (datetime.now(UTC) - timedelta(days=10)).isoformat()
    iam = _make_cred_iam(f"bob,false,false,true,{recent_ts},false,N/A")
    with patch(f"{MOD}.get_aws_client", return_value=iam):
        findings = _data(_check_iam_key_age())
    assert findings == []


def test_iam_key_inactive_skipped():
    old_ts = (datetime.now(UTC) - timedelta(days=200)).isoformat()
    iam = _make_cred_iam(f"carol,false,false,false,{old_ts},false,N/A")
    with patch(f"{MOD}.get_aws_client", return_value=iam):
        findings = _data(_check_iam_key_age())
    assert findings == []


def test_iam_key_na_rotated_skipped():
    iam = _make_cred_iam("dave,false,false,true,N/A,false,N/A")
    with patch(f"{MOD}.get_aws_client", return_value=iam):
        findings = _data(_check_iam_key_age())
    assert findings == []


def test_iam_key2_old_flagged():
    old_ts = (datetime.now(UTC) - timedelta(days=95)).isoformat()
    iam = _make_cred_iam(f"eve,false,false,false,N/A,true,{old_ts}")
    with patch(f"{MOD}.get_aws_client", return_value=iam):
        findings = _data(_check_iam_key_age())
    assert len(findings) == 1
    assert "key 2" in findings[0]["finding"]


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
    findings = _data(_check_public_rds(rdss))
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
    assert _data(_check_public_rds(rdss)) == []


def test_rds_with_error_skipped():
    rdss = [{"error": "AccessDenied"}]
    assert _data(_check_public_rds(rdss)) == []


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
        findings = _data(_check_s3_block_public_access(s3s))
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
        findings = _data(_check_s3_block_public_access(s3s))
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
        findings = _data(_check_s3_block_public_access(s3s))
    assert len(findings) == 1
    assert findings[0]["resource"] == "no-config-bucket"


def test_s3_error_bucket_skipped():
    s3s = [{"error": "AccessDenied"}]
    mock_s3 = MagicMock()
    with patch(f"{MOD}.get_aws_client", return_value=mock_s3):
        findings = _data(_check_s3_block_public_access(s3s))
    assert findings == []


# ── _check_cloudtrail ─────────────────────────────────────────────────────────


def test_cloudtrail_no_trails_flagged():
    ct = MagicMock()
    ct.describe_trails.return_value = {"trailList": []}
    findings = _data(_check_cloudtrail(ct))
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
    findings = _data(_check_cloudtrail(ct))
    assert len(findings) == 1
    assert "not actively logging" in findings[0]["finding"]
    assert findings[0]["remediation_type"] == "enable_cloudtrail_logging"
    assert findings[0]["remediation_label"] == "Start CloudTrail Logging"


def test_cloudtrail_logging_ok():
    ct = MagicMock()
    ct.describe_trails.return_value = {
        "trailList": [
            {"TrailARN": "arn:aws:cloudtrail:us-east-1:123:trail/main", "Name": "main"}
        ]
    }
    ct.get_trail_status.return_value = {"IsLogging": True}
    findings = _data(_check_cloudtrail(ct))
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
    ec2.get_paginator.return_value.paginate.return_value = [
        {"Reservations": [{"Instances": instances}]}
    ]
    return ec2


def test_imdsv2_optional_flagged():
    ec2 = _ec2_with_instances([_make_ec2_instance("i-111", "optional", name="web")])
    findings = _data(_check_imdsv2(ec2))
    assert len(findings) == 1
    assert findings[0]["resource"] == "i-111"
    assert findings[0]["severity"] == "MEDIUM"
    assert "IMDSv1" in findings[0]["finding"]
    assert "web" in findings[0]["finding"]
    assert findings[0]["remediation_type"] == "enforce_imdsv2"
    assert findings[0]["remediation_label"] == "Enforce IMDSv2"


def test_imdsv2_required_not_flagged():
    ec2 = _ec2_with_instances([_make_ec2_instance("i-222", "required")])
    assert _data(_check_imdsv2(ec2)) == []


def test_imdsv2_terminated_skipped():
    ec2 = _ec2_with_instances(
        [_make_ec2_instance("i-333", "optional", state="terminated")]
    )
    assert _data(_check_imdsv2(ec2)) == []


def test_imdsv2_no_name_uses_instance_id():
    ec2 = _ec2_with_instances([_make_ec2_instance("i-444", "optional")])
    findings = _data(_check_imdsv2(ec2))
    assert "i-444" in findings[0]["finding"]


def test_imdsv2_api_error_returns_empty():
    ec2 = MagicMock()
    ec2.get_paginator.side_effect = make_client_error("AccessDenied")
    assert _data(_check_imdsv2(ec2)) == []


# ── _check_ebs_encryption ─────────────────────────────────────────────────────


def _make_volumes_ec2(volumes):
    ec2 = MagicMock()
    ec2.get_paginator.return_value.paginate.return_value = [{"Volumes": volumes}]
    return ec2


def test_ebs_unencrypted_flagged():
    ec2 = _make_volumes_ec2(
        [{"VolumeId": "vol-abc", "Encrypted": False, "Size": 50, "VolumeType": "gp3"}]
    )
    findings = _data(_check_ebs_encryption(ec2))
    assert len(findings) == 1
    assert findings[0]["resource"] == "vol-abc"
    assert findings[0]["severity"] == "MEDIUM"
    assert "50 GB" in findings[0]["finding"]


def test_ebs_encrypted_not_flagged():
    ec2 = _make_volumes_ec2(
        [{"VolumeId": "vol-xyz", "Encrypted": True, "Size": 100, "VolumeType": "gp3"}]
    )
    assert _data(_check_ebs_encryption(ec2)) == []


def test_ebs_mixed_only_flags_unencrypted():
    ec2 = _make_volumes_ec2(
        [
            {
                "VolumeId": "vol-bad",
                "Encrypted": False,
                "Size": 20,
                "VolumeType": "gp2",
            },
            {"VolumeId": "vol-ok", "Encrypted": True, "Size": 20, "VolumeType": "gp2"},
        ]
    )
    findings = _data(_check_ebs_encryption(ec2))
    assert len(findings) == 1
    assert findings[0]["resource"] == "vol-bad"


def test_ebs_api_error_returns_empty():
    ec2 = MagicMock()
    ec2.get_paginator.side_effect = make_client_error("AccessDenied")
    assert _data(_check_ebs_encryption(ec2)) == []


# ── _check_s3_encryption ──────────────────────────────────────────────────────


def _make_s3_enc(bucket_name, rules=None, error_code=None):
    """Return a mock s3 client for a single bucket encryption check."""
    mock_s3 = MagicMock()
    if error_code:
        mock_s3.get_bucket_encryption.side_effect = ClientError(
            {"Error": {"Code": error_code, "Message": ""}}, "GetBucketEncryption"
        )
    else:
        mock_s3.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {"Rules": rules or []}
        }
    return mock_s3


def test_s3_no_encryption_rule_flagged():
    mock_s3 = _make_s3_enc(
        "plain-bucket", error_code="ServerSideEncryptionConfigurationNotFoundError"
    )
    s3s = [{"BucketName": "plain-bucket"}]
    with patch(f"{MOD}.get_aws_client", return_value=mock_s3):
        findings = _data(_check_s3_encryption(s3s))
    assert len(findings) == 1
    assert findings[0]["resource"] == "plain-bucket"
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["remediation_type"] == "s3_default_encryption"
    assert findings[0]["remediation_label"] == "Enable S3 Default Encryption"


def test_s3_aes256_encryption_not_flagged():
    mock_s3 = _make_s3_enc(
        "enc-bucket",
        rules=[{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}],
    )
    s3s = [{"BucketName": "enc-bucket"}]
    with patch(f"{MOD}.get_aws_client", return_value=mock_s3):
        findings = _data(_check_s3_encryption(s3s))
    assert findings == []


def test_s3_kms_encryption_not_flagged():
    mock_s3 = _make_s3_enc(
        "kms-bucket",
        rules=[{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}],
    )
    s3s = [{"BucketName": "kms-bucket"}]
    with patch(f"{MOD}.get_aws_client", return_value=mock_s3):
        findings = _data(_check_s3_encryption(s3s))
    assert findings == []


def test_s3_encryption_error_bucket_skipped():
    s3s = [{"error": "AccessDenied"}]
    mock_s3 = MagicMock()
    with patch(f"{MOD}.get_aws_client", return_value=mock_s3):
        findings = _data(_check_s3_encryption(s3s))
    assert findings == []
    mock_s3.get_bucket_encryption.assert_not_called()


def test_s3_encryption_api_error_returns_empty():
    mock_s3 = MagicMock()
    mock_s3.get_bucket_encryption.side_effect = make_client_error("AccessDenied")
    s3s = [{"BucketName": "any-bucket"}]
    with patch(f"{MOD}.get_aws_client", return_value=mock_s3):
        findings = _data(_check_s3_encryption(s3s))
    assert findings == []


def test_iam_user_mfa_api_error_returns_empty():
    iam = MagicMock()
    iam.generate_credential_report.side_effect = make_client_error("AccessDenied")
    with patch(f"{MOD}.get_aws_client", return_value=iam):
        findings = _data(_check_iam_users_mfa())
    assert findings == []


# ── _check_guardduty_enabled ──────────────────────────────────────────────────


def test_guardduty_not_enabled_flagged():
    gd = MagicMock()
    gd.list_detectors.return_value = {"DetectorIds": []}
    findings = _data(_check_guardduty_enabled(gd))
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert "GuardDuty" in findings[0]["finding"]
    assert findings[0]["remediation_type"] == "enable_guardduty"
    assert findings[0]["remediation_label"] == "Enable GuardDuty"


def test_guardduty_detector_disabled_flagged():
    gd = MagicMock()
    gd.list_detectors.return_value = {"DetectorIds": ["abc123"]}
    gd.get_detector.return_value = {"Status": "DISABLED"}
    findings = _data(_check_guardduty_enabled(gd))
    assert len(findings) == 1
    assert "not enabled" in findings[0]["finding"]
    assert findings[0]["remediation_type"] == "enable_guardduty"
    assert findings[0]["remediation_label"] == "Enable GuardDuty"


def test_guardduty_enabled_not_flagged():
    gd = MagicMock()
    gd.list_detectors.return_value = {"DetectorIds": ["abc123"]}
    gd.get_detector.return_value = {"Status": "ENABLED"}
    assert _data(_check_guardduty_enabled(gd)) == []


def test_guardduty_api_error_returns_empty():
    gd = MagicMock()
    gd.list_detectors.side_effect = make_client_error("AccessDenied")
    assert _data(_check_guardduty_enabled(gd)) == []


def test_guardduty_subscription_required_logs_without_display():
    gd = MagicMock()
    gd.list_detectors.side_effect = make_client_error("SubscriptionRequiredException")
    with patch(f"{MOD}.logger.error") as mock_error:
        result = _check_guardduty_enabled(gd, region="us-east-1")

    assert result["ok"] is False
    assert result["errors"][0]["code"] == "SubscriptionRequiredException"
    assert result["errors"][0]["region"] == "us-east-1"
    mock_error.assert_called_once()
    assert mock_error.call_args.kwargs["display"] is False


# ── run_security_scan wiring ──────────────────────────────────────────────────


def _make_clean_clients():
    """Return mocks representing a fully-compliant AWS environment."""
    iam = MagicMock()
    iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
    iam.generate_credential_report.return_value = {"State": "COMPLETE"}
    iam.get_credential_report.return_value = {"Content": _CRED_HEADER.encode()}

    _ec2_pages = {
        "describe_security_groups": {"SecurityGroups": []},
        "describe_instances": {"Reservations": []},
        "describe_volumes": {"Volumes": []},
    }

    def _ec2_get_paginator(name):
        pag = MagicMock()
        pag.paginate.return_value = [_ec2_pages[name]]
        return pag

    ec2 = MagicMock()
    ec2.get_paginator.side_effect = _ec2_get_paginator

    s3 = MagicMock()
    s3.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
    }
    s3.get_bucket_encryption.return_value = {
        "ServerSideEncryptionConfiguration": {
            "Rules": [
                {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
            ]
        }
    }

    ct = MagicMock()
    ct.describe_trails.return_value = {
        "trailList": [
            {"TrailARN": "arn:aws:cloudtrail:us-east-1:123:trail/main", "Name": "main"}
        ]
    }
    ct.get_trail_status.return_value = {"IsLogging": True}

    gd = MagicMock()
    gd.list_detectors.return_value = {"DetectorIds": ["det-111"]}
    gd.get_detector.return_value = {"Status": "ENABLED"}

    return iam, ec2, s3, ct, gd


def test_run_security_scan_clean_environment_no_findings():
    iam, ec2, s3, ct, gd = _make_clean_clients()

    def _dispatch(svc, region=None):
        return {"iam": iam, "ec2": ec2, "s3": s3, "cloudtrail": ct, "guardduty": gd}[
            svc
        ]

    s3s = [{"BucketName": "my-bucket"}]

    with (
        patch(f"{MOD}.get_aws_client", side_effect=_dispatch),
        patch(f"{MOD}.get_client", side_effect=_dispatch),
    ):
        findings = _data(run_security_scan(s3s=s3s, rdss=[], include_global=True))

    assert findings == []


def test_run_security_scan_include_global_false_skips_root_mfa():
    iam, ec2, s3, ct, gd = _make_clean_clients()
    # If include_global were True, this would produce a finding
    iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 0}}

    def _dispatch(svc, region=None):
        return {"iam": iam, "ec2": ec2, "s3": s3, "cloudtrail": ct, "guardduty": gd}[
            svc
        ]

    with (
        patch(f"{MOD}.get_aws_client", side_effect=_dispatch),
        patch(f"{MOD}.get_client", side_effect=_dispatch),
    ):
        findings = _data(run_security_scan(s3s=[], rdss=[], include_global=False))

    assert not any(f.get("resource") == "root" for f in findings)


def test_run_security_scan_guardduty_disabled_produces_finding():
    iam, ec2, s3, ct, gd = _make_clean_clients()
    gd.list_detectors.return_value = {"DetectorIds": []}

    def _dispatch(svc, region=None):
        return {"iam": iam, "ec2": ec2, "s3": s3, "cloudtrail": ct, "guardduty": gd}[
            svc
        ]

    with (
        patch(f"{MOD}.get_aws_client", side_effect=_dispatch),
        patch(f"{MOD}.get_client", side_effect=_dispatch),
    ):
        findings = _data(run_security_scan(s3s=[], rdss=[], include_global=False))

    gd_findings = [f for f in findings if f["resource"] == "guardduty"]
    assert len(gd_findings) == 1
    assert gd_findings[0]["severity"] == "HIGH"
