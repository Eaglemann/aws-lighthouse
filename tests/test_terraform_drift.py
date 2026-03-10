"""Unit tests for aws_lighthouse/tools/terraform_drift.py."""

import pytest

from aws_lighthouse.tools.terraform_drift import (
    _extract_resource_id,
    _get_hcl_fix,
    _is_in_tf_content,
    _tf_resource_name,
    classify_findings_by_iac,
)

pytestmark = [pytest.mark.unit]


class TestExtractResourceId:
    def test_s3_arn(self):
        assert _extract_resource_id("arn:aws:s3:::my-bucket") == "my-bucket"

    def test_ec2_arn_with_slash(self):
        rid = "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0"
        assert _extract_resource_id(rid) == "i-1234567890abcdef0"

    def test_iam_role_arn(self):
        assert _extract_resource_id("arn:aws:iam::123456789012:role/MyRole") == "MyRole"

    def test_kms_key_arn(self):
        arn = "arn:aws:kms:us-east-1:123456789012:key/mrk-1234abcd"
        assert _extract_resource_id(arn) == "mrk-1234abcd"

    def test_plain_sg_id_passthrough(self):
        assert _extract_resource_id("sg-1234567890abcdef0") == "sg-1234567890abcdef0"

    def test_bucket_name_passthrough(self):
        assert _extract_resource_id("my-bucket") == "my-bucket"

    def test_arn_no_slash_in_last_segment(self):
        # e.g. arn:aws:s3:::bucketname (no slash after colon)
        assert _extract_resource_id("arn:aws:s3:::bucketname") == "bucketname"


class TestTfResourceName:
    def test_replaces_hyphens(self):
        assert _tf_resource_name("my-bucket") == "my_bucket"

    def test_replaces_dots(self):
        assert _tf_resource_name("my.bucket") == "my_bucket"

    def test_alphanumeric_unchanged(self):
        assert _tf_resource_name("mybucket") == "mybucket"

    def test_empty_fallback(self):
        assert _tf_resource_name("") == "resource"

    def test_strips_leading_trailing_underscores(self):
        result = _tf_resource_name("-leading")
        assert not result.startswith("_")


class TestGetHclFix:
    def test_s3_public_access(self):
        fix = _get_hcl_fix("S3 bucket has no public access block", "my-bucket")
        assert fix is not None
        assert "aws_s3_bucket_public_access_block" in fix
        assert "my-bucket" in fix

    def test_s3_encryption(self):
        fix = _get_hcl_fix("S3 bucket has no default encryption", "my-bucket")
        assert fix is not None
        assert "aws_s3_bucket_server_side_encryption_configuration" in fix

    def test_imdsv2(self):
        fix = _get_hcl_fix("EC2 instance not using IMDSv2", "i-1234")
        assert fix is not None
        assert "http_tokens" in fix

    def test_guardduty(self):
        fix = _get_hcl_fix("GuardDuty not enabled in us-east-1", "us-east-1")
        assert fix is not None
        assert "aws_guardduty_detector" in fix

    def test_cloudtrail(self):
        fix = _get_hcl_fix("CloudTrail not enabled", "us-east-1")
        assert fix is not None
        assert "aws_cloudtrail" in fix

    def test_ssh_finding(self):
        fix = _get_hcl_fix("Security group allows unrestricted SSH", "sg-123")
        assert fix is not None
        assert "22" in fix

    def test_kms_rotation(self):
        fix = _get_hcl_fix("KMS key rotation not enabled", "mrk-1234")
        assert fix is not None
        assert "enable_key_rotation" in fix

    def test_rds_publicly_accessible(self):
        fix = _get_hcl_fix("RDS instance is publicly accessible", "db-prod")
        assert fix is not None
        assert "publicly_accessible" in fix

    def test_vpc_flow_logs(self):
        fix = _get_hcl_fix("VPC vpc-123 has no flow logs enabled", "vpc-123")
        assert fix is not None
        assert "aws_flow_log" in fix

    def test_nat_gateway(self):
        fix = _get_hcl_fix(
            "NAT Gateway nat-123 has had no traffic in 7 days", "nat-123"
        )
        assert fix is not None
        assert "aws_nat_gateway" in fix or "Remove" in fix

    def test_load_balancer(self):
        fix = _get_hcl_fix(
            "Load balancer my-alb has had no requests in 7 days", "my-alb"
        )
        assert fix is not None
        assert "aws_lb" in fix or "load balancer" in fix.lower() or "Remove" in fix

    def test_no_match_returns_none(self):
        assert _get_hcl_fix("some unrecognized finding text here", "res") is None

    def test_case_insensitive_match(self):
        fix = _get_hcl_fix("S3 BUCKET HAS NO PUBLIC ACCESS BLOCK", "my-bucket")
        assert fix is not None


class TestIsInTfContent:
    def test_found(self):
        assert _is_in_tf_content("my-bucket", 'bucket = "my-bucket"')

    def test_not_found(self):
        assert not _is_in_tf_content("my-bucket", "some other content")

    def test_empty_resource_id(self):
        assert not _is_in_tf_content("", "anything")


class TestClassifyFindingsByIac:
    def _finding(self, resource: str, finding: str, severity: str = "HIGH") -> dict:
        return {"resource": resource, "finding": finding, "severity": severity}

    def test_iac_managed_when_resource_in_tf(self, tmp_path):
        tf = tmp_path / "main.tf"
        tf.write_text(
            'resource "aws_s3_bucket" "my_bucket" {\n  bucket = "my-bucket"\n}\n'
        )
        findings = [self._finding("my-bucket", "S3 bucket has no public access block")]
        result = classify_findings_by_iac(findings, str(tmp_path))
        assert result["ok"]
        assert result["data"][0]["iac_managed"] is True
        assert result["data"][0]["shadow_infra"] is False

    def test_shadow_infra_when_resource_not_in_tf(self, tmp_path):
        tf = tmp_path / "main.tf"
        tf.write_text(
            'resource "aws_s3_bucket" "other" {\n  bucket = "other-bucket"\n}\n'
        )
        findings = [
            self._finding("missing-bucket", "S3 bucket has no public access block")
        ]
        result = classify_findings_by_iac(findings, str(tmp_path))
        assert result["ok"]
        assert result["data"][0]["shadow_infra"] is True
        assert result["data"][0]["iac_managed"] is False

    def test_hcl_fix_attached_for_known_finding(self, tmp_path):
        (tmp_path / "main.tf").write_text("")
        findings = [self._finding("my-bucket", "S3 bucket has no public access block")]
        result = classify_findings_by_iac(findings, str(tmp_path))
        assert result["ok"]
        assert result["data"][0]["hcl_fix"] is not None

    def test_hcl_fix_none_for_unknown_finding(self, tmp_path):
        (tmp_path / "main.tf").write_text("")
        findings = [self._finding("res", "some completely unknown finding type")]
        result = classify_findings_by_iac(findings, str(tmp_path))
        assert result["ok"]
        assert result["data"][0]["hcl_fix"] is None

    def test_no_tf_files_returns_empty_list(self, tmp_path):
        result = classify_findings_by_iac([], str(tmp_path))
        assert result["ok"]
        assert result["data"] == []

    def test_nonexistent_directory_returns_error(self, tmp_path):
        result = classify_findings_by_iac([], str(tmp_path / "does-not-exist"))
        assert not result["ok"]
        assert result["errors"][0]["code"] == "DirectoryNotFound"

    def test_blocked_path_monkeypatch(self, monkeypatch):
        from aws_lighthouse.tools import terraform_drift

        monkeypatch.setattr(terraform_drift, "_is_blocked_path", lambda p: True)
        result = classify_findings_by_iac([], "/any/path")
        assert not result["ok"]
        assert result["errors"][0]["code"] == "BlockedPath"

    def test_empty_findings_returns_empty_list(self, tmp_path):
        (tmp_path / "main.tf").write_text(
            'resource "aws_s3_bucket" "b" { bucket = "b" }'
        )
        result = classify_findings_by_iac([], str(tmp_path))
        assert result["ok"]
        assert result["data"] == []

    def test_arn_resource_id_extracted(self, tmp_path):
        (tmp_path / "main.tf").write_text('bucket = "my-bucket"')
        findings = [
            self._finding(
                "arn:aws:s3:::my-bucket", "S3 bucket has no default encryption"
            )
        ]
        result = classify_findings_by_iac(findings, str(tmp_path))
        assert result["ok"]
        assert result["data"][0]["resource_id"] == "my-bucket"
        assert result["data"][0]["iac_managed"] is True

    def test_tf_resource_info_populated_when_iac_managed(self, tmp_path):
        (tmp_path / "main.tf").write_text(
            'resource "aws_s3_bucket" "my_bucket" {\n  bucket = "my-bucket"\n}\n'
        )
        findings = [self._finding("my-bucket", "some finding")]
        result = classify_findings_by_iac(findings, str(tmp_path))
        tf_res = result["data"][0]["tf_resource"]
        assert tf_res is not None
        assert tf_res["resource_type"] == "aws_s3_bucket"
        assert tf_res["resource_name"] == "my_bucket"
        assert tf_res["tf_file"] == "main.tf"

    def test_mixed_iac_and_shadow(self, tmp_path):
        (tmp_path / "main.tf").write_text(
            'resource "aws_s3_bucket" "a" { bucket = "bucket-a" }'
        )
        findings = [
            self._finding("bucket-a", "S3 bucket has no public access block"),
            self._finding("bucket-b", "S3 bucket has no public access block"),
        ]
        result = classify_findings_by_iac(findings, str(tmp_path))
        assert result["ok"]
        assert result["data"][0]["iac_managed"] is True
        assert result["data"][1]["shadow_infra"] is True

    def test_source_kind_preserved(self, tmp_path):
        (tmp_path / "main.tf").write_text("")
        findings = [self._finding("r", "some finding")]
        result = classify_findings_by_iac(
            findings, str(tmp_path), source_kind="cost_scan"
        )
        assert result["data"][0]["source_kind"] == "cost_scan"

    def test_severity_preserved(self, tmp_path):
        (tmp_path / "main.tf").write_text("")
        findings = [self._finding("r", "some finding", severity="CRITICAL")]
        result = classify_findings_by_iac(findings, str(tmp_path))
        assert result["data"][0]["severity"] == "CRITICAL"
