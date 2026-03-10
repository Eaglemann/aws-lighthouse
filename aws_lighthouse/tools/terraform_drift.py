"""Terraform drift detection: classify scan findings as IaC-managed or shadow infrastructure."""

import contextlib
import re
from pathlib import Path
from typing import Any

from ..scan_contract import error_result, ok_result
from ..types import ScanResult
from .bash import _is_blocked_path

# ---------------------------------------------------------------------------
# HCL fix mapping (ordered list of tuples -- first match wins)
# ---------------------------------------------------------------------------

_FINDING_TO_HCL: list[tuple[str, str]] = [
    (
        "public access",
        'resource "aws_s3_bucket_public_access_block" "{name}" {{\n'
        '  bucket                  = "{resource_id}"\n'
        "  block_public_acls       = true\n"
        "  block_public_policy     = true\n"
        "  ignore_public_acls      = true\n"
        "  restrict_public_buckets = true\n"
        "}}",
    ),
    (
        "encryption",
        'resource "aws_s3_bucket_server_side_encryption_configuration" "{name}" {{\n'
        '  bucket = "{resource_id}"\n'
        "  rule {{\n"
        "    apply_server_side_encryption_by_default {{\n"
        '      sse_algorithm = "AES256"\n'
        "    }}\n"
        "    bucket_key_enabled = true\n"
        "  }}\n"
        "}}",
    ),
    (
        "IMDSv2",
        "# Add inside your aws_instance resource for {resource_id}:\n"
        "  metadata_options {{\n"
        '    http_tokens   = "required"\n'
        '    http_endpoint = "enabled"\n'
        "  }}",
    ),
    (
        "EBS",
        "# Add to your aws_ebs_volume or aws_instance for {resource_id}:\n"
        "  encrypted = true",
    ),
    (
        "GuardDuty",
        'resource "aws_guardduty_detector" "main" {{\n  enable = true\n}}',
    ),
    (
        "CloudTrail",
        'resource "aws_cloudtrail" "main" {{\n'
        '  name                          = "lighthouse-trail"\n'
        "  s3_bucket_name                = aws_s3_bucket.trail.bucket\n"
        "  include_global_service_events = true\n"
        "  is_multi_region_trail         = true\n"
        "  enable_log_file_validation    = true\n"
        "}}",
    ),
    (
        "rotation",
        "# Add to your aws_kms_key resource for {resource_id}:\n"
        "  enable_key_rotation = true",
    ),
    (
        "SSH",
        "# In aws_security_group for {resource_id}, restrict the ingress rule:\n"
        "  ingress {{\n"
        "    from_port   = 22\n"
        "    to_port     = 22\n"
        '    protocol    = "tcp"\n'
        '    cidr_blocks = ["10.0.0.0/8"]  # Replace with your allowed CIDR\n'
        "  }}",
    ),
    (
        "RDP",
        "# In aws_security_group for {resource_id}, restrict the ingress rule:\n"
        "  ingress {{\n"
        "    from_port   = 3389\n"
        "    to_port     = 3389\n"
        '    protocol    = "tcp"\n'
        '    cidr_blocks = ["10.0.0.0/8"]  # Replace with your allowed CIDR\n'
        "  }}",
    ),
    (
        "publicly accessible",
        "# In your aws_db_instance for {resource_id}:\n  publicly_accessible = false",
    ),
    (
        "NAT Gateway",
        "# Remove the aws_nat_gateway resource for {resource_id} from your .tf files\n"
        "# Also release the associated aws_eip if no longer needed",
    ),
    (
        "Load balancer",
        "# Remove the aws_lb (or aws_alb) resource for {resource_id} from your .tf files\n"
        "# Also remove associated aws_lb_listener and aws_lb_target_group resources",
    ),
    (
        "no connections",
        "# Your aws_db_instance for {resource_id} appears idle.\n"
        "# Consider stopping it or setting deletion_protection = false before removing:\n"
        '# resource "aws_db_instance" "{name}" {{\n'
        "#   ... existing config ...\n"
        "#   deletion_protection = false\n"
        "# }}",
    ),
    (
        "not been invoked",
        "# Remove the aws_lambda_function resource for {resource_id}:\n"
        '# resource "aws_lambda_function" "{name}" {{\n'
        "#   ... existing config ...\n"
        "# }}\n"
        "# Also remove associated aws_iam_role, aws_cloudwatch_log_group, and triggers.",
    ),
    (
        "flow logs",
        'resource "aws_flow_log" "{name}" {{\n'
        '  vpc_id          = "{resource_id}"\n'
        '  traffic_type    = "ALL"\n'
        "  iam_role_arn    = aws_iam_role.flow_log.arn\n"
        "  log_destination = aws_cloudwatch_log_group.flow_log.arn\n"
        "}}",
    ),
    (
        "retention policy",
        'resource "aws_cloudwatch_log_group" "{name}" {{\n'
        '  name              = "{resource_id}"\n'
        "  retention_in_days = 90\n"
        "}}",
    ),
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_resource_id(resource: str) -> str:
    """Extract the short resource ID from an ARN or pass through as-is.

    Examples:
        "arn:aws:s3:::my-bucket"                     -> "my-bucket"
        "arn:aws:ec2:us-east-1:123:instance/i-abc"   -> "i-abc"
        "arn:aws:iam::123:role/MyRole"               -> "MyRole"
        "sg-1234567890abcdef0"                        -> "sg-1234567890abcdef0"
    """
    if not resource.startswith("arn:"):
        return resource
    parts = resource.split(":")
    last = parts[-1]
    if "/" in last:
        return last.rsplit("/", 1)[-1]
    return last


def _tf_resource_name(resource_id: str) -> str:
    """Convert a resource ID to a valid Terraform resource name (alphanumeric + underscores)."""
    return re.sub(r"[^a-zA-Z0-9_]", "_", resource_id).strip("_") or "resource"


def _get_hcl_fix(finding_text: str, resource_id: str) -> str | None:
    """Return the HCL snippet for a finding, or None if no template matches."""
    name = _tf_resource_name(resource_id)
    for keyword, template in _FINDING_TO_HCL:
        if keyword.lower() in finding_text.lower():
            return template.format(resource_id=resource_id, name=name)
    return None


def _is_in_tf_content(resource_id: str, tf_content: str) -> bool:
    """Return True if resource_id appears anywhere in the combined .tf content."""
    return bool(resource_id) and resource_id in tf_content


def _find_matching_tf_resource(resource_id: str, tf_dir: Path) -> dict[str, str] | None:
    """Return the first resource block in .tf files that references resource_id."""
    resource_re = re.compile(r'resource\s+"(aws_\w+)"\s+"(\w+)"\s*\{', re.MULTILINE)
    for tf_file in sorted(tf_dir.glob("*.tf")):
        try:
            content = tf_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if resource_id not in content:
            continue
        for m in resource_re.finditer(content):
            block_start = m.start()
            block_preview = content[block_start : block_start + 1000]
            if resource_id in block_preview:
                return {
                    "resource_type": m.group(1),
                    "resource_name": m.group(2),
                    "tf_file": tf_file.name,
                }
        # resource_id found in file but not inside a specific block
        return {
            "resource_type": "unknown",
            "resource_name": "unknown",
            "tf_file": tf_file.name,
        }
    return None


# ---------------------------------------------------------------------------
# Main classification function
# ---------------------------------------------------------------------------


def classify_findings_by_iac(
    findings: list[dict[str, Any]],
    tf_directory: str,
    source_kind: str = "security",
) -> ScanResult:
    """Classify scan findings as IaC-managed or shadow infrastructure.

    Searches all .tf files in *tf_directory* for each finding's resource ID.
    Returns a list of dicts with keys:
        source_kind, resource_id, finding, severity,
        iac_managed, shadow_infra, tf_resource (dict | None), hcl_fix (str | None)
    """
    if _is_blocked_path(tf_directory):
        return error_result(
            data=[],
            errors=[
                {
                    "code": "BlockedPath",
                    "message": f"Access to '{tf_directory}' is blocked for security reasons.",
                    "service": "terraform",
                    "operation": "classify_findings_by_iac",
                }
            ],
        )

    tf_dir = Path(tf_directory)
    if not tf_dir.exists() or not tf_dir.is_dir():
        return error_result(
            data=[],
            errors=[
                {
                    "code": "DirectoryNotFound",
                    "message": f"Directory '{tf_directory}' does not exist or is not a directory.",
                    "service": "terraform",
                    "operation": "classify_findings_by_iac",
                }
            ],
        )

    tf_files = sorted(tf_dir.glob("*.tf"))
    if not tf_files:
        return ok_result([])

    # Concatenate all .tf content for fast substring search
    tf_content_all = ""
    for tf_file in tf_files:
        with contextlib.suppress(OSError):
            tf_content_all += tf_file.read_text(encoding="utf-8", errors="ignore")

    drift_findings: list[dict[str, Any]] = []
    for f in findings:
        resource = str(f.get("resource") or f.get("principal_name") or "")
        finding_text = str(f.get("finding") or f.get("reason") or "")
        severity = f.get("severity")

        resource_id = _extract_resource_id(resource)
        iac_managed = _is_in_tf_content(resource_id, tf_content_all)
        tf_resource = (
            _find_matching_tf_resource(resource_id, tf_dir) if iac_managed else None
        )
        hcl_fix = _get_hcl_fix(finding_text, resource_id)

        drift_findings.append(
            {
                "source_kind": source_kind,
                "resource_id": resource_id,
                "finding": finding_text,
                "severity": severity,
                "iac_managed": iac_managed,
                "shadow_infra": not iac_managed,
                "tf_resource": tf_resource,
                "hcl_fix": hcl_fix,
            }
        )

    return ok_result(drift_findings)
