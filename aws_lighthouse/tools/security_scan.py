from datetime import datetime, timezone
from typing import Any, Dict, List

from botocore.exceptions import ClientError

from ..auth import get_aws_client, get_aws_client_for_region
from ..logger import logger


def _check_root_mfa() -> List[Dict[str, Any]]:
    """Check whether the root account has MFA enabled."""
    try:
        iam = get_aws_client("iam")
        summary = iam.get_account_summary().get("SummaryMap", {})
        if not summary.get("AccountMFAEnabled", 0):
            return [
                {
                    "severity": "HIGH",
                    "resource": "root",
                    "finding": "Root account does not have MFA enabled",
                }
            ]
    except Exception as e:
        logger.error(f"Failed to check root MFA: {e}")
    return []


def _check_open_security_groups(ec2) -> List[Dict[str, Any]]:
    """Flag security groups that allow unrestricted ingress on SSH (22) or RDP (3389)."""
    findings = []
    try:
        for sg in ec2.describe_security_groups().get("SecurityGroups", []):
            for perm in sg.get("IpPermissions", []):
                from_port = perm.get("FromPort", 0)
                to_port = perm.get("ToPort", 65535)
                open_cidrs = [
                    r["CidrIp"]
                    for r in perm.get("IpRanges", [])
                    if r["CidrIp"] == "0.0.0.0/0"
                ] + [
                    r["CidrIpv6"]
                    for r in perm.get("Ipv6Ranges", [])
                    if r["CidrIpv6"] == "::/0"
                ]
                if not open_cidrs:
                    continue
                for port in (22, 3389):
                    if from_port <= port <= to_port:
                        findings.append(
                            {
                                "severity": "HIGH",
                                "resource": sg["GroupId"],
                                "finding": (
                                    f"Security group '{sg.get('GroupName')}' allows port {port} "
                                    f"from {', '.join(open_cidrs)}"
                                ),
                            }
                        )
    except Exception as e:
        logger.error(f"Failed to check security groups: {e}")
    return findings


def _check_iam_key_age() -> List[Dict[str, Any]]:
    """Flag active IAM access keys older than 90 days."""
    findings = []
    try:
        iam = get_aws_client("iam")
        now = datetime.now(timezone.utc)
        for user in iam.list_users().get("Users", []):
            for key in iam.list_access_keys(UserName=user["UserName"]).get(
                "AccessKeyMetadata", []
            ):
                if key["Status"] != "Active":
                    continue
                age = (now - key["CreateDate"]).days
                if age > 90:
                    findings.append(
                        {
                            "severity": "MEDIUM",
                            "resource": user["UserName"],
                            "finding": f"Access key {key['AccessKeyId']} is {age} days old (>90 days)",
                        }
                    )
    except Exception as e:
        logger.error(f"Failed to check IAM access key age: {e}")
    return findings


def _check_public_rds(rdss: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Flag RDS instances that are publicly accessible."""
    return [
        {
            "severity": "HIGH",
            "resource": db["DBInstanceIdentifier"],
            "finding": f"RDS instance is publicly accessible (engine: {db['Engine']}, class: {db['Class']})",
        }
        for db in rdss
        if "error" not in db and db.get("PubliclyAccessible")
    ]


def _check_s3_block_public_access(s3s: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Flag S3 buckets that do not have Block Public Access fully enabled."""
    findings = []
    try:
        s3 = get_aws_client("s3")
        for bucket in s3s:
            if "error" in bucket:
                continue
            name = bucket["BucketName"]
            try:
                block = s3.get_public_access_block(Bucket=name)[
                    "PublicAccessBlockConfiguration"
                ]
                if not all(
                    [
                        block.get("BlockPublicAcls"),
                        block.get("IgnorePublicAcls"),
                        block.get("BlockPublicPolicy"),
                        block.get("RestrictPublicBuckets"),
                    ]
                ):
                    findings.append(
                        {
                            "severity": "HIGH",
                            "resource": name,
                            "finding": "S3 bucket does not have Block Public Access fully enabled",
                            "remediation_type": "s3_block_public_access",
                            "remediation_label": "Enable S3 Block Public Access",
                        }
                    )
            except ClientError as e:
                if (
                    e.response["Error"]["Code"]
                    == "NoSuchPublicAccessBlockConfiguration"
                ):
                    findings.append(
                        {
                            "severity": "HIGH",
                            "resource": name,
                            "finding": "S3 bucket has no Block Public Access configuration",
                            "remediation_type": "s3_block_public_access",
                            "remediation_label": "Enable S3 Block Public Access",
                        }
                    )
    except Exception as e:
        logger.error(f"Failed to check S3 public access: {e}")
    return findings


def _check_imdsv2(ec2) -> List[Dict[str, Any]]:
    """Flag EC2 instances that still allow IMDSv1 (HttpTokens != required)."""
    findings = []
    try:
        for res in ec2.describe_instances().get("Reservations", []):
            for inst in res.get("Instances", []):
                if inst.get("State", {}).get("Name") == "terminated":
                    continue
                if inst.get("MetadataOptions", {}).get("HttpTokens") != "required":
                    name = next(
                        (
                            t["Value"]
                            for t in inst.get("Tags", [])
                            if t["Key"] == "Name"
                        ),
                        inst["InstanceId"],
                    )
                    findings.append(
                        {
                            "severity": "MEDIUM",
                            "resource": inst["InstanceId"],
                            "finding": (
                                f"Instance '{name}' allows IMDSv1 (HttpTokens=optional)"
                                " — vulnerable to SSRF credential theft"
                            ),
                        }
                    )
    except Exception as e:
        logger.error(f"Failed to check IMDSv2 enforcement: {e}")
    return findings


def _check_ebs_encryption(ec2) -> List[Dict[str, Any]]:
    """Flag EBS volumes that are not encrypted at rest."""
    findings = []
    try:
        for vol in ec2.describe_volumes().get("Volumes", []):
            if not vol.get("Encrypted", False):
                findings.append(
                    {
                        "severity": "MEDIUM",
                        "resource": vol["VolumeId"],
                        "finding": (
                            f"EBS volume is not encrypted"
                            f" ({vol.get('Size', 0)} GB {vol.get('VolumeType', 'unknown')})"
                        ),
                    }
                )
    except Exception as e:
        logger.error(f"Failed to check EBS encryption: {e}")
    return findings


def _check_cloudtrail(ct) -> List[Dict[str, Any]]:
    """Check that CloudTrail is configured and actively logging in this region."""
    findings = []
    try:
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        if not trails:
            return [
                {
                    "severity": "HIGH",
                    "resource": "cloudtrail",
                    "finding": "No CloudTrail trails configured in this region",
                }
            ]
        for trail in trails:
            status = ct.get_trail_status(Name=trail["TrailARN"])
            if not status.get("IsLogging"):
                findings.append(
                    {
                        "severity": "HIGH",
                        "resource": trail.get("Name"),
                        "finding": "CloudTrail trail exists but is not actively logging",
                    }
                )
    except Exception as e:
        logger.error(f"Failed to check CloudTrail: {e}")
    return findings


def run_security_scan(
    s3s: List[Dict[str, Any]],
    rdss: List[Dict[str, Any]],
    region: str | None = None,
    include_global: bool = True,
) -> List[Dict[str, Any]]:
    """Run security checks and return a unified list of findings.

    include_global controls whether account-wide checks (root MFA, IAM key age,
    S3 block public access) are executed.  Set to False when looping over
    multiple regions to avoid duplicate global findings.
    """
    _cl = (
        (lambda svc: get_aws_client_for_region(svc, region))
        if region
        else (lambda svc: get_aws_client(svc))
    )
    findings = []
    if include_global:
        findings.extend(_check_root_mfa())
        findings.extend(_check_iam_key_age())
        findings.extend(_check_s3_block_public_access(s3s))
    ec2 = _cl("ec2")
    findings.extend(_check_open_security_groups(ec2))
    findings.extend(_check_imdsv2(ec2))
    findings.extend(_check_ebs_encryption(ec2))
    findings.extend(_check_public_rds(rdss))
    findings.extend(_check_cloudtrail(_cl("cloudtrail")))
    return findings
