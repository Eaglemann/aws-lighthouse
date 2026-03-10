import csv
import io
import time
from datetime import UTC, datetime
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from ..auth import get_aws_client, get_client
from ..logger import logger
from ..scan_contract import (
    error_result,
    is_expected_unavailable_scan_error,
    merge_list_results,
    ok_result,
    scan_error_from_exception,
)
from ..types import ScanResult, SecurityFinding


def _get_credential_report(iam) -> ScanResult:
    """Generate and return the IAM credential report as a list of row dicts.

    Polls generate_credential_report until State == COMPLETE (max 10 x 2 s).
    Returns an empty list on timeout or API error.
    """
    try:
        for _ in range(10):
            if iam.generate_credential_report().get("State") == "COMPLETE":
                break
            time.sleep(2)
        else:
            logger.error("IAM credential report did not complete in time")
            return error_result(
                data=[],
                errors=[
                    {
                        "code": "CredentialReportTimeout",
                        "message": "IAM credential report did not complete in time",
                        "service": "iam",
                        "operation": "GenerateCredentialReport",
                        "retryable": True,
                    }
                ],
            )
        report = iam.get_credential_report()
        content = report["Content"]
        if isinstance(content, bytes):
            content = content.decode("utf-8")
        return ok_result(list(csv.DictReader(io.StringIO(content))))
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to get IAM credential report: {e}")
        return error_result(
            data=[],
            errors=[
                scan_error_from_exception(
                    service="iam",
                    operation="GetCredentialReport",
                    exc=e,
                )
            ],
        )


def _check_root_mfa() -> ScanResult:
    """Check whether the root account has MFA enabled."""
    try:
        iam = get_aws_client("iam")
        summary = iam.get_account_summary().get("SummaryMap", {})
        if not summary.get("AccountMFAEnabled", 0):
            return ok_result(
                [
                    {
                        "severity": "HIGH",
                        "resource": "root",
                        "finding": "Root account does not have MFA enabled",
                    }
                ]
            )
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to check root MFA: {e}")
        return error_result(
            data=[],
            errors=[
                scan_error_from_exception(
                    service="iam",
                    operation="GetAccountSummary",
                    exc=e,
                )
            ],
        )
    return ok_result([])


_SENSITIVE_PORTS: dict[int, str] = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
}


def _check_open_security_groups(ec2, region: str | None = None) -> ScanResult:
    """Flag SGs that allow unrestricted ingress on sensitive ports or all traffic.

    Checks (in priority order per permission rule):
      - All-traffic rules (IpProtocol="-1"): CRITICAL
      - All-ports rules (0-65535): CRITICAL
      - Specific ports (SSH/22, RDP/3389, MySQL/3306, PostgreSQL/5432): HIGH
    """
    findings: list[SecurityFinding] = []
    try:
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page.get("SecurityGroups", []):
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
                    cidr_str = ", ".join(open_cidrs)
                    sg_name = sg.get("GroupName", sg["GroupId"])
                    # All-traffic rule (protocol -1 = all protocols/ports)
                    if perm.get("IpProtocol") == "-1":
                        findings.append(
                            {
                                "severity": "CRITICAL",
                                "resource": sg["GroupId"],
                                "finding": (
                                    f"Security group '{sg_name}' allows all traffic "
                                    f"from {cidr_str}"
                                ),
                            }
                        )
                        continue
                    # All-ports TCP/UDP rule (0-65535)
                    if from_port == 0 and to_port == 65535:
                        findings.append(
                            {
                                "severity": "CRITICAL",
                                "resource": sg["GroupId"],
                                "finding": (
                                    f"Security group '{sg_name}' allows all ports "
                                    f"from {cidr_str}"
                                ),
                            }
                        )
                        continue
                    # Specific sensitive ports
                    for port, service in _SENSITIVE_PORTS.items():
                        if from_port <= port <= to_port:
                            findings.append(
                                {
                                    "severity": "HIGH",
                                    "resource": sg["GroupId"],
                                    "finding": (
                                        f"Security group '{sg_name}' allows port {port} ({service}) "
                                        f"from {cidr_str}"
                                    ),
                                }
                            )
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to check security groups: {e}")
        return error_result(
            data=findings,
            errors=[
                scan_error_from_exception(
                    service="ec2",
                    operation="DescribeSecurityGroups",
                    exc=e,
                    region=region,
                )
            ],
        )
    return ok_result(findings)


def _check_iam_users_mfa(report: ScanResult | None = None) -> ScanResult:
    """Flag IAM users with console access (password_enabled) but no MFA device.

    Uses the IAM credential report (2 API calls) instead of per-user
    get_login_profile + list_mfa_devices (2N calls).
    Pass a pre-fetched report to avoid duplicate API calls when multiple checks
    share the same credential report.
    """
    findings: list[SecurityFinding] = []
    try:
        if report is None:
            iam = get_aws_client("iam")
            report = _get_credential_report(iam)
        for row in report["data"]:
            username = row.get("user", "")
            if username == "<root_account>":
                continue
            if (
                row.get("password_enabled") == "true"
                and row.get("mfa_active") == "false"
            ):
                findings.append(
                    {
                        "severity": "HIGH",
                        "resource": username,
                        "finding": f"IAM user '{username}' has console access but no MFA device",
                    }
                )
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to check IAM user MFA: {e}")
        return error_result(
            data=findings,
            errors=[
                scan_error_from_exception(
                    service="iam",
                    operation="GenerateCredentialReport",
                    exc=e,
                )
            ],
        )
    return error_result(data=findings, errors=report["errors"])


def _check_iam_key_age(report: ScanResult | None = None) -> ScanResult:
    """Flag active IAM access keys older than 90 days.

    Uses the IAM credential report (2 API calls) instead of per-user
    list_access_keys (N calls, one per user).
    Pass a pre-fetched report to avoid duplicate API calls when multiple checks
    share the same credential report.
    """
    findings: list[SecurityFinding] = []
    try:
        if report is None:
            iam = get_aws_client("iam")
            report = _get_credential_report(iam)
        now = datetime.now(UTC)
        for row in report["data"]:
            username = row.get("user", "")
            if username == "<root_account>":
                continue
            for key_num in ("1", "2"):
                if row.get(f"access_key_{key_num}_active") != "true":
                    continue
                rotated = row.get(f"access_key_{key_num}_last_rotated", "N/A")
                if rotated in ("N/A", "no_information", ""):
                    continue
                age = (now - datetime.fromisoformat(rotated)).days
                if age > 90:
                    findings.append(
                        {
                            "severity": "MEDIUM",
                            "resource": username,
                            "finding": f"Access key {key_num} for '{username}' is {age} days old (>90 days)",
                        }
                    )
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to check IAM access key age: {e}")
        return error_result(
            data=findings,
            errors=[
                scan_error_from_exception(
                    service="iam",
                    operation="GenerateCredentialReport",
                    exc=e,
                )
            ],
        )
    return error_result(data=findings, errors=report["errors"])


def _check_public_rds(rdss: list[dict[str, Any]]) -> ScanResult:
    """Flag RDS instances that are publicly accessible."""
    return ok_result(
        [
            {
                "severity": "HIGH",
                "resource": db["DBInstanceIdentifier"],
                "finding": f"RDS instance is publicly accessible (engine: {db['Engine']}, class: {db['Class']})",
            }
            for db in rdss
            if db.get("PubliclyAccessible")
        ]
    )


def _check_s3_block_public_access(s3s: list[dict[str, Any]]) -> ScanResult:
    """Flag S3 buckets that do not have Block Public Access fully enabled."""
    findings: list[SecurityFinding] = []
    errors = []
    try:
        s3 = get_aws_client("s3")
        for bucket in s3s:
            name = bucket.get("BucketName")
            if not name:
                continue
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
                else:
                    errors.append(
                        scan_error_from_exception(
                            service="s3",
                            operation="GetPublicAccessBlock",
                            exc=e,
                        )
                    )
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to check S3 public access: {e}")
        errors.append(
            scan_error_from_exception(
                service="s3",
                operation="GetPublicAccessBlock",
                exc=e,
            )
        )
    return error_result(data=findings, errors=errors)


def _check_s3_encryption(s3s: list[dict[str, Any]]) -> ScanResult:
    """Flag S3 buckets that have no default server-side encryption rule."""
    findings: list[SecurityFinding] = []
    errors = []
    try:
        s3 = get_aws_client("s3")
        for bucket in s3s:
            name = bucket.get("BucketName")
            if not name:
                continue
            try:
                rules = (
                    s3.get_bucket_encryption(Bucket=name)
                    .get("ServerSideEncryptionConfiguration", {})
                    .get("Rules", [])
                )
                if not rules:
                    raise ClientError(
                        {
                            "Error": {
                                "Code": "ServerSideEncryptionConfigurationNotFoundError",
                                "Message": "",
                            }
                        },
                        "GetBucketEncryption",
                    )
            except ClientError as e:
                if (
                    e.response["Error"]["Code"]
                    == "ServerSideEncryptionConfigurationNotFoundError"
                ):
                    findings.append(
                        {
                            "severity": "MEDIUM",
                            "resource": name,
                            "finding": "S3 bucket has no default server-side encryption rule",
                            "remediation_type": "s3_default_encryption",
                            "remediation_label": "Enable S3 Default Encryption",
                        }
                    )
                else:
                    errors.append(
                        scan_error_from_exception(
                            service="s3",
                            operation="GetBucketEncryption",
                            exc=e,
                        )
                    )
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to check S3 encryption: {e}")
        errors.append(
            scan_error_from_exception(
                service="s3",
                operation="GetBucketEncryption",
                exc=e,
            )
        )
    return error_result(data=findings, errors=errors)


def _check_imdsv2(ec2, region: str | None = None) -> ScanResult:
    """Flag EC2 instances that still allow IMDSv1 (HttpTokens != required)."""
    findings: list[SecurityFinding] = []
    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for res in page.get("Reservations", []):
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
                                "remediation_type": "enforce_imdsv2",
                                "remediation_label": "Enforce IMDSv2",
                            }
                        )
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to check IMDSv2 enforcement: {e}")
        return error_result(
            data=findings,
            errors=[
                scan_error_from_exception(
                    service="ec2",
                    operation="DescribeInstances",
                    exc=e,
                    region=region,
                )
            ],
        )
    return ok_result(findings)


def _check_ebs_encryption(ec2, region: str | None = None) -> ScanResult:
    """Flag EBS volumes that are not encrypted at rest."""
    findings: list[SecurityFinding] = []
    try:
        paginator = ec2.get_paginator("describe_volumes")
        for page in paginator.paginate():
            for vol in page.get("Volumes", []):
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
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to check EBS encryption: {e}")
        return error_result(
            data=findings,
            errors=[
                scan_error_from_exception(
                    service="ec2",
                    operation="DescribeVolumes",
                    exc=e,
                    region=region,
                )
            ],
        )
    return ok_result(findings)


def _check_cloudtrail(ct, region: str | None = None) -> ScanResult:
    """Check that CloudTrail is configured and actively logging in this region."""
    findings: list[SecurityFinding] = []
    try:
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        if not trails:
            return ok_result(
                [
                    {
                        "severity": "HIGH",
                        "resource": "cloudtrail",
                        "finding": "No CloudTrail trails configured in this region",
                    }
                ]
            )
        for trail in trails:
            status = ct.get_trail_status(Name=trail["TrailARN"])
            if not status.get("IsLogging"):
                findings.append(
                    {
                        "severity": "HIGH",
                        "resource": trail.get("Name"),
                        "finding": "CloudTrail trail exists but is not actively logging",
                        "remediation_type": "enable_cloudtrail_logging",
                        "remediation_label": "Start CloudTrail Logging",
                    }
                )
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to check CloudTrail: {e}")
        return error_result(
            data=findings,
            errors=[
                scan_error_from_exception(
                    service="cloudtrail",
                    operation="DescribeTrails",
                    exc=e,
                    region=region,
                )
            ],
        )
    return ok_result(findings)


def _check_guardduty_enabled(gd, region: str | None = None) -> ScanResult:
    """Check that GuardDuty is enabled in this region."""
    try:
        detector_ids = gd.list_detectors().get("DetectorIds", [])
        if not detector_ids:
            return ok_result(
                [
                    {
                        "severity": "HIGH",
                        "resource": "guardduty",
                        "finding": "GuardDuty is not enabled in this region",
                        "remediation_type": "enable_guardduty",
                        "remediation_label": "Enable GuardDuty",
                    }
                ]
            )
        for detector_id in detector_ids:
            det = gd.get_detector(DetectorId=detector_id)
            if det.get("Status") != "ENABLED":
                return ok_result(
                    [
                        {
                            "severity": "HIGH",
                            "resource": detector_id,
                            "finding": "GuardDuty detector exists but is not enabled",
                            "remediation_type": "enable_guardduty",
                            "remediation_label": "Enable GuardDuty",
                        }
                    ]
                )
    except (ClientError, BotoCoreError) as e:
        error = scan_error_from_exception(
            service="guardduty",
            operation="ListDetectors",
            exc=e,
            region=region,
        )
        logger.error(
            f"Failed to check GuardDuty: {e}",
            display=not is_expected_unavailable_scan_error(error),
        )
        return error_result(
            data=[],
            errors=[error],
        )
    return ok_result([])


def _check_kms_rotation(region: str | None = None) -> ScanResult:
    """Flag customer-managed KMS symmetric keys with automatic rotation disabled.

    Only checks keys with KeyManager=CUSTOMER, KeyState=Enabled, and
    KeySpec=SYMMETRIC_DEFAULT. AWS-managed keys and asymmetric keys are skipped
    (asymmetric keys do not support automatic rotation via the API).
    """
    findings: list[SecurityFinding] = []
    errors: list[Any] = []
    try:
        kms = get_client("kms", region)
        paginator = kms.get_paginator("list_keys")
        for page in paginator.paginate():
            for key_entry in page.get("Keys", []):
                key_id = key_entry["KeyId"]
                try:
                    meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
                except (ClientError, BotoCoreError) as e:
                    logger.error(f"Failed to describe KMS key {key_id}: {e}")
                    errors.append(
                        scan_error_from_exception(
                            service="kms", operation="DescribeKey", exc=e, region=region
                        )
                    )
                    continue
                if meta.get("KeyManager") != "CUSTOMER":
                    continue
                if meta.get("KeyState") != "Enabled":
                    continue
                if meta.get("KeySpec", "SYMMETRIC_DEFAULT") != "SYMMETRIC_DEFAULT":
                    continue
                try:
                    rotation = kms.get_key_rotation_status(KeyId=key_id)
                    if not rotation.get("KeyRotationEnabled"):
                        findings.append(
                            {
                                "severity": "MEDIUM",
                                "resource": key_id,
                                "finding": (
                                    f"KMS CMK '{key_id}' does not have automatic"
                                    " key rotation enabled"
                                ),
                            }
                        )
                except (ClientError, BotoCoreError) as e:
                    logger.error(
                        f"Failed to check rotation status for KMS key {key_id}: {e}"
                    )
                    errors.append(
                        scan_error_from_exception(
                            service="kms",
                            operation="GetKeyRotationStatus",
                            exc=e,
                            region=region,
                        )
                    )
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to list KMS keys: {e}")
        return error_result(
            data=findings,
            errors=[
                scan_error_from_exception(
                    service="kms", operation="ListKeys", exc=e, region=region
                )
            ],
        )
    return error_result(data=findings, errors=errors) if errors else ok_result(findings)


def _check_vpc_flow_logs(ec2, region: str | None = None) -> ScanResult:
    """Flag VPCs that do not have VPC Flow Logs enabled."""
    findings: list[SecurityFinding] = []
    try:
        vpcs = ec2.describe_vpcs(
            Filters=[{"Name": "state", "Values": ["available"]}]
        ).get("Vpcs", [])
        for vpc in vpcs:
            vpc_id = vpc["VpcId"]
            flow_logs = ec2.describe_flow_logs(
                Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
            ).get("FlowLogs", [])
            if not flow_logs:
                findings.append(
                    {
                        "severity": "MEDIUM",
                        "resource": vpc_id,
                        "finding": f"VPC {vpc_id} has no flow logs enabled",
                        "remediation_type": "vpc_flow_logs",
                        "remediation_label": f"Enable flow logs for {vpc_id}",
                    }
                )
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to check VPC flow logs: {e}")
        return error_result(
            data=findings,
            errors=[
                scan_error_from_exception(
                    service="ec2",
                    operation="DescribeVpcs",
                    exc=e,
                    region=region,
                )
            ],
        )
    return ok_result(findings)


def run_security_scan(
    s3s: list[dict[str, Any]],
    rdss: list[dict[str, Any]],
    region: str | None = None,
    include_global: bool = True,
) -> ScanResult:
    """Run security checks and return a unified list of findings.

    include_global controls whether account-wide checks (root MFA, IAM key age,
    S3 block public access) are executed.  Set to False when looping over
    multiple regions to avoid duplicate global findings.
    """

    def _cl(svc):
        return get_client(svc, region)

    results: list[ScanResult] = []
    if include_global:
        results.append(_check_root_mfa())
        # Generate the credential report once and share it between both checks
        # to avoid 2x the polling overhead (up to 40 s each).
        _shared_cred_report = _get_credential_report(get_aws_client("iam"))
        results.append(_check_iam_users_mfa(_shared_cred_report))
        results.append(_check_iam_key_age(_shared_cred_report))
        results.append(_check_s3_block_public_access(s3s))
        results.append(_check_s3_encryption(s3s))
    ec2 = _cl("ec2")
    results.append(_check_open_security_groups(ec2, region))
    results.append(_check_imdsv2(ec2, region))
    results.append(_check_ebs_encryption(ec2, region))
    results.append(_check_public_rds(rdss))
    results.append(_check_cloudtrail(_cl("cloudtrail"), region))
    results.append(_check_guardduty_enabled(_cl("guardduty"), region))
    results.append(_check_kms_rotation(region))
    results.append(_check_vpc_flow_logs(ec2, region))
    return merge_list_results(results)
