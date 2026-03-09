"""
Security Group Blast Radius — enriches open-SG findings with:
  - Attached resources (EC2 / RDS / Lambda / Other) via describe_network_interfaces
  - Public IP exposure
  - VPC Internet Gateway presence
  - CloudTrail SSH/RDP connection history (last 30 days)
  - Exposure verdict: INTERNET_EXPOSED | PRIVATE | UNKNOWN
"""

import json
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime, timedelta
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from ..auth import get_client
from ..logger import logger
from ..scan_contract import error_result, ok_result, scan_error_from_exception
from ..types import ScanResult, SGAttachedResource, SGBlastRadius


def _get_attached_resources(ec2: Any, sg_id: str) -> list[SGAttachedResource]:
    """Return all resources using this SG, discovered via network interfaces.

    Uses the describe_network_interfaces paginator to find every ENI with
    the given SG, then classifies each ENI by type (EC2 / RDS / Lambda / Other).
    Results are deduplicated by resource_id.
    """
    resources: dict[str, SGAttachedResource] = {}
    try:
        paginator = ec2.get_paginator("describe_network_interfaces")
        for page in paginator.paginate(
            Filters=[{"Name": "group-id", "Values": [sg_id]}]
        ):
            for eni in page.get("NetworkInterfaces", []):
                interface_type = eni.get("InterfaceType", "")
                description = eni.get("Description", "")
                attachment = eni.get("Attachment", {})
                association = eni.get("Association", {})

                # Classify resource type
                if interface_type == "lambda_function":
                    resource_type = "Lambda"
                    resource_id = eni.get("NetworkInterfaceId", "")
                elif (
                    description.startswith("RDSNetworkInterface")
                    or "rds" in description.lower()
                ):
                    resource_type = "RDS"
                    resource_id = eni.get("NetworkInterfaceId", "")
                elif attachment.get("InstanceId"):
                    resource_type = "EC2"
                    resource_id = attachment["InstanceId"]
                else:
                    resource_type = "Other"
                    resource_id = eni.get("NetworkInterfaceId", "")

                if not resource_id or resource_id in resources:
                    continue

                resource_name = description[:50] if description else resource_id
                private_ip = eni.get("PrivateIpAddress", "")
                public_ip = association.get("PublicIp") if association else None

                resources[resource_id] = {
                    "resource_type": resource_type,
                    "resource_id": resource_id,
                    "resource_name": resource_name,
                    "private_ip": private_ip,
                    "public_ip": public_ip,
                }
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to describe network interfaces for {sg_id}: {e}")
    return list(resources.values())


def _get_sg_vpc(ec2: Any, sg_id: str) -> str | None:
    """Return the VPC ID for this security group, or None on failure."""
    try:
        resp = ec2.describe_security_groups(GroupIds=[sg_id])
        sgs = resp.get("SecurityGroups", [])
        if sgs:
            return sgs[0].get("VpcId") or None
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to get VPC for SG {sg_id}: {e}")
    return None


def _get_sg_name(ec2: Any, sg_id: str) -> str:
    """Return the GroupName for this security group, or sg_id on failure."""
    try:
        resp = ec2.describe_security_groups(GroupIds=[sg_id])
        sgs = resp.get("SecurityGroups", [])
        if sgs:
            return str(sgs[0].get("GroupName", sg_id))
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to get name for SG {sg_id}: {e}")
    return sg_id


def _check_igw(ec2: Any, vpc_id: str) -> bool:
    """Return True if the given VPC has an Internet Gateway attached."""
    try:
        resp = ec2.describe_internet_gateways(
            Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}]
        )
        return bool(resp.get("InternetGateways"))
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to check IGW for VPC {vpc_id}: {e}")
        return False


def _get_cloudtrail_connections(
    ct: Any, sg_id: str, lookback_days: int = 30
) -> tuple[int, list[str]]:
    """Return (event_count, top_3_source_ips) from CloudTrail for this SG.

    Looks up AuthorizeSecurityGroupIngress and RevokeSecurityGroupIngress events
    to surface recent SG modification history. Actual SSH/RDP connections would
    require VPC Flow Logs (out of scope for the MVP).

    The source IP is the API caller's IP (who modified the rule), not the
    connecting host — this is the best signal available from CloudTrail alone.
    """
    event_names = ["AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress"]
    end_time = datetime.now(UTC)
    start_time = end_time - timedelta(days=lookback_days)

    all_events: list[dict] = []
    for event_name in event_names:
        kwargs: dict = {}
        collected = 0
        while collected < 20:
            try:
                resp = ct.lookup_events(
                    LookupAttributes=[
                        {"AttributeKey": "EventName", "AttributeValue": event_name}
                    ],
                    StartTime=start_time,
                    EndTime=end_time,
                    **kwargs,
                )
            except (ClientError, BotoCoreError) as e:
                logger.error(f"CloudTrail lookup failed for {event_name}: {e}")
                break

            page_events = resp.get("Events", [])
            # Filter to events that mention this sg_id
            for ev in page_events:
                ct_event_str = ev.get("CloudTrailEvent", "{}")
                try:
                    ct_detail = json.loads(ct_event_str)
                except json.JSONDecodeError:
                    ct_detail = {}
                req_params = ct_detail.get("requestParameters", {}) or {}
                group_id = str(req_params.get("groupId", ""))
                if sg_id in group_id or sg_id in ct_event_str:
                    all_events.append(ev)
                    collected += 1

            if "NextToken" not in resp or len(all_events) >= 20:
                break
            kwargs["NextToken"] = resp["NextToken"]

    # Extract source IPs from CloudTrailEvent JSON
    source_ips: list[str] = []
    for ev in all_events:
        ct_event_str = ev.get("CloudTrailEvent", "{}")
        try:
            ct_detail = json.loads(ct_event_str)
        except json.JSONDecodeError:
            continue
        ip = ct_detail.get("sourceIPAddress", "")
        if ip and not ip.startswith("AWS"):
            source_ips.append(ip)

    counter = Counter(source_ips)
    top_ips = [ip for ip, _ in counter.most_common(3)]
    return len(all_events), top_ips


def _analyze_sg(
    ec2: Any,
    ct: Any,
    sg_id: str,
    region: str | None,
    lookback_days: int,
) -> SGBlastRadius:
    """Analyse one SG and return its blast-radius dict."""
    sg_name = _get_sg_name(ec2, sg_id)
    attached_resources = _get_attached_resources(ec2, sg_id)

    vpc_id = _get_sg_vpc(ec2, sg_id)
    has_igw = _check_igw(ec2, vpc_id) if vpc_id else False

    has_public_ip = any(r["public_ip"] for r in attached_resources)

    if has_public_ip and has_igw:
        exposure = "INTERNET_EXPOSED"
    elif not has_public_ip:
        exposure = "PRIVATE"
    else:
        exposure = "UNKNOWN"

    recent_connection_count, top_source_ips = _get_cloudtrail_connections(
        ct, sg_id, lookback_days
    )

    return {
        "sg_id": sg_id,
        "sg_name": sg_name,
        "region": region,
        "attached_resources": attached_resources,
        "has_public_ip": has_public_ip,
        "has_igw": has_igw,
        "exposure": exposure,
        "recent_connection_count": recent_connection_count,
        "top_source_ips": top_source_ips,
    }


def get_sg_blast_radius(
    sg_ids: list[str],
    region: str | None = None,
    lookback_days: int = 30,
) -> ScanResult:
    """Analyse the blast radius of the given open security groups.

    For each SG ID, determines:
    - Which EC2 / RDS / Lambda resources are attached (via ENIs)
    - Whether any of those resources have a public IP
    - Whether the SG's VPC has an Internet Gateway
    - Recent CloudTrail modification events (AuthorizeSecurityGroupIngress /
      RevokeSecurityGroupIngress) as a proxy for rule-change history
    - An exposure verdict: INTERNET_EXPOSED | PRIVATE | UNKNOWN

    sg_ids is deduplicated before scanning; an empty list returns ok_result([]).
    """
    unique_ids = list(dict.fromkeys(sg_ids))  # preserves order, deduplicates
    if not unique_ids:
        return ok_result([])

    try:
        ec2 = get_client("ec2", region)
        ct = get_client("cloudtrail", region)
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to initialise clients for SG blast radius: {e}")
        return error_result(
            data=[],
            errors=[
                scan_error_from_exception(
                    service="ec2",
                    operation="CreateClient",
                    exc=e,
                    region=region,
                )
            ],
        )

    results: list[SGBlastRadius] = []
    errors = []

    with ThreadPoolExecutor(max_workers=min(len(unique_ids), 5)) as executor:
        future_to_sg = {
            executor.submit(_analyze_sg, ec2, ct, sg_id, region, lookback_days): sg_id
            for sg_id in unique_ids
        }
        for future in as_completed(future_to_sg):
            sg_id = future_to_sg[future]
            try:
                results.append(future.result())
            except (ClientError, BotoCoreError) as e:
                logger.error(f"Blast radius analysis failed for {sg_id}: {e}")
                errors.append(
                    scan_error_from_exception(
                        service="ec2",
                        operation="DescribeNetworkInterfaces",
                        exc=e,
                        region=region,
                    )
                )
            except Exception as e:  # noqa: BLE001
                logger.error(f"Unexpected error analysing SG {sg_id}: {e}")
                errors.append(
                    {
                        "code": type(e).__name__,
                        "message": str(e),
                        "service": "ec2",
                        "operation": "AnalyseSG",
                        "retryable": False,
                    }
                )

    # Sort by sg_id for deterministic output
    results.sort(key=lambda r: r["sg_id"])

    if errors:
        return error_result(data=results, errors=errors)
    return ok_result(results)
