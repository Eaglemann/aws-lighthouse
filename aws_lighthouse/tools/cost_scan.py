import os
from datetime import UTC, datetime, timedelta
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from ..auth import get_client
from ..logger import logger
from ..scan_contract import (
    error_result,
    merge_list_results,
    ok_result,
    scan_error_from_exception,
)
from ..types import CostFinding

_SNAPSHOT_AGE_DAYS = int(os.getenv("LIGHTHOUSE_SNAPSHOT_AGE_DAYS", "90"))


def _check_unattached_ebs(ec2, region: str | None = None):
    """Flag EBS volumes that are not attached to any instance."""
    findings: list[CostFinding] = []
    try:
        paginator = ec2.get_paginator("describe_volumes")
        for page in paginator.paginate(
            Filters=[{"Name": "status", "Values": ["available"]}]
        ):
            for vol in page.get("Volumes", []):
                size = vol.get("Size", 0)
                vol_type = vol.get("VolumeType", "unknown")
                findings.append(
                    {
                        "resource": vol["VolumeId"],
                        "finding": f"Unattached EBS volume ({size} GB {vol_type}) — paying for storage with no instance",
                        "remediation_type": "delete_ebs_volume",
                        "remediation_label": "Delete EBS Volume",
                    }
                )
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to check unattached EBS volumes: {e}")
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


def _check_stopped_ec2(ec2, region: str | None = None):
    """Flag EC2 instances that are stopped but still incurring EBS costs."""
    findings: list[CostFinding] = []
    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}]
        ):
            for reservation in page.get("Reservations", []):
                for inst in reservation.get("Instances", []):
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
                            "resource": inst["InstanceId"],
                            "finding": f"Stopped EC2 instance '{name}' ({inst.get('InstanceType')}) — EBS volumes still billed",
                        }
                    )
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to check stopped EC2 instances: {e}")
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


def _check_old_snapshots(ec2, region: str | None = None):
    """Flag owned EBS snapshots older than 90 days."""
    findings: list[CostFinding] = []
    try:
        paginator = ec2.get_paginator("describe_snapshots")
        cutoff = datetime.now(UTC) - timedelta(days=_SNAPSHOT_AGE_DAYS)
        for page in paginator.paginate(OwnerIds=["self"]):
            for snap in page.get("Snapshots", []):
                start_time = snap.get("StartTime")
                if start_time and start_time < cutoff:
                    age = (datetime.now(UTC) - start_time).days
                    size = snap.get("VolumeSize", 0)
                    description = snap.get("Description", "")
                    findings.append(
                        {
                            "resource": snap["SnapshotId"],
                            "finding": f"EBS snapshot is {age} days old ({size} GB) — '{description}'",
                        }
                    )
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to check old EBS snapshots: {e}")
        return error_result(
            data=findings,
            errors=[
                scan_error_from_exception(
                    service="ec2",
                    operation="DescribeSnapshots",
                    exc=e,
                    region=region,
                )
            ],
        )
    return ok_result(findings)


def _check_idle_nat_gateways(ec2, cw, region: str | None = None):
    """Flag NAT Gateways with zero outbound traffic over the past 7 days."""
    findings: list[CostFinding] = []
    try:
        kwargs: dict[str, object] = {
            "Filter": [{"Name": "state", "Values": ["available"]}]
        }
        while True:
            resp = ec2.describe_nat_gateways(**kwargs)
            for gw in resp.get("NatGateways", []):
                nat_id = gw["NatGatewayId"]
                metrics = cw.get_metric_statistics(
                    Namespace="AWS/NatGateway",
                    MetricName="BytesOutToDestination",
                    Dimensions=[{"Name": "NatGatewayId", "Value": nat_id}],
                    StartTime=datetime.now(UTC) - timedelta(days=7),
                    EndTime=datetime.now(UTC),
                    Period=604_800,
                    Statistics=["Sum"],
                )
                total_bytes = sum(dp["Sum"] for dp in metrics.get("Datapoints", []))
                if total_bytes == 0:
                    findings.append(
                        {
                            "resource": nat_id,
                            "finding": f"NAT Gateway {nat_id} has had no traffic in 7 days",
                            "remediation_type": "delete_nat_gateway",
                            "remediation_label": f"Delete idle NAT Gateway {nat_id}",
                            "region": region or "",
                        }
                    )
            token = resp.get("NextToken")
            if not token:
                break
            kwargs["NextToken"] = token
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to check idle NAT Gateways: {e}")
        return error_result(
            data=findings,
            errors=[
                scan_error_from_exception(
                    service="ec2",
                    operation="DescribeNatGateways",
                    exc=e,
                    region=region,
                )
            ],
        )
    return ok_result(findings)


def _check_idle_load_balancers(elbv2, cw, region: str | None = None):
    """Flag ALBs/NLBs with zero requests over the past 7 days."""
    _NS_MAP = {
        "application": "AWS/ApplicationELB",
        "network": "AWS/NetworkELB",
    }
    findings: list[CostFinding] = []
    try:
        kwargs: dict[str, object] = {}
        while True:
            resp = elbv2.describe_load_balancers(**kwargs)
            for lb in resp.get("LoadBalancers", []):
                lb_type = lb.get("Type", "")
                if lb_type not in _NS_MAP:
                    continue
                if lb.get("State", {}).get("Code") != "active":
                    continue
                namespace = _NS_MAP[lb_type]
                lb_dimension = lb["LoadBalancerArn"].split("loadbalancer/", 1)[-1]
                metrics = cw.get_metric_statistics(
                    Namespace=namespace,
                    MetricName="RequestCount",
                    Dimensions=[{"Name": "LoadBalancer", "Value": lb_dimension}],
                    StartTime=datetime.now(UTC) - timedelta(days=7),
                    EndTime=datetime.now(UTC),
                    Period=604_800,
                    Statistics=["Sum"],
                )
                total_requests = sum(dp["Sum"] for dp in metrics.get("Datapoints", []))
                if total_requests == 0:
                    findings.append(
                        {
                            "resource": lb["LoadBalancerName"],
                            "finding": (
                                f"Load balancer {lb['LoadBalancerName']} ({lb_type})"
                                " has had no requests in 7 days"
                            ),
                            "remediation_type": "delete_load_balancer",
                            "remediation_label": f"Delete idle load balancer {lb['LoadBalancerName']}",
                            "region": region or "",
                        }
                    )
            token = resp.get("NextMarker")
            if not token:
                break
            kwargs["Marker"] = token
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to check idle load balancers: {e}")
        return error_result(
            data=findings,
            errors=[
                scan_error_from_exception(
                    service="elbv2",
                    operation="DescribeLoadBalancers",
                    exc=e,
                    region=region,
                )
            ],
        )
    return ok_result(findings)


def _check_idle_rds_instances(rds, cw, region: str | None = None):
    """Flag RDS instances with no database connections in the past 7 days."""
    findings: list[CostFinding] = []
    try:
        kwargs: dict[str, Any] = {}
        instances: list[dict[str, Any]] = []
        while True:
            resp = rds.describe_db_instances(**kwargs)
            instances.extend(resp.get("DBInstances", []))
            if "Marker" not in resp:
                break
            kwargs["Marker"] = resp["Marker"]

        for db in instances:
            if db.get("DBInstanceStatus") != "available":
                continue
            db_id = db["DBInstanceIdentifier"]
            engine = db.get("Engine", "unknown")
            metrics = cw.get_metric_statistics(
                Namespace="AWS/RDS",
                MetricName="DatabaseConnections",
                Dimensions=[{"Name": "DBInstanceIdentifier", "Value": db_id}],
                StartTime=datetime.now(UTC) - timedelta(days=7),
                EndTime=datetime.now(UTC),
                Period=604_800,
                Statistics=["Maximum"],
            )
            max_connections = max(
                (dp["Maximum"] for dp in metrics.get("Datapoints", [])), default=0
            )
            if max_connections == 0:
                findings.append(
                    {
                        "resource": db_id,
                        "finding": f"RDS instance {db_id} has had no connections in 7 days (engine: {engine})",
                        "remediation_type": "stop_rds_instance",
                        "remediation_label": f"Stop or delete idle RDS instance {db_id}",
                        "region": region or "",
                    }
                )
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to check idle RDS instances: {e}")
        return error_result(
            data=findings,
            errors=[
                scan_error_from_exception(
                    service="rds",
                    operation="DescribeDBInstances",
                    exc=e,
                    region=region,
                )
            ],
        )
    return ok_result(findings)


def _check_idle_lambda_functions(lmb, cw, region: str | None = None):
    """Flag Lambda functions with zero invocations over the past 30 days."""
    findings: list[CostFinding] = []
    try:
        kwargs: dict[str, Any] = {}
        functions: list[dict[str, Any]] = []
        while True:
            resp = lmb.list_functions(**kwargs)
            functions.extend(resp.get("Functions", []))
            if "NextMarker" not in resp:
                break
            kwargs["Marker"] = resp["NextMarker"]

        for fn in functions:
            fn_name = fn["FunctionName"]
            runtime = fn.get("Runtime", "unknown")
            metrics = cw.get_metric_statistics(
                Namespace="AWS/Lambda",
                MetricName="Invocations",
                Dimensions=[{"Name": "FunctionName", "Value": fn_name}],
                StartTime=datetime.now(UTC) - timedelta(days=30),
                EndTime=datetime.now(UTC),
                Period=2_592_000,  # 30 days in seconds
                Statistics=["Sum"],
            )
            total_invocations = sum(dp["Sum"] for dp in metrics.get("Datapoints", []))
            if total_invocations == 0:
                findings.append(
                    {
                        "resource": fn_name,
                        "finding": f"Lambda function {fn_name} has not been invoked in 30 days (runtime: {runtime})",
                        "remediation_type": "delete_lambda_function",
                        "remediation_label": f"Delete idle Lambda function {fn_name}",
                        "region": region or "",
                    }
                )
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to check idle Lambda functions: {e}")
        return error_result(
            data=findings,
            errors=[
                scan_error_from_exception(
                    service="lambda",
                    operation="ListFunctions",
                    exc=e,
                    region=region,
                )
            ],
        )
    return ok_result(findings)


def _check_log_group_retention(logs_client, region: str | None = None):
    """Flag CloudWatch log groups that have no retention policy (logs kept forever)."""
    findings: list[CostFinding] = []
    try:
        kwargs: dict[str, Any] = {}
        while True:
            resp = logs_client.describe_log_groups(**kwargs)
            for lg in resp.get("logGroups", []):
                if "retentionInDays" not in lg:
                    name = lg["logGroupName"]
                    findings.append(
                        {
                            "resource": name,
                            "finding": f"CloudWatch log group {name} has no retention policy (logs kept forever)",
                            "remediation_type": "set_log_retention",
                            "remediation_label": f"Set retention policy for {name}",
                            "region": region or "",
                        }
                    )
            token = resp.get("nextToken")
            if not token:
                break
            kwargs["nextToken"] = token
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to check log group retention: {e}")
        return error_result(
            data=findings,
            errors=[
                scan_error_from_exception(
                    service="logs",
                    operation="DescribeLogGroups",
                    exc=e,
                    region=region,
                )
            ],
        )
    return ok_result(findings)


def _check_unassociated_eips(ec2, region: str | None = None):
    """Flag Elastic IPs that are allocated but not associated with any resource."""
    findings: list[CostFinding] = []
    try:
        response = ec2.describe_addresses()
        for addr in response.get("Addresses", []):
            if "AssociationId" not in addr:
                findings.append(
                    {
                        "resource": addr.get("AllocationId", addr.get("PublicIp")),
                        "finding": f"Elastic IP {addr['PublicIp']} is allocated but not associated — ~$0.005/hr wasted",
                        "remediation_type": "release_eip",
                        "remediation_label": "Release Elastic IP",
                    }
                )
    except (ClientError, BotoCoreError) as e:
        logger.error(f"Failed to check unassociated Elastic IPs: {e}")
        return error_result(
            data=findings,
            errors=[
                scan_error_from_exception(
                    service="ec2",
                    operation="DescribeAddresses",
                    exc=e,
                    region=region,
                )
            ],
        )
    return ok_result(findings)


def run_cost_scan(region: str | None = None):
    """Run all cost waste checks and return a unified list of findings."""
    ec2 = get_client("ec2", region)
    cw = get_client("cloudwatch", region)
    elbv2 = get_client("elbv2", region)
    rds = get_client("rds", region)
    lmb = get_client("lambda", region)
    logs = get_client("logs", region)
    return merge_list_results(
        [
            _check_unattached_ebs(ec2, region),
            _check_stopped_ec2(ec2, region),
            _check_old_snapshots(ec2, region),
            _check_unassociated_eips(ec2, region),
            _check_idle_nat_gateways(ec2, cw, region),
            _check_idle_load_balancers(elbv2, cw, region),
            _check_idle_rds_instances(rds, cw, region),
            _check_idle_lambda_functions(lmb, cw, region),
            _check_log_group_retention(logs, region),
        ]
    )
