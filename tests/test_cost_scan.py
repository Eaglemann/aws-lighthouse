from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

from aws_lighthouse.tools.cost_scan import (
    _check_idle_load_balancers,
    _check_idle_nat_gateways,
    _check_idle_rds_instances,
    _check_old_snapshots,
    _check_stopped_ec2,
    _check_unassociated_eips,
    _check_unattached_ebs,
    run_cost_scan,
)

MOD = "aws_lighthouse.tools.cost_scan"


def _data(result):
    assert set(result.keys()) == {"ok", "data", "errors"}
    return result["data"]


# ── _check_unattached_ebs ─────────────────────────────────────────────────────


def _make_volumes_ec2(volumes):
    ec2 = MagicMock()
    ec2.get_paginator.return_value.paginate.return_value = [{"Volumes": volumes}]
    return ec2


def test_unattached_ebs_found():
    ec2 = _make_volumes_ec2([{"VolumeId": "vol-abc", "Size": 100, "VolumeType": "gp3"}])
    result = _check_unattached_ebs(ec2)
    findings = _data(result)
    assert result["ok"] is True
    assert len(findings) == 1
    assert findings[0]["resource"] == "vol-abc"
    assert "100 GB" in findings[0]["finding"]
    assert findings[0]["remediation_type"] == "delete_ebs_volume"


def test_unattached_ebs_none():
    ec2 = _make_volumes_ec2([])
    result = _check_unattached_ebs(ec2)
    assert result["ok"] is True
    assert result["data"] == []


def test_unattached_ebs_api_error_returns_empty():
    ec2 = MagicMock()
    ec2.get_paginator.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": ""}}, "DescribeVolumes"
    )
    result = _check_unattached_ebs(ec2)
    assert result["ok"] is False
    assert result["data"] == []
    assert result["errors"][0]["code"] == "AccessDenied"


# ── _check_stopped_ec2 ────────────────────────────────────────────────────────


def _make_instances_ec2(reservations):
    ec2 = MagicMock()
    ec2.get_paginator.return_value.paginate.return_value = [
        {"Reservations": reservations}
    ]
    return ec2


def test_stopped_ec2_found():
    ec2 = _make_instances_ec2(
        [
            {
                "Instances": [
                    {
                        "InstanceId": "i-111",
                        "InstanceType": "t3.micro",
                        "Tags": [{"Key": "Name", "Value": "my-server"}],
                    }
                ]
            }
        ]
    )
    result = _check_stopped_ec2(ec2)
    findings = _data(result)
    assert len(findings) == 1
    assert findings[0]["resource"] == "i-111"
    assert "my-server" in findings[0]["finding"]


def test_stopped_ec2_uses_instance_id_when_no_name():
    ec2 = _make_instances_ec2(
        [
            {
                "Instances": [
                    {"InstanceId": "i-222", "InstanceType": "t3.small", "Tags": []}
                ]
            }
        ]
    )
    findings = _data(_check_stopped_ec2(ec2))
    assert len(findings) == 1
    assert "i-222" in findings[0]["finding"]


def test_stopped_ec2_none():
    ec2 = _make_instances_ec2([])
    result = _check_stopped_ec2(ec2)
    assert result["ok"] is True
    assert result["data"] == []


def test_stopped_ec2_api_error_returns_empty():
    ec2 = MagicMock()
    ec2.get_paginator.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": ""}}, "DescribeInstances"
    )
    result = _check_stopped_ec2(ec2)
    assert result["ok"] is False
    assert result["data"] == []
    assert result["errors"][0]["code"] == "AccessDenied"


# ── _check_old_snapshots ──────────────────────────────────────────────────────


def _make_snapshots_ec2(snapshots):
    ec2 = MagicMock()
    ec2.get_paginator.return_value.paginate.return_value = [{"Snapshots": snapshots}]
    return ec2


def test_old_snapshot_flagged():
    old = datetime.now(UTC) - timedelta(days=100)
    ec2 = _make_snapshots_ec2(
        [
            {
                "SnapshotId": "snap-abc",
                "StartTime": old,
                "VolumeSize": 50,
                "Description": "old backup",
            }
        ]
    )
    findings = _data(_check_old_snapshots(ec2))
    assert len(findings) == 1
    assert findings[0]["resource"] == "snap-abc"
    assert "50 GB" in findings[0]["finding"]


def test_recent_snapshot_not_flagged():
    recent = datetime.now(UTC) - timedelta(days=10)
    ec2 = _make_snapshots_ec2(
        [
            {
                "SnapshotId": "snap-xyz",
                "StartTime": recent,
                "VolumeSize": 20,
                "Description": "fresh",
            }
        ]
    )
    result = _check_old_snapshots(ec2)
    assert result["ok"] is True
    assert result["data"] == []


def test_old_snapshots_api_error_returns_empty():
    ec2 = MagicMock()
    ec2.get_paginator.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": ""}}, "DescribeSnapshots"
    )
    result = _check_old_snapshots(ec2)
    assert result["ok"] is False
    assert result["data"] == []
    assert result["errors"][0]["code"] == "AccessDenied"


# ── _check_unassociated_eips ──────────────────────────────────────────────────


def test_unassociated_eip_flagged():
    ec2 = MagicMock()
    ec2.describe_addresses.return_value = {
        "Addresses": [{"AllocationId": "eipalloc-123", "PublicIp": "1.2.3.4"}]
    }
    findings = _data(_check_unassociated_eips(ec2))
    assert len(findings) == 1
    assert findings[0]["resource"] == "eipalloc-123"
    assert "1.2.3.4" in findings[0]["finding"]
    assert findings[0]["remediation_type"] == "release_eip"


def test_associated_eip_not_flagged():
    ec2 = MagicMock()
    ec2.describe_addresses.return_value = {
        "Addresses": [
            {
                "AllocationId": "eipalloc-456",
                "PublicIp": "5.6.7.8",
                "AssociationId": "eipassoc-999",
            }
        ]
    }
    result = _check_unassociated_eips(ec2)
    assert result["ok"] is True
    assert result["data"] == []


def test_unassociated_eips_api_error_returns_empty():
    ec2 = MagicMock()
    ec2.describe_addresses.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": ""}}, "DescribeAddresses"
    )
    result = _check_unassociated_eips(ec2)
    assert result["ok"] is False
    assert result["data"] == []
    assert result["errors"][0]["code"] == "AccessDenied"


# ── run_cost_scan wiring ──────────────────────────────────────────────────────

MOD = "aws_lighthouse.tools.cost_scan"


def _make_clean_ec2():
    _pages = {
        "describe_volumes": {"Volumes": []},
        "describe_instances": {"Reservations": []},
        "describe_snapshots": {"Snapshots": []},
    }

    def _get_paginator(name):
        pag = MagicMock()
        pag.paginate.return_value = [_pages[name]]
        return pag

    ec2 = MagicMock()
    ec2.get_paginator.side_effect = _get_paginator
    ec2.describe_addresses.return_value = {"Addresses": []}
    ec2.describe_nat_gateways.return_value = {"NatGateways": []}
    return ec2


def _make_clean_cw():
    cw = MagicMock()
    cw.get_metric_statistics.return_value = {"Datapoints": []}
    return cw


def _make_clean_elbv2():
    elbv2 = MagicMock()
    elbv2.describe_load_balancers.return_value = {"LoadBalancers": []}
    return elbv2


def _make_clean_rds():
    rds = MagicMock()
    rds.describe_db_instances.return_value = {"DBInstances": []}
    return rds


def test_run_cost_scan_clean_returns_empty():
    ec2 = _make_clean_ec2()
    cw = _make_clean_cw()
    elbv2 = _make_clean_elbv2()
    rds = _make_clean_rds()

    def _get_client(service, region=None):
        return {"ec2": ec2, "cloudwatch": cw, "elbv2": elbv2, "rds": rds}[service]

    with patch(f"{MOD}.get_client", side_effect=_get_client):
        result = run_cost_scan()
    assert result["ok"] is True
    assert result["data"] == []


def test_run_cost_scan_aggregates_all_checks():
    _pages = {
        "describe_volumes": {
            "Volumes": [{"VolumeId": "vol-aaa", "Size": 10, "VolumeType": "gp2"}]
        },
        "describe_instances": {
            "Reservations": [
                {
                    "Instances": [
                        {"InstanceId": "i-bbb", "InstanceType": "t3.micro", "Tags": []}
                    ]
                }
            ]
        },
        "describe_snapshots": {
            "Snapshots": [
                {
                    "SnapshotId": "snap-ccc",
                    "StartTime": datetime.now(UTC) - timedelta(days=100),
                    "VolumeSize": 20,
                    "Description": "old",
                }
            ]
        },
    }

    def _get_paginator(name):
        pag = MagicMock()
        pag.paginate.return_value = [_pages[name]]
        return pag

    ec2 = MagicMock()
    ec2.get_paginator.side_effect = _get_paginator
    ec2.describe_addresses.return_value = {
        "Addresses": [{"AllocationId": "eipalloc-ddd", "PublicIp": "1.2.3.4"}]
    }
    ec2.describe_nat_gateways.return_value = {"NatGateways": []}
    cw = _make_clean_cw()
    elbv2 = _make_clean_elbv2()
    rds = _make_clean_rds()

    def _get_client(service, region=None):
        return {"ec2": ec2, "cloudwatch": cw, "elbv2": elbv2, "rds": rds}[service]

    with patch(f"{MOD}.get_client", side_effect=_get_client):
        result = run_cost_scan()

    resources = [f["resource"] for f in result["data"]]
    assert "vol-aaa" in resources
    assert "i-bbb" in resources
    assert "snap-ccc" in resources
    assert "eipalloc-ddd" in resources


# ── MED-7: env var threshold override ─────────────────────────────────────────


def test_snapshot_age_env_var_overrides_default(monkeypatch):
    """LIGHTHOUSE_SNAPSHOT_AGE_DAYS controls the snapshot staleness cutoff."""
    import importlib

    import aws_lighthouse.tools.cost_scan as mod

    monkeypatch.setenv("LIGHTHOUSE_SNAPSHOT_AGE_DAYS", "30")
    importlib.reload(mod)
    assert mod._SNAPSHOT_AGE_DAYS == 30
    # Restore default
    monkeypatch.delenv("LIGHTHOUSE_SNAPSHOT_AGE_DAYS", raising=False)
    importlib.reload(mod)
    assert mod._SNAPSHOT_AGE_DAYS == 90


# ── _check_idle_nat_gateways ────────────────────────────────────────────────


class TestCheckIdleNatGateways:
    def _make_clients(self, nat_ids, bytes_out_map=None):
        ec2 = MagicMock()
        cw = MagicMock()
        ec2.describe_nat_gateways.return_value = {
            "NatGateways": [{"NatGatewayId": nid} for nid in nat_ids]
        }
        if bytes_out_map is None:
            cw.get_metric_statistics.return_value = {"Datapoints": []}
        else:

            def get_metric_stats(**kwargs):
                nat_id = kwargs["Dimensions"][0]["Value"]
                val = bytes_out_map.get(nat_id, 0)
                return {"Datapoints": [{"Sum": val}] if val > 0 else []}

            cw.get_metric_statistics.side_effect = get_metric_stats
        return ec2, cw

    def test_no_nat_gateways_returns_empty(self):
        ec2, cw = self._make_clients([])
        assert _data(_check_idle_nat_gateways(ec2, cw, "us-east-1")) == []

    def test_nat_with_no_traffic_flagged(self):
        ec2, cw = self._make_clients(["nat-111"])
        result = _data(_check_idle_nat_gateways(ec2, cw, "us-east-1"))
        assert len(result) == 1
        assert result[0]["resource"] == "nat-111"
        assert "no traffic" in result[0]["finding"]
        assert result[0]["remediation_type"] == "delete_nat_gateway"

    def test_nat_with_traffic_not_flagged(self):
        ec2, cw = self._make_clients(["nat-222"], bytes_out_map={"nat-222": 1024})
        assert _data(_check_idle_nat_gateways(ec2, cw, "us-east-1")) == []

    def test_mixed_nat_gateways(self):
        ec2, cw = self._make_clients(
            ["nat-ok", "nat-bad"], bytes_out_map={"nat-ok": 500}
        )
        result = _data(_check_idle_nat_gateways(ec2, cw, "us-east-1"))
        assert len(result) == 1
        assert result[0]["resource"] == "nat-bad"

    def test_client_error_returns_empty(self):
        ec2 = MagicMock()
        ec2.describe_nat_gateways.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "DescribeNatGateways",
        )
        result = _check_idle_nat_gateways(ec2, MagicMock(), "us-east-1")
        assert result["ok"] is False
        assert result["data"] == []

    def test_pagination(self):
        ec2 = MagicMock()
        cw = MagicMock()
        ec2.describe_nat_gateways.side_effect = [
            {
                "NatGateways": [{"NatGatewayId": "nat-p1"}],
                "NextToken": "tok",
            },
            {"NatGateways": [{"NatGatewayId": "nat-p2"}]},
        ]
        cw.get_metric_statistics.return_value = {"Datapoints": []}
        result = _data(_check_idle_nat_gateways(ec2, cw, "us-east-1"))
        assert len(result) == 2
        resources = {f["resource"] for f in result}
        assert resources == {"nat-p1", "nat-p2"}


# ── _check_idle_load_balancers ──────────────────────────────────────────────


class TestCheckIdleLoadBalancers:
    def _make_clients(self, lbs, request_count_map=None):
        elbv2 = MagicMock()
        cw = MagicMock()
        elbv2.describe_load_balancers.return_value = {"LoadBalancers": lbs}
        if request_count_map is None:
            cw.get_metric_statistics.return_value = {"Datapoints": []}
        else:

            def get_metric_stats(**kwargs):
                lb_dim = kwargs["Dimensions"][0]["Value"]
                val = request_count_map.get(lb_dim, 0)
                return {"Datapoints": [{"Sum": val}] if val > 0 else []}

            cw.get_metric_statistics.side_effect = get_metric_stats
        return elbv2, cw

    def _lb(self, name, lb_type="application", state="active"):
        return {
            "LoadBalancerName": name,
            "LoadBalancerArn": (
                f"arn:aws:elasticloadbalancing:us-east-1:123:"
                f"loadbalancer/app/{name}/abc123"
            ),
            "Type": lb_type,
            "State": {"Code": state},
        }

    def test_no_load_balancers_returns_empty(self):
        elbv2, cw = self._make_clients([])
        assert _data(_check_idle_load_balancers(elbv2, cw, "us-east-1")) == []

    def test_idle_alb_flagged(self):
        elbv2, cw = self._make_clients([self._lb("my-alb", "application")])
        result = _data(_check_idle_load_balancers(elbv2, cw, "us-east-1"))
        assert len(result) == 1
        assert result[0]["resource"] == "my-alb"
        assert result[0]["remediation_type"] == "delete_load_balancer"

    def test_active_alb_not_flagged(self):
        lb = self._lb("busy-alb", "application")
        lb_dim = lb["LoadBalancerArn"].split("loadbalancer/", 1)[-1]
        elbv2, cw = self._make_clients([lb], request_count_map={lb_dim: 1000})
        assert _data(_check_idle_load_balancers(elbv2, cw, "us-east-1")) == []

    def test_inactive_lb_skipped(self):
        elbv2, cw = self._make_clients([self._lb("prov-alb", state="provisioning")])
        assert _data(_check_idle_load_balancers(elbv2, cw, "us-east-1")) == []

    def test_gateway_lb_skipped(self):
        elbv2, cw = self._make_clients([self._lb("my-gwlb", "gateway")])
        assert _data(_check_idle_load_balancers(elbv2, cw, "us-east-1")) == []

    def test_nlb_uses_network_namespace(self):
        elbv2, cw = self._make_clients([self._lb("my-nlb", "network")])
        _check_idle_load_balancers(elbv2, cw, "us-east-1")
        call_args = cw.get_metric_statistics.call_args
        assert call_args.kwargs["Namespace"] == "AWS/NetworkELB"

    def test_client_error_returns_empty(self):
        elbv2 = MagicMock()
        elbv2.describe_load_balancers.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "DescribeLoadBalancers",
        )
        result = _check_idle_load_balancers(elbv2, MagicMock(), "us-east-1")
        assert result["ok"] is False
        assert result["data"] == []


# ── _check_idle_rds_instances ───────────────────────────────────────────────


class TestCheckIdleRdsInstances:
    def _make_clients(self, instances, max_connections_map=None):
        """instances: list of dicts with DBInstanceIdentifier, DBInstanceStatus, Engine"""
        rds = MagicMock()
        cw = MagicMock()
        rds.describe_db_instances.return_value = {"DBInstances": instances}

        if max_connections_map is None:
            cw.get_metric_statistics.return_value = {"Datapoints": []}
        else:

            def get_metric_stats(**kwargs):
                db_id = kwargs["Dimensions"][0]["Value"]
                val = max_connections_map.get(db_id, 0)
                return {"Datapoints": [{"Maximum": val}] if val > 0 else []}

            cw.get_metric_statistics.side_effect = get_metric_stats
        return rds, cw

    def _db(self, db_id, status="available", engine="mysql"):
        return {
            "DBInstanceIdentifier": db_id,
            "DBInstanceStatus": status,
            "Engine": engine,
        }

    def test_no_instances_returns_empty(self):
        rds, cw = self._make_clients([])
        assert _data(_check_idle_rds_instances(rds, cw, "us-east-1")) == []

    def test_idle_instance_flagged(self):
        rds, cw = self._make_clients([self._db("db-prod")])
        result = _data(_check_idle_rds_instances(rds, cw, "us-east-1"))
        assert len(result) == 1
        assert result[0]["resource"] == "db-prod"
        assert "no connections" in result[0]["finding"]
        assert result[0]["remediation_type"] == "stop_rds_instance"

    def test_active_instance_not_flagged(self):
        rds, cw = self._make_clients(
            [self._db("db-active")],
            max_connections_map={"db-active": 5},
        )
        assert _data(_check_idle_rds_instances(rds, cw, "us-east-1")) == []

    def test_non_available_instance_skipped(self):
        rds, cw = self._make_clients([self._db("db-stopped", status="stopped")])
        assert _data(_check_idle_rds_instances(rds, cw, "us-east-1")) == []

    def test_engine_included_in_finding(self):
        rds, cw = self._make_clients([self._db("db-pg", engine="postgres")])
        result = _data(_check_idle_rds_instances(rds, cw, "us-east-1"))
        assert "postgres" in result[0]["finding"]

    def test_mixed_instances(self):
        rds, cw = self._make_clients(
            [self._db("db-ok"), self._db("db-idle")],
            max_connections_map={"db-ok": 10},
        )
        result = _data(_check_idle_rds_instances(rds, cw, "us-east-1"))
        assert len(result) == 1
        assert result[0]["resource"] == "db-idle"

    def test_client_error_returns_empty(self):
        rds = MagicMock()
        rds.describe_db_instances.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "DescribeDBInstances",
        )
        result = _check_idle_rds_instances(rds, MagicMock(), "us-east-1")
        assert result["ok"] is False
        assert result["data"] == []

    def test_pagination_fetches_all_instances(self):
        rds = MagicMock()
        cw = MagicMock()
        cw.get_metric_statistics.return_value = {"Datapoints": []}
        rds.describe_db_instances.side_effect = [
            {
                "DBInstances": [
                    {
                        "DBInstanceIdentifier": "db-1",
                        "DBInstanceStatus": "available",
                        "Engine": "mysql",
                    }
                ],
                "Marker": "token",
            },
            {
                "DBInstances": [
                    {
                        "DBInstanceIdentifier": "db-2",
                        "DBInstanceStatus": "available",
                        "Engine": "mysql",
                    }
                ]
            },
        ]
        result = _data(_check_idle_rds_instances(rds, cw, "us-east-1"))
        assert len(result) == 2
        assert rds.describe_db_instances.call_count == 2
