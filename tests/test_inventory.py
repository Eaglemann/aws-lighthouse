from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

from aws_lighthouse.tools.inventory import (
    get_ec2_inventory,
    get_lambda_inventory,
    get_rds_inventory,
)

MOD = "aws_lighthouse.tools.inventory"


def _make_lambda(functions):
    lmb = MagicMock()
    lmb.get_paginator.return_value.paginate.return_value = [{"Functions": functions}]
    return lmb


def _fn(name, last_modified, memory=128, timeout=3, code_size=1_048_576):
    return {
        "FunctionName": name,
        "Runtime": "python3.12",
        "MemorySize": memory,
        "Timeout": timeout,
        "CodeSize": code_size,
        "LastModified": last_modified,
        "FunctionArn": f"arn:aws:lambda:us-east-1:123:function:{name}",
    }


# ── basic fields ──────────────────────────────────────────────────────────────


def test_lambda_inventory_returns_expected_fields():
    recent = (datetime.now(timezone.utc) - timedelta(days=10)).strftime(
        "%Y-%m-%dT%H:%M:%S.000+0000"
    )
    lmb = _make_lambda([_fn("my-fn", recent)])
    with patch(f"{MOD}.get_aws_client", return_value=lmb):
        result = get_lambda_inventory()
    assert len(result) == 1
    fn = result[0]
    assert fn["FunctionName"] == "my-fn"
    assert fn["Runtime"] == "python3.12"
    assert fn["MemorySize"] == 128
    assert fn["Timeout"] == 3
    assert fn["CodeSizeMB"] == 1.0
    assert "error" not in fn


# ── stale detection ───────────────────────────────────────────────────────────


def test_lambda_stale_after_180_days():
    old = (datetime.now(timezone.utc) - timedelta(days=200)).strftime(
        "%Y-%m-%dT%H:%M:%S.000+0000"
    )
    lmb = _make_lambda([_fn("old-fn", old)])
    with patch(f"{MOD}.get_aws_client", return_value=lmb):
        result = get_lambda_inventory()
    assert result[0]["Stale"] is True


def test_lambda_not_stale_when_recent():
    recent = (datetime.now(timezone.utc) - timedelta(days=30)).strftime(
        "%Y-%m-%dT%H:%M:%S.000+0000"
    )
    lmb = _make_lambda([_fn("fresh-fn", recent)])
    with patch(f"{MOD}.get_aws_client", return_value=lmb):
        result = get_lambda_inventory()
    assert result[0]["Stale"] is False


def test_lambda_bad_date_format_stale_false():
    lmb = _make_lambda([_fn("broken-fn", "not-a-date")])
    with patch(f"{MOD}.get_aws_client", return_value=lmb):
        result = get_lambda_inventory()
    assert result[0]["Stale"] is False


# ── error handling ────────────────────────────────────────────────────────────


def test_lambda_api_error_returns_error_list():
    lmb = MagicMock()
    lmb.get_paginator.side_effect = Exception("denied")
    with patch(f"{MOD}.get_aws_client", return_value=lmb):
        result = get_lambda_inventory()
    assert len(result) == 1
    assert "error" in result[0]


def test_lambda_empty_account_returns_empty_list():
    lmb = _make_lambda([])
    with patch(f"{MOD}.get_aws_client", return_value=lmb):
        result = get_lambda_inventory()
    assert result == []


# ── get_ec2_inventory ─────────────────────────────────────────────────────────


def _make_ec2(reservations):
    ec2 = MagicMock()
    ec2.get_paginator.return_value.paginate.return_value = [
        {"Reservations": reservations}
    ]
    return ec2


def _inst(instance_id, name=None, instance_type="t3.micro", state="running"):
    tags = [{"Key": "Name", "Value": name}] if name else []
    return {
        "InstanceId": instance_id,
        "InstanceType": instance_type,
        "State": {"Name": state},
        "LaunchTime": datetime(2025, 1, 1, tzinfo=timezone.utc),
        "KeyName": "my-key",
        "Tags": tags,
    }


def test_ec2_inventory_returns_expected_fields():
    ec2 = _make_ec2([{"Instances": [_inst("i-111", name="web")]}])
    with patch(f"{MOD}.get_aws_client", return_value=ec2):
        result = get_ec2_inventory()
    assert len(result) == 1
    assert result[0]["InstanceId"] == "i-111"
    assert result[0]["Name"] == "web"
    assert result[0]["Type"] == "t3.micro"
    assert result[0]["State"] == "running"
    assert "error" not in result[0]


def test_ec2_inventory_unknown_name_when_no_tag():
    ec2 = _make_ec2([{"Instances": [_inst("i-222")]}])
    with patch(f"{MOD}.get_aws_client", return_value=ec2):
        result = get_ec2_inventory()
    assert result[0]["Name"] == "Unknown"


def test_ec2_inventory_empty_account():
    ec2 = _make_ec2([])
    with patch(f"{MOD}.get_aws_client", return_value=ec2):
        result = get_ec2_inventory()
    assert result == []


def test_ec2_inventory_api_error_returns_error_list():
    ec2 = MagicMock()
    ec2.get_paginator.side_effect = Exception("denied")
    with patch(f"{MOD}.get_aws_client", return_value=ec2):
        result = get_ec2_inventory()
    assert len(result) == 1
    assert "error" in result[0]


# ── get_rds_inventory ─────────────────────────────────────────────────────────


def _make_rds(db_instances):
    rds = MagicMock()
    rds.get_paginator.return_value.paginate.return_value = [
        {"DBInstances": db_instances}
    ]
    return rds


def _db(identifier, engine="mysql", db_class="db.t3.micro", public=False):
    return {
        "DBInstanceIdentifier": identifier,
        "Engine": engine,
        "DBInstanceClass": db_class,
        "DBInstanceStatus": "available",
        "PubliclyAccessible": public,
    }


def test_rds_inventory_returns_expected_fields():
    rds = _make_rds([_db("prod-db", public=True)])
    with patch(f"{MOD}.get_aws_client", return_value=rds):
        result = get_rds_inventory()
    assert len(result) == 1
    assert result[0]["DBInstanceIdentifier"] == "prod-db"
    assert result[0]["Engine"] == "mysql"
    assert result[0]["PubliclyAccessible"] is True
    assert "error" not in result[0]


def test_rds_inventory_empty_account():
    rds = _make_rds([])
    with patch(f"{MOD}.get_aws_client", return_value=rds):
        result = get_rds_inventory()
    assert result == []


def test_rds_inventory_api_error_returns_error_list():
    rds = MagicMock()
    rds.get_paginator.side_effect = Exception("denied")
    with patch(f"{MOD}.get_aws_client", return_value=rds):
        result = get_rds_inventory()
    assert len(result) == 1
    assert "error" in result[0]
