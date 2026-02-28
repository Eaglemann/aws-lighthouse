from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

from aws_lighthouse.tools.inventory import get_lambda_inventory

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
