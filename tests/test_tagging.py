from unittest.mock import MagicMock, patch

from botocore.exceptions import BotoCoreError, ClientError

from aws_lighthouse.tools.tagging import check_tagging_compliance

MOD = "aws_lighthouse.tools.tagging"


def _data(result):
    assert set(result.keys()) == {"ok", "data", "errors"}
    return result["data"]


def _make_ec2(instances):
    ec2 = MagicMock()
    ec2.get_paginator.return_value.paginate.return_value = [
        {"Reservations": [{"Instances": instances}]}
    ]
    return ec2


def _make_rds(dbs):
    rds = MagicMock()
    rds.get_paginator.return_value.paginate.return_value = [{"DBInstances": dbs}]
    return rds


def _make_s3(buckets, tag_map=None):
    """tag_map: dict of bucket_name -> list of {"Key":..,"Value":..} tags."""
    s3 = MagicMock()
    s3.list_buckets.return_value = {"Buckets": [{"Name": b} for b in (buckets or [])]}
    tag_map = tag_map or {}

    def get_bucket_tagging(Bucket):
        if Bucket in tag_map:
            return {"TagSet": tag_map[Bucket]}
        raise ClientError(
            {"Error": {"Code": "NoSuchTagSet", "Message": ""}}, "GetBucketTagging"
        )

    s3.get_bucket_tagging.side_effect = get_bucket_tagging
    return s3


def _make_lambda(functions):
    """functions: list of {"FunctionName": .., "FunctionArn": ..}"""
    lmb = MagicMock()
    lmb.get_paginator.return_value.paginate.return_value = [{"Functions": functions}]
    lmb.list_tags.return_value = {"Tags": {}}
    return lmb


def _make_tagging_client(tag_map=None):
    """tag_map: dict of arn -> list of {"Key": .., "Value": ..} tags."""
    tagging = MagicMock()
    tag_map = tag_map or {}
    resources = [{"ResourceARN": arn, "Tags": tags} for arn, tags in tag_map.items()]
    tagging.get_paginator.return_value.paginate.return_value = [
        {"ResourceTagMappingList": resources}
    ]
    return tagging


def _run(ec2=None, rds=None, s3=None, lmb=None, tagging=None, required_tags=None):
    ec2 = ec2 or _make_ec2([])
    rds = rds or _make_rds([])
    s3 = s3 or _make_s3([])
    lmb = lmb or _make_lambda([])
    tagging = tagging or _make_tagging_client()

    def _dispatch(svc, region=None):
        if svc == "ec2":
            return ec2
        if svc == "rds":
            return rds
        if svc == "s3":
            return s3
        if svc == "lambda":
            return lmb
        if svc == "resourcegroupstaggingapi":
            return tagging
        return MagicMock()

    with patch(f"{MOD}.get_client", side_effect=_dispatch):
        return check_tagging_compliance(required_tags=required_tags)


# ── EC2 ───────────────────────────────────────────────────────────────────────


def test_ec2_missing_tags_flagged():
    instance = {
        "InstanceId": "i-111",
        "State": {"Name": "running"},
        "Tags": [{"Key": "Name", "Value": "web"}],
    }
    findings = _data(
        _run(ec2=_make_ec2([instance]), required_tags=["Environment", "Owner"])
    )
    ec2_findings = [f for f in findings if f["resource_type"] == "EC2"]
    assert len(ec2_findings) == 1
    assert set(ec2_findings[0]["missing_tags"]) == {"Environment", "Owner"}


def test_ec2_fully_tagged_not_flagged():
    instance = {
        "InstanceId": "i-222",
        "State": {"Name": "running"},
        "Tags": [
            {"Key": "Environment", "Value": "prod"},
            {"Key": "Owner", "Value": "team"},
        ],
    }
    findings = _data(
        _run(ec2=_make_ec2([instance]), required_tags=["Environment", "Owner"])
    )
    assert not any(f["resource_type"] == "EC2" for f in findings)


def test_ec2_terminated_skipped():
    instance = {
        "InstanceId": "i-333",
        "State": {"Name": "terminated"},
        "Tags": [],
    }
    findings = _data(_run(ec2=_make_ec2([instance]), required_tags=["Environment"]))
    assert not any(f["resource_id"] == "i-333" for f in findings)


# ── RDS ───────────────────────────────────────────────────────────────────────


def test_rds_missing_tags_flagged():
    db = {"DBInstanceIdentifier": "prod-db", "TagList": []}
    findings = _data(_run(rds=_make_rds([db]), required_tags=["Environment"]))
    rds_findings = [f for f in findings if f["resource_type"] == "RDS"]
    assert len(rds_findings) == 1
    assert "Environment" in rds_findings[0]["missing_tags"]


def test_rds_fully_tagged_not_flagged():
    db = {
        "DBInstanceIdentifier": "ok-db",
        "TagList": [{"Key": "Environment", "Value": "staging"}],
    }
    findings = _data(_run(rds=_make_rds([db]), required_tags=["Environment"]))
    assert not any(f["resource_type"] == "RDS" for f in findings)


# ── S3 ────────────────────────────────────────────────────────────────────────


def test_s3_no_tags_flagged():
    # NoSuchTagSet → treated as missing all tags
    findings = _data(
        _run(s3=_make_s3(["raw-bucket"], tag_map={}), required_tags=["Owner"])
    )
    s3_findings = [f for f in findings if f["resource_type"] == "S3"]
    assert len(s3_findings) == 1
    assert s3_findings[0]["resource_id"] == "raw-bucket"


def test_s3_fully_tagged_not_flagged():
    s3 = _make_s3(
        ["tagged-bucket"],
        tag_map={"tagged-bucket": [{"Key": "Owner", "Value": "me"}]},
    )
    findings = _data(_run(s3=s3, required_tags=["Owner"]))
    assert not any(f["resource_type"] == "S3" for f in findings)


def test_s3_skipped_when_include_s3_false():
    s3 = _make_s3(["some-bucket"], tag_map={})

    def _dispatch(svc, region=None):
        if svc == "s3":
            return s3
        return MagicMock()

    with patch(f"{MOD}.get_client", side_effect=_dispatch):
        result = check_tagging_compliance(required_tags=["Owner"], include_s3=False)
    findings = result["data"]
    assert not any(f["resource_type"] == "S3" for f in findings)


# ── Lambda ────────────────────────────────────────────────────────────────────

_FN = {
    "FunctionName": "my-fn",
    "FunctionArn": "arn:aws:lambda:us-east-1:123:function:my-fn",
}
_FN_ARN = _FN["FunctionArn"]


def test_lambda_missing_tags_flagged():
    findings = _data(
        _run(
            lmb=_make_lambda([_FN]),
            tagging=_make_tagging_client({}),
            required_tags=["Environment", "Owner"],
        )
    )
    lmb_findings = [f for f in findings if f["resource_type"] == "Lambda"]
    assert len(lmb_findings) == 1
    assert lmb_findings[0]["resource_id"] == "my-fn"
    assert set(lmb_findings[0]["missing_tags"]) == {"Environment", "Owner"}


def test_lambda_fully_tagged_not_flagged():
    tag_map = {
        _FN_ARN: [
            {"Key": "Environment", "Value": "prod"},
            {"Key": "Owner", "Value": "team"},
        ]
    }
    findings = _data(
        _run(
            lmb=_make_lambda([_FN]),
            tagging=_make_tagging_client(tag_map),
            required_tags=["Environment", "Owner"],
        )
    )
    assert not any(f["resource_type"] == "Lambda" for f in findings)


def test_lambda_partially_tagged_reports_only_missing():
    tag_map = {_FN_ARN: [{"Key": "Environment", "Value": "prod"}]}
    findings = _data(
        _run(
            lmb=_make_lambda([_FN]),
            tagging=_make_tagging_client(tag_map),
            required_tags=["Environment", "Owner"],
        )
    )
    lmb_findings = [f for f in findings if f["resource_type"] == "Lambda"]
    assert len(lmb_findings) == 1
    assert lmb_findings[0]["missing_tags"] == ["Owner"]


def test_lambda_bulk_tag_fetch_error_falls_back_to_per_function_tags():
    tagging = MagicMock()
    tagging.get_paginator.side_effect = BotoCoreError()
    lmb = _make_lambda([_FN])
    lmb.list_tags.return_value = {"Tags": {"Owner": "team"}}
    result = _run(
        lmb=lmb,
        tagging=tagging,
        required_tags=["Owner"],
    )
    findings = _data(result)
    assert result["ok"] is False
    assert not any(f["resource_type"] == "Lambda" for f in findings)
    lmb.list_tags.assert_called_once_with(Resource=_FN_ARN)


def test_lambda_tag_lookup_failures_do_not_invent_missing_tag_findings():
    tagging = MagicMock()
    tagging.get_paginator.side_effect = BotoCoreError()
    lmb = _make_lambda([_FN])
    lmb.list_tags.side_effect = BotoCoreError()

    result = _run(
        lmb=lmb,
        tagging=tagging,
        required_tags=["Owner"],
    )

    findings = _data(result)
    assert result["ok"] is False
    assert not any(f["resource_type"] == "Lambda" for f in findings)


def test_lambda_bulk_tags_two_pages_collects_all():
    fn2 = {
        "FunctionName": "fn2",
        "FunctionArn": "arn:aws:lambda:us-east-1:123:function:fn2",
    }
    tagging = MagicMock()
    tagging.get_paginator.return_value.paginate.return_value = [
        {
            "ResourceTagMappingList": [
                {"ResourceARN": _FN_ARN, "Tags": [{"Key": "Owner", "Value": "me"}]}
            ]
        },
        {
            "ResourceTagMappingList": [
                {
                    "ResourceARN": fn2["FunctionArn"],
                    "Tags": [{"Key": "Owner", "Value": "me"}],
                }
            ]
        },
    ]
    findings = _data(
        _run(
            lmb=_make_lambda([_FN, fn2]),
            tagging=tagging,
            required_tags=["Owner"],
        )
    )
    assert not any(f["resource_type"] == "Lambda" for f in findings)


def test_lambda_api_error_doesnt_break_other_findings():
    lmb = MagicMock()
    lmb.get_paginator.side_effect = BotoCoreError()
    db = {"DBInstanceIdentifier": "ok-db", "TagList": []}
    result = _run(rds=_make_rds([db]), lmb=lmb, required_tags=["Owner"])
    findings = _data(result)
    assert result["ok"] is False
    # RDS finding still returned despite Lambda error
    assert any(f["resource_type"] == "RDS" for f in findings)
    assert not any(f["resource_type"] == "Lambda" for f in findings)


# HIGH-9: Skipped Lambda resources surface a warning
def test_lambda_per_function_fallback_failure_logs_warning():
    """When per-function tag lookup fails, the skipped name must appear in a logger.warn call."""
    tagging = MagicMock()
    tagging.get_paginator.side_effect = BotoCoreError()
    lmb = _make_lambda([_FN])
    lmb.list_tags.side_effect = BotoCoreError()

    with patch(f"{MOD}.logger.warn") as mock_warn:
        _run(lmb=lmb, tagging=tagging, required_tags=["Owner"])

    # A warning mentioning the skipped function name must be emitted
    assert mock_warn.called, "Expected logger.warn to be called for skipped Lambda"
    warn_text = mock_warn.call_args.args[0]
    assert "my-fn" in warn_text or "Skipped" in warn_text
