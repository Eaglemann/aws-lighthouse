from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

from aws_lighthouse.tools.tagging import check_tagging_compliance

MOD = "aws_lighthouse.tools.tagging"


def _make_ec2(instances):
    ec2 = MagicMock()
    ec2.describe_instances.return_value = {"Reservations": [{"Instances": instances}]}
    return ec2


def _make_rds(dbs):
    rds = MagicMock()
    rds.describe_db_instances.return_value = {"DBInstances": dbs}
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


def _run(ec2=None, rds=None, s3=None, required_tags=None):
    ec2 = ec2 or _make_ec2([])
    rds = rds or _make_rds([])
    s3 = s3 or _make_s3([])

    def get_client(svc):
        if svc == "ec2":
            return ec2
        if svc == "rds":
            return rds
        if svc == "s3":
            return s3
        return MagicMock()

    with patch(f"{MOD}.get_aws_client", side_effect=get_client):
        with patch(
            f"{MOD}.get_aws_client_for_region",
            side_effect=lambda svc, r: get_client(svc),
        ):
            return check_tagging_compliance(required_tags=required_tags)


# ── EC2 ───────────────────────────────────────────────────────────────────────


def test_ec2_missing_tags_flagged():
    instance = {
        "InstanceId": "i-111",
        "State": {"Name": "running"},
        "Tags": [{"Key": "Name", "Value": "web"}],
    }
    findings = _run(ec2=_make_ec2([instance]), required_tags=["Environment", "Owner"])
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
    findings = _run(ec2=_make_ec2([instance]), required_tags=["Environment", "Owner"])
    assert not any(f["resource_type"] == "EC2" for f in findings)


def test_ec2_terminated_skipped():
    instance = {
        "InstanceId": "i-333",
        "State": {"Name": "terminated"},
        "Tags": [],
    }
    findings = _run(ec2=_make_ec2([instance]), required_tags=["Environment"])
    assert not any(f["resource_id"] == "i-333" for f in findings)


# ── RDS ───────────────────────────────────────────────────────────────────────


def test_rds_missing_tags_flagged():
    db = {"DBInstanceIdentifier": "prod-db", "TagList": []}
    findings = _run(rds=_make_rds([db]), required_tags=["Environment"])
    rds_findings = [f for f in findings if f["resource_type"] == "RDS"]
    assert len(rds_findings) == 1
    assert "Environment" in rds_findings[0]["missing_tags"]


def test_rds_fully_tagged_not_flagged():
    db = {
        "DBInstanceIdentifier": "ok-db",
        "TagList": [{"Key": "Environment", "Value": "staging"}],
    }
    findings = _run(rds=_make_rds([db]), required_tags=["Environment"])
    assert not any(f["resource_type"] == "RDS" for f in findings)


# ── S3 ────────────────────────────────────────────────────────────────────────


def test_s3_no_tags_flagged():
    # NoSuchTagSet → treated as missing all tags
    findings = _run(s3=_make_s3(["raw-bucket"], tag_map={}), required_tags=["Owner"])
    s3_findings = [f for f in findings if f["resource_type"] == "S3"]
    assert len(s3_findings) == 1
    assert s3_findings[0]["resource_id"] == "raw-bucket"


def test_s3_fully_tagged_not_flagged():
    s3 = _make_s3(
        ["tagged-bucket"],
        tag_map={"tagged-bucket": [{"Key": "Owner", "Value": "me"}]},
    )
    findings = _run(s3=s3, required_tags=["Owner"])
    assert not any(f["resource_type"] == "S3" for f in findings)


def test_s3_skipped_when_include_s3_false():
    s3 = _make_s3(["some-bucket"], tag_map={})

    def get_client(svc):
        if svc == "s3":
            return s3
        return MagicMock()

    with patch(f"{MOD}.get_aws_client", side_effect=get_client):
        findings = check_tagging_compliance(required_tags=["Owner"], include_s3=False)
    assert not any(f["resource_type"] == "S3" for f in findings)
