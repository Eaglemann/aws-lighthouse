from unittest.mock import MagicMock, patch

from aws_lighthouse.tools.cloudwatch_scan import (
    _build_alarm_index,
    detect_cloudwatch_gaps,
)

MOD = "aws_lighthouse.tools.cloudwatch_scan"


# ── _build_alarm_index ────────────────────────────────────────────────────────


def test_build_alarm_index_populated():
    cw = MagicMock()
    cw.get_paginator.return_value.paginate.return_value = [
        {
            "MetricAlarms": [
                {
                    "Namespace": "AWS/EC2",
                    "MetricName": "CPUUtilization",
                    "Dimensions": [{"Name": "InstanceId", "Value": "i-111"}],
                }
            ]
        }
    ]
    index = _build_alarm_index(cw)
    assert ("AWS/EC2", "CPUUtilization", "InstanceId", "i-111") in index


def test_build_alarm_index_empty_pages():
    cw = MagicMock()
    cw.get_paginator.return_value.paginate.return_value = [{"MetricAlarms": []}]
    assert _build_alarm_index(cw) == set()


def test_build_alarm_index_api_error_returns_empty():
    cw = MagicMock()
    cw.get_paginator.side_effect = Exception("denied")
    assert _build_alarm_index(cw) == set()


# ── detect_cloudwatch_gaps ────────────────────────────────────────────────────


def _make_clients(instances=None, dbs=None, alarms=None):
    """Return (cw, ec2, rds) mocks with paginator-based responses."""
    cw = MagicMock()
    cw.get_paginator.return_value.paginate.return_value = [
        {"MetricAlarms": alarms or []}
    ]

    ec2 = MagicMock()
    ec2.get_paginator.return_value.paginate.return_value = [
        {"Reservations": [{"Instances": instances or []}]}
    ]

    rds = MagicMock()
    rds.get_paginator.return_value.paginate.return_value = [{"DBInstances": dbs or []}]

    return cw, ec2, rds


def _make_lambda_client(functions=None):
    lmb = MagicMock()
    lmb.get_paginator.return_value.paginate.return_value = [
        {"Functions": functions or []}
    ]
    return lmb


def _run(cw, ec2, rds, lmb=None):
    lmb = lmb or _make_lambda_client()

    def _dispatch(svc, region=None):
        return {"cloudwatch": cw, "ec2": ec2, "rds": rds, "lambda": lmb}.get(
            svc, MagicMock()
        )

    with patch(f"{MOD}.get_client", side_effect=_dispatch):
        return detect_cloudwatch_gaps()


def test_ec2_missing_both_alarms_flagged():
    instance = {
        "InstanceId": "i-abc",
        "State": {"Name": "running"},
        "Tags": [{"Key": "Name", "Value": "web"}],
    }
    cw, ec2, rds = _make_clients(instances=[instance])
    findings = _run(cw, ec2, rds)
    ec2_findings = [f for f in findings if f["resource_type"] == "EC2"]
    assert len(ec2_findings) == 1
    assert set(ec2_findings[0]["missing_alarms"]) == {
        "CPUUtilization",
        "StatusCheckFailed",
    }


def test_ec2_with_all_alarms_not_flagged():
    instance = {"InstanceId": "i-def", "State": {"Name": "running"}, "Tags": []}
    alarms = [
        {
            "Namespace": "AWS/EC2",
            "MetricName": "CPUUtilization",
            "Dimensions": [{"Name": "InstanceId", "Value": "i-def"}],
        },
        {
            "Namespace": "AWS/EC2",
            "MetricName": "StatusCheckFailed",
            "Dimensions": [{"Name": "InstanceId", "Value": "i-def"}],
        },
    ]
    cw, ec2, rds = _make_clients(instances=[instance], alarms=alarms)
    findings = _run(cw, ec2, rds)
    assert not any(f["resource_type"] == "EC2" for f in findings)


def test_ec2_terminated_skipped():
    instance = {"InstanceId": "i-dead", "State": {"Name": "terminated"}, "Tags": []}
    cw, ec2, rds = _make_clients(instances=[instance])
    findings = _run(cw, ec2, rds)
    assert not any(f["resource_id"] == "i-dead" for f in findings)


def test_rds_missing_alarms_flagged():
    db = {"DBInstanceIdentifier": "my-db"}
    cw, ec2, rds = _make_clients(dbs=[db])
    findings = _run(cw, ec2, rds)
    rds_findings = [f for f in findings if f["resource_type"] == "RDS"]
    assert len(rds_findings) == 1
    assert set(rds_findings[0]["missing_alarms"]) == {
        "CPUUtilization",
        "FreeStorageSpace",
    }


def test_rds_with_all_alarms_not_flagged():
    db = {"DBInstanceIdentifier": "ok-db"}
    alarms = [
        {
            "Namespace": "AWS/RDS",
            "MetricName": "CPUUtilization",
            "Dimensions": [{"Name": "DBInstanceIdentifier", "Value": "ok-db"}],
        },
        {
            "Namespace": "AWS/RDS",
            "MetricName": "FreeStorageSpace",
            "Dimensions": [{"Name": "DBInstanceIdentifier", "Value": "ok-db"}],
        },
    ]
    cw, ec2, rds = _make_clients(dbs=[db], alarms=alarms)
    findings = _run(cw, ec2, rds)
    assert not any(f["resource_type"] == "RDS" for f in findings)


def test_ec2_api_error_returns_no_ec2_findings():
    cw = MagicMock()
    cw.get_paginator.return_value.paginate.return_value = [{"MetricAlarms": []}]
    ec2 = MagicMock()
    ec2.get_paginator.side_effect = Exception("denied")
    rds = MagicMock()
    rds.get_paginator.return_value.paginate.return_value = [{"DBInstances": []}]

    findings = _run(cw, ec2, rds)
    assert not any(f["resource_type"] == "EC2" for f in findings)


# ── Lambda alarm gaps ─────────────────────────────────────────────────────────


def test_lambda_missing_both_alarms_flagged():
    fn = {"FunctionName": "process-orders"}
    cw, ec2, rds = _make_clients()
    findings = _run(cw, ec2, rds, lmb=_make_lambda_client([fn]))
    lmb_findings = [f for f in findings if f["resource_type"] == "Lambda"]
    assert len(lmb_findings) == 1
    assert set(lmb_findings[0]["missing_alarms"]) == {"Errors", "Throttles"}
    assert lmb_findings[0]["resource_id"] == "process-orders"


def test_lambda_with_all_alarms_not_flagged():
    fn = {"FunctionName": "fully-alarmed"}
    alarms = [
        {
            "Namespace": "AWS/Lambda",
            "MetricName": "Errors",
            "Dimensions": [{"Name": "FunctionName", "Value": "fully-alarmed"}],
        },
        {
            "Namespace": "AWS/Lambda",
            "MetricName": "Throttles",
            "Dimensions": [{"Name": "FunctionName", "Value": "fully-alarmed"}],
        },
    ]
    cw, ec2, rds = _make_clients(alarms=alarms)
    findings = _run(cw, ec2, rds, lmb=_make_lambda_client([fn]))
    assert not any(f["resource_type"] == "Lambda" for f in findings)


def test_lambda_missing_only_throttles_flagged():
    fn = {"FunctionName": "half-monitored"}
    alarms = [
        {
            "Namespace": "AWS/Lambda",
            "MetricName": "Errors",
            "Dimensions": [{"Name": "FunctionName", "Value": "half-monitored"}],
        }
    ]
    cw, ec2, rds = _make_clients(alarms=alarms)
    findings = _run(cw, ec2, rds, lmb=_make_lambda_client([fn]))
    lmb_findings = [f for f in findings if f["resource_type"] == "Lambda"]
    assert len(lmb_findings) == 1
    assert lmb_findings[0]["missing_alarms"] == ["Throttles"]


def test_lambda_api_error_doesnt_break_other_findings():
    db = {"DBInstanceIdentifier": "prod-db"}
    cw, ec2, rds = _make_clients(dbs=[db])
    bad_lmb = MagicMock()
    bad_lmb.get_paginator.side_effect = Exception("denied")
    findings = _run(cw, ec2, rds, lmb=bad_lmb)
    assert not any(f["resource_type"] == "Lambda" for f in findings)
    assert any(f["resource_type"] == "RDS" for f in findings)


# ── Pagination regression — resources on page 2 must not be silently dropped ─


def test_ec2_two_page_pagination_collects_all_instances():
    inst_p1 = {"InstanceId": "i-page1", "State": {"Name": "running"}, "Tags": []}
    inst_p2 = {"InstanceId": "i-page2", "State": {"Name": "running"}, "Tags": []}

    cw = MagicMock()
    cw.get_paginator.return_value.paginate.return_value = [{"MetricAlarms": []}]

    ec2 = MagicMock()
    ec2.get_paginator.return_value.paginate.return_value = [
        {"Reservations": [{"Instances": [inst_p1]}]},
        {"Reservations": [{"Instances": [inst_p2]}]},
    ]

    rds = MagicMock()
    rds.get_paginator.return_value.paginate.return_value = [{"DBInstances": []}]

    findings = _run(cw, ec2, rds)
    ids = {f["resource_id"] for f in findings if f["resource_type"] == "EC2"}
    assert ids == {"i-page1", "i-page2"}


def test_rds_two_page_pagination_collects_all_dbs():
    db_p1 = {"DBInstanceIdentifier": "db-page1"}
    db_p2 = {"DBInstanceIdentifier": "db-page2"}

    cw = MagicMock()
    cw.get_paginator.return_value.paginate.return_value = [{"MetricAlarms": []}]

    ec2 = MagicMock()
    ec2.get_paginator.return_value.paginate.return_value = [{"Reservations": []}]

    rds = MagicMock()
    rds.get_paginator.return_value.paginate.return_value = [
        {"DBInstances": [db_p1]},
        {"DBInstances": [db_p2]},
    ]

    findings = _run(cw, ec2, rds)
    ids = {f["resource_id"] for f in findings if f["resource_type"] == "RDS"}
    assert ids == {"db-page1", "db-page2"}
