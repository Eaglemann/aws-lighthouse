from aws_lighthouse.scan_orchestrator import collect_scan_results


def _ok(data):
    return {"ok": True, "data": data, "errors": []}


def test_collect_scan_results_preserves_input_order():
    result = collect_scan_results(
        ["eu-west-1", "us-east-1"],
        lambda region: _ok([{"region": region}]),
        max_workers=2,
    )

    assert result == _ok([{"region": "eu-west-1"}, {"region": "us-east-1"}])


def test_collect_scan_results_merges_partial_errors():
    error = {
        "code": "AccessDenied",
        "message": "denied",
        "service": "ec2",
        "operation": "DescribeInstances",
        "region": "us-east-1",
    }

    def _scan(region):
        if region == "us-east-1":
            return {"ok": False, "data": [], "errors": [error]}
        return _ok([{"region": region}])

    result = collect_scan_results(["eu-west-1", "us-east-1"], _scan, max_workers=2)

    assert result["ok"] is False
    assert result["data"] == [{"region": "eu-west-1"}]
    assert result["errors"] == [error]
