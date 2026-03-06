from botocore.exceptions import ClientError, EndpointConnectionError

from aws_lighthouse.scan_contract import (
    error_result,
    is_expected_unavailable_scan_error,
    merge_list_results,
    ok_result,
    scan_error_from_exception,
    scan_error_kind,
    scan_error_reason,
    to_v1_payload,
    to_v2_payload,
)


def test_ok_result_wraps_data_without_errors():
    result = ok_result([{"id": "x"}])
    assert result["ok"] is True
    assert result["data"] == [{"id": "x"}]
    assert result["errors"] == []


def test_error_result_marks_failed_when_errors_present():
    err = {
        "code": "AccessDenied",
        "message": "denied",
        "service": "ec2",
        "operation": "DescribeInstances",
    }
    result = error_result(data=[{"id": "partial"}], errors=[err])
    assert result["ok"] is False
    assert result["data"] == [{"id": "partial"}]
    assert result["errors"] == [err]


def test_error_result_marks_success_when_error_list_empty():
    result = error_result(data=[], errors=[])
    assert result["ok"] is True
    assert result["data"] == []
    assert result["errors"] == []


def test_merge_list_results_accumulates_data_and_errors():
    err = {
        "code": "ThrottlingException",
        "message": "slow down",
        "service": "rds",
        "operation": "DescribeDBInstances",
    }
    merged = merge_list_results(
        [
            ok_result([{"id": "a"}]),
            error_result(data=[{"id": "b"}], errors=[err]),
            ok_result({"id": "c"}),
        ]
    )
    assert merged["ok"] is False
    assert merged["data"] == [{"id": "a"}, {"id": "b"}, {"id": "c"}]
    assert merged["errors"] == [err]


def test_v1_payload_returns_raw_data():
    result = ok_result({"key": "value"})
    assert to_v1_payload(result) == {"key": "value"}


def test_v2_payload_returns_full_envelope():
    result = ok_result({"key": "value"})
    assert to_v2_payload(result) == result


def test_scan_error_from_client_error_uses_aws_error_metadata():
    exc = ClientError(
        error_response={
            "Error": {
                "Code": "ThrottlingException",
                "Message": "Rate exceeded",
            }
        },
        operation_name="DescribeInstances",
    )
    error = scan_error_from_exception(
        service="ec2",
        operation="DescribeInstances",
        region="us-east-1",
        exc=exc,
    )
    assert error["code"] == "ThrottlingException"
    assert error["message"] == "Rate exceeded"
    assert error["service"] == "ec2"
    assert error["operation"] == "DescribeInstances"
    assert error["region"] == "us-east-1"
    assert error["retryable"] is True


def test_scan_error_from_botocore_error_marks_retryable():
    exc = EndpointConnectionError(endpoint_url="https://ec2.us-east-1.amazonaws.com")
    error = scan_error_from_exception(
        service="ec2",
        operation="DescribeInstances",
        exc=exc,
    )
    assert error["code"] == "EndpointConnectionError"
    assert "Could not connect to the endpoint URL" in error["message"]
    assert error["retryable"] is True


def test_savings_plans_data_unavailable_is_classified_as_expected_unavailable():
    error = {
        "code": "DataUnavailableException",
        "message": "raw message",
        "service": "ce",
        "operation": "GetSavingsPlansCoverage",
    }

    assert scan_error_kind(error) == "expected_unavailable"
    assert is_expected_unavailable_scan_error(error) is True
    assert (
        scan_error_reason(error)
        == "Savings Plans data unavailable for this account/period"
    )


def test_guardduty_subscription_required_is_classified_as_expected_unavailable():
    error = {
        "code": "SubscriptionRequiredException",
        "message": "raw message",
        "service": "guardduty",
        "operation": "ListDetectors",
        "region": "us-east-1",
    }

    assert scan_error_kind(error) == "expected_unavailable"
    assert is_expected_unavailable_scan_error(error) is True
    assert scan_error_reason(error) == "subscription required"


def test_unrelated_scan_errors_remain_unexpected_failures():
    error = {
        "code": "AccessDeniedException",
        "message": "denied",
        "service": "ce",
        "operation": "GetSavingsPlansCoverage",
    }

    assert scan_error_kind(error) == "unexpected_failure"
    assert is_expected_unavailable_scan_error(error) is False
    assert scan_error_reason(error) == "denied"
