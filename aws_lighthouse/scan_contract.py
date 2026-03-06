from collections.abc import Iterable
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from .types import ScanError, ScanResult

_RETRYABLE_ERROR_CODES = {
    "RequestLimitExceeded",
    "RequestTimeout",
    "RequestTimeoutException",
    "ServiceUnavailable",
    "SlowDown",
    "ThrottledException",
    "Throttling",
    "ThrottlingException",
    "TooManyRequestsException",
}

_EXPECTED_UNAVAILABLE_REASONS = {
    ("ce", "GetSavingsPlansCoverage", "DataUnavailableException"): (
        "Savings Plans data unavailable for this account/period"
    ),
    ("ce", "GetSavingsPlansUtilization", "DataUnavailableException"): (
        "Savings Plans data unavailable for this account/period"
    ),
    ("guardduty", "ListDetectors", "SubscriptionRequiredException"): (
        "subscription required"
    ),
}


def _is_retryable(exc: Exception) -> bool:
    if isinstance(exc, ClientError):
        code = str(exc.response.get("Error", {}).get("Code", ""))
        return code in _RETRYABLE_ERROR_CODES
    return isinstance(exc, BotoCoreError)


def scan_error_from_exception(
    *,
    service: str,
    operation: str,
    exc: Exception,
    region: str | None = None,
) -> ScanError:
    """Create a typed ScanError from a boto-style exception."""
    code = exc.__class__.__name__
    message = str(exc)
    if isinstance(exc, ClientError):
        err = exc.response.get("Error", {})
        code = str(err.get("Code", code))
        message = str(err.get("Message", message))
    error: ScanError = {
        "code": code,
        "message": message,
        "service": service,
        "operation": operation,
        "retryable": _is_retryable(exc),
    }
    if region:
        error["region"] = region
    return error


def scan_error_kind(error: ScanError) -> str:
    """Classify a scan error for rendering and log policy decisions."""
    key = (error["service"], error["operation"], error["code"])
    if key in _EXPECTED_UNAVAILABLE_REASONS:
        return "expected_unavailable"
    return "unexpected_failure"


def is_expected_unavailable_scan_error(error: ScanError) -> bool:
    return scan_error_kind(error) == "expected_unavailable"


def scan_error_reason(error: ScanError) -> str:
    """Return a concise user-facing reason for a structured scan error."""
    key = (error["service"], error["operation"], error["code"])
    return _EXPECTED_UNAVAILABLE_REASONS.get(key, error["message"])


def ok_result(data: Any) -> ScanResult:
    return {"ok": True, "data": data, "errors": []}


def error_result(*, data: Any, errors: list[ScanError]) -> ScanResult:
    return {"ok": not errors, "data": data, "errors": errors}


def merge_list_results(results: Iterable[ScanResult]) -> ScanResult:
    """Merge list-typed envelopes while preserving all errors."""
    data: list[Any] = []
    errors: list[ScanError] = []
    for result in results:
        payload = result.get("data", [])
        if isinstance(payload, list):
            data.extend(payload)
        elif payload is not None:
            data.append(payload)
        errors.extend(result.get("errors", []))
    return {"ok": not errors, "data": data, "errors": errors}


def to_v1_payload(result: ScanResult) -> Any:
    """Compatibility payload for legacy machine contracts."""
    return result["data"]


def to_v2_payload(result: ScanResult) -> ScanResult:
    """Explicit envelope payload for v2 machine contracts."""
    return result
