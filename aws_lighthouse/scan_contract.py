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
