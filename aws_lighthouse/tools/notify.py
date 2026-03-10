"""Webhook notification support for aws-lighthouse watch alerts."""

import json
import urllib.error
import urllib.request
from typing import Any


def _count_high_critical(findings: list[dict[str, Any]]) -> int:
    """Count findings with severity HIGH or CRITICAL."""
    return sum(1 for f in findings if f.get("severity") in {"HIGH", "CRITICAL"})


def build_alert_payload(
    account_id: str,
    new_security: list[dict[str, Any]],
    new_iam: list[dict[str, Any]],
    new_cost_waste: list[dict[str, Any]],
    scan_url: str | None = None,
) -> dict[str, Any]:
    """Build the webhook JSON payload for new findings."""
    high_critical = _count_high_critical(new_security) + _count_high_critical(new_iam)
    total_new = len(new_security) + len(new_iam) + len(new_cost_waste)

    # Slack-compatible format (also works as plain JSON for other webhooks)
    summary_lines: list[str] = []
    if new_security:
        summary_lines.append(f"• {len(new_security)} new security finding(s)")
    if new_iam:
        summary_lines.append(f"• {len(new_iam)} new IAM finding(s)")
    if new_cost_waste:
        summary_lines.append(f"• {len(new_cost_waste)} new cost waste finding(s)")

    text = (
        f"*AWS Lighthouse Alert* — {total_new} new finding(s) in account `{account_id}`"
    )
    if high_critical:
        text += f" ({high_critical} HIGH/CRITICAL)"
    if summary_lines:
        text += "\n" + "\n".join(summary_lines)

    payload: dict[str, Any] = {
        "text": text,
        "account_id": account_id,
        "total_new": total_new,
        "high_critical_count": high_critical,
        "new_security_findings": new_security,
        "new_iam_findings": new_iam,
        "new_cost_waste": new_cost_waste,
    }
    if scan_url:
        payload["scan_url"] = scan_url
    return payload


def send_webhook(url: str, payload: dict[str, Any], timeout: int = 10) -> bool:
    """POST payload as JSON to url. Returns True on success, False on failure."""
    data = json.dumps(payload, default=str).encode("utf-8")
    req = urllib.request.Request(  # noqa: S310
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return bool(resp.status < 400)
    except (urllib.error.URLError, urllib.error.HTTPError, OSError):
        return False


def should_alert(
    delta: dict[str, Any],
    min_severity: str | None = "HIGH",
) -> bool:
    """Return True if the delta contains findings that warrant an alert.

    Alerts when there are any new findings if min_severity is None,
    or when there are HIGH/CRITICAL findings if min_severity is HIGH.

    The *delta* dict uses the structure produced by ``_build_delta_payload``
    in ``cli.py``: ``sections`` -> ``<section_key>`` -> ``new`` (list).
    """
    if not delta.get("baseline_found"):
        return False  # First scan — no baseline to compare against
    summary = delta.get("summary", {})
    total_new = summary.get("total_new", 0)
    if total_new == 0:
        return False
    if min_severity == "HIGH":
        sections = delta.get("sections", {})
        new_sec: list[dict[str, Any]] = sections.get("security_findings", {}).get(
            "new", []
        )
        new_iam: list[dict[str, Any]] = sections.get("iam_findings", {}).get("new", [])
        return _count_high_critical(new_sec) > 0 or _count_high_critical(new_iam) > 0
    return bool(total_new > 0)
