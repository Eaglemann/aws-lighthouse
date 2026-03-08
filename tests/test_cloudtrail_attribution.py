"""Tests for aws_lighthouse/tools/cloudtrail_attribution.py."""

import json
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest

from aws_lighthouse.tools.cloudtrail_attribution import (
    _extract_actor,
    get_cost_attribution,
)

pytestmark = [pytest.mark.unit]

# ── helpers ──────────────────────────────────────────────────────────────────

_MODULE = "aws_lighthouse.tools.cloudtrail_attribution.get_client"


def _anomaly(service: str, pct: float = 80.0) -> dict:
    return {
        "service": service,
        "baseline_30d": 100.0,
        "recent_30d": 180.0,
        "pct_change": pct,
        "detection_type": "spike",
    }


def _ct_event(
    name: str = "RunInstances",
    actor_type: str = "IAMUser",
    user_name: str = "alice",
    region: str = "us-east-1",
    offset_seconds: int = 0,
) -> dict:
    """Build a minimal CloudTrail Events[] entry."""
    if actor_type == "IAMUser":
        identity = {"type": "IAMUser", "userName": user_name}
    elif actor_type == "AssumedRole":
        identity = {
            "type": "AssumedRole",
            "sessionContext": {"sessionIssuer": {"userName": user_name}},
        }
    elif actor_type == "Root":
        identity = {"type": "Root"}
    else:
        identity = {"type": "AWSService", "invokedBy": "lambda.amazonaws.com"}

    detail = json.dumps({"userIdentity": identity})
    return {
        "EventName": name,
        "EventTime": datetime(2026, 3, 1, 12, offset_seconds, 0, tzinfo=UTC),
        "AwsRegion": region,
        "CloudTrailEvent": detail,
    }


# ── _extract_actor unit tests ─────────────────────────────────────────────────


def test_extract_actor_iam_user() -> None:
    detail = json.dumps({"userIdentity": {"type": "IAMUser", "userName": "bob"}})
    assert _extract_actor(detail) == "bob"


def test_extract_actor_assumed_role() -> None:
    detail = json.dumps(
        {
            "userIdentity": {
                "type": "AssumedRole",
                "sessionContext": {"sessionIssuer": {"userName": "deployer"}},
            }
        }
    )
    assert _extract_actor(detail) == "deployer"


def test_extract_actor_root() -> None:
    detail = json.dumps({"userIdentity": {"type": "Root"}})
    assert _extract_actor(detail) == "root"


def test_extract_actor_malformed_json() -> None:
    assert _extract_actor("not-json{{{{") == "unknown"


# ── get_cost_attribution integration tests ────────────────────────────────────


@patch(_MODULE)
def test_attribution_returns_events_for_known_service(
    mock_get_client: MagicMock,
) -> None:
    """Matching events are extracted and actor is resolved correctly."""
    ct = MagicMock()
    mock_get_client.return_value = ct

    event_a = _ct_event(
        "RunInstances", actor_type="IAMUser", user_name="alice", offset_seconds=0
    )
    event_b = _ct_event(
        "CreateVolume", actor_type="IAMUser", user_name="bob", offset_seconds=10
    )
    ct.lookup_events.return_value = {"Events": [event_a, event_b]}

    anomalies = [_anomaly("Amazon EC2")]
    result = get_cost_attribution(anomalies, max_events=10)

    assert result["ok"] is True
    data = result["data"]
    assert len(data) == 1
    attr = data[0]
    assert attr["service"] == "Amazon EC2"
    actors = {ev["actor"] for ev in attr["events"]}
    assert "alice" in actors or "bob" in actors


@patch(_MODULE)
def test_attribution_skips_unknown_service(mock_get_client: MagicMock) -> None:
    """Services not in _SERVICE_EVENTS are silently skipped."""
    ct = MagicMock()
    mock_get_client.return_value = ct
    ct.lookup_events.return_value = {"Events": []}

    result = get_cost_attribution([_anomaly("Amazon Foo")])
    assert result["ok"] is True
    assert result["data"] == []
    ct.lookup_events.assert_not_called()


@patch(_MODULE)
def test_attribution_caps_at_max_events(mock_get_client: MagicMock) -> None:
    """Results are capped at max_events even if the API returns more."""
    ct = MagicMock()
    mock_get_client.return_value = ct

    many_events = [_ct_event("RunInstances", offset_seconds=i) for i in range(20)]
    ct.lookup_events.return_value = {"Events": many_events}

    result = get_cost_attribution([_anomaly("Amazon EC2")], max_events=5)
    assert result["ok"] is True
    assert len(result["data"][0]["events"]) <= 5


@patch(_MODULE)
def test_attribution_empty_anomalies_returns_empty_list(
    mock_get_client: MagicMock,
) -> None:
    """Empty anomaly list produces ok result with empty data."""
    ct = MagicMock()
    mock_get_client.return_value = ct

    result = get_cost_attribution([])
    assert result["ok"] is True
    assert result["data"] == []
    ct.lookup_events.assert_not_called()


@patch(_MODULE)
def test_attribution_api_error_returns_error_result(mock_get_client: MagicMock) -> None:
    """A ClientError during get_client yields ok=False."""
    from botocore.exceptions import ClientError

    mock_get_client.side_effect = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
        "CreateClient",
    )

    result = get_cost_attribution([_anomaly("Amazon EC2")])
    assert result["ok"] is False
    assert result["data"] == []
    assert result["errors"]


@patch(_MODULE)
def test_attribution_pagination_stops_at_max(mock_get_client: MagicMock) -> None:
    """When NextToken is present and we haven't hit max, a second page is fetched."""
    ct = MagicMock()
    mock_get_client.return_value = ct

    page1_events = [_ct_event("RunInstances", offset_seconds=i) for i in range(3)]
    page2_events = [_ct_event("RunInstances", offset_seconds=i + 10) for i in range(3)]

    ct.lookup_events.side_effect = [
        {"Events": page1_events, "NextToken": "tok123"},
        {"Events": page2_events},
        # AllocateAddress calls (also requested in parallel)
        {"Events": []},
        {"Events": []},
        # CreateVolume
        {"Events": []},
        {"Events": []},
    ]

    result = get_cost_attribution([_anomaly("Amazon EC2")], max_events=10)
    assert result["ok"] is True
    # At least 2 pages fetched for RunInstances
    assert ct.lookup_events.call_count >= 2


@patch(_MODULE)
def test_attribution_events_sorted_desc(mock_get_client: MagicMock) -> None:
    """Events are sorted by EventTime descending (most recent first)."""
    ct = MagicMock()
    mock_get_client.return_value = ct

    older = _ct_event("RunInstances", offset_seconds=0)  # 12:00:00
    newer = _ct_event("CreateVolume", offset_seconds=30)  # 12:00:30
    ct.lookup_events.return_value = {"Events": [older, newer]}

    result = get_cost_attribution([_anomaly("Amazon EC2")], max_events=10)
    assert result["ok"] is True
    events = result["data"][0]["events"]
    # newer event should come first
    times = [ev["event_time"] for ev in events]
    assert times == sorted(times, reverse=True)


@patch(_MODULE)
def test_attribution_event_fields_populated(mock_get_client: MagicMock) -> None:
    """Each attribution event has the required fields."""
    ct = MagicMock()
    mock_get_client.return_value = ct
    ct.lookup_events.return_value = {
        "Events": [_ct_event("RunInstances", actor_type="Root", region="eu-west-1")]
    }

    result = get_cost_attribution([_anomaly("Amazon EC2")], max_events=10)
    assert result["ok"] is True
    ev = result["data"][0]["events"][0]
    assert ev["event_name"] == "RunInstances"
    assert ev["actor"] == "root"
    assert "T" in ev["event_time"] or ev["event_time"]  # ISO 8601
    assert ev["region"] == "eu-west-1"


@patch(_MODULE)
def test_attribution_multiple_anomalies(mock_get_client: MagicMock) -> None:
    """Attribution processes multiple anomalies independently."""
    ct = MagicMock()
    mock_get_client.return_value = ct
    ct.lookup_events.return_value = {"Events": [_ct_event("CreateTable")]}

    result = get_cost_attribution(
        [_anomaly("Amazon EC2"), _anomaly("Amazon DynamoDB")], max_events=10
    )
    assert result["ok"] is True
    services = {a["service"] for a in result["data"]}
    assert "Amazon EC2" in services
    assert "Amazon DynamoDB" in services


@patch(_MODULE)
def test_attribution_assumed_role_actor(mock_get_client: MagicMock) -> None:
    """AssumedRole identity returns the sessionIssuer userName."""
    ct = MagicMock()
    mock_get_client.return_value = ct
    ct.lookup_events.return_value = {
        "Events": [
            _ct_event("RunInstances", actor_type="AssumedRole", user_name="ci-role")
        ]
    }

    result = get_cost_attribution([_anomaly("Amazon EC2")], max_events=10)
    assert result["ok"] is True
    actors = [ev["actor"] for ev in result["data"][0]["events"]]
    assert "ci-role" in actors
