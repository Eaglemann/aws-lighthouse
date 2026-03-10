"""
Tests for the LangGraph agent security gate (should_require_approval)
and the approval_node approval/denial paths.
"""

from unittest.mock import MagicMock, patch

import pytest
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from aws_lighthouse.agent import (
    OLLAMA_MODEL_NAME,
    SAFE_TOOLS,
    _classify_tool_result,
    _normalize_schema_like_args,
    _parse_severity_filter,
    _parse_source_kind_filter,
    _parse_status_filter,
    _record_tool_execution_results,
    _route_after_approval,
    approval_node,
    check_ollama_runtime,
    should_require_approval,
    tool_detect_cost_anomalies,
    tool_get_ec2_inventory,
    tool_get_opportunity_details,
    tool_list_opportunities,
    tool_plan_opportunities,
    tool_update_opportunity,
    tools,
    tools_node,
)

pytestmark = [pytest.mark.unit, pytest.mark.security]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DESTRUCTIVE_TOOLS = {
    "tool_write_file",
    "tool_execute_bash",
    "terminate_ec2",
    "delete_ebs",
    "s3_block_public_access",
    "tool_read_file",  # intentionally removed from SAFE_TOOLS — must require approval
}


def _state(tool_calls: list) -> dict:
    """Build a minimal AgentState dict with one AIMessage."""
    msg = MagicMock(spec=AIMessage)
    msg.tool_calls = tool_calls
    msg.content = ""
    return {"messages": [msg]}


def _tc(name: str) -> dict:
    """Shorthand for a tool call dict."""
    return {"name": name, "id": f"call-{name}", "args": {}}


# ---------------------------------------------------------------------------
# should_require_approval — routing logic
# ---------------------------------------------------------------------------


def test_no_tool_calls_returns_end():
    assert should_require_approval(_state([])) == "end"


def test_every_safe_tool_bypasses_approval():
    """Every entry in SAFE_TOOLS must route directly to 'tools', not 'approval'."""
    for name in SAFE_TOOLS:
        result = should_require_approval(_state([_tc(name)]))
        assert result == "tools", (
            f"Expected 'tools' for safe tool {name!r} but got {result!r}. "
            "If this tool is mutative, remove it from SAFE_TOOLS."
        )


def test_destructive_tool_requires_approval():
    for name in _DESTRUCTIVE_TOOLS:
        result = should_require_approval(_state([_tc(name)]))
        assert result == "approval", (
            f"Expected 'approval' for destructive tool {name!r} but got {result!r}."
        )


def test_mixed_batch_with_one_destructive_requires_approval():
    """A batch containing any destructive tool must go through approval."""
    tcs = [_tc("tool_get_ec2_inventory"), _tc("terminate_ec2")]
    assert should_require_approval(_state(tcs)) == "approval"


def test_unknown_tool_name_requires_approval():
    """An unrecognised tool name must never silently bypass approval."""
    assert (
        should_require_approval(_state([_tc("tool_injected_by_prompt")])) == "approval"
    )


def test_tool_read_file_is_not_in_safe_tools():
    """tool_read_file must require approval — it can access sensitive local paths."""
    assert "tool_read_file" not in SAFE_TOOLS, (
        "tool_read_file must NOT be in SAFE_TOOLS. "
        "It can read ~/.aws/credentials and ~/.ssh/id_rsa without restriction."
    )


def test_safe_tools_contains_no_destructive_tools():
    """No destructive tool may appear in SAFE_TOOLS."""
    overlap = SAFE_TOOLS & _DESTRUCTIVE_TOOLS
    assert not overlap, (
        f"Destructive tools found in SAFE_TOOLS: {overlap}. "
        "This silently removes user approval for those tools."
    )


# ---------------------------------------------------------------------------
# approval_node — approval path
# ---------------------------------------------------------------------------


def test_approval_node_sets_approved_true_on_approval():
    """Approval must return approved=True so _route_after_approval reaches ToolNode."""
    msg = MagicMock(spec=AIMessage)
    msg.tool_calls = [_tc("terminate_ec2")]
    msg.content = "I will terminate the instance."
    state = {"messages": [msg]}

    with patch("typer.prompt", return_value="y"), patch("aws_lighthouse.agent.logger"):
        result = approval_node(state)

    assert result.get("approved") is True, (
        "approval_node must set approved=True on approval so _route_after_approval "
        "routes to ToolNode."
    )
    assert "messages" not in result, (
        "approval_node must not inject messages on approval."
    )


# ---------------------------------------------------------------------------
# approval_node — denial path
# ---------------------------------------------------------------------------


def test_approval_node_denial_injects_tool_message_per_call():
    """On denial, one ToolMessage rejection must be returned per pending tool call."""
    tc1 = {"name": "terminate_ec2", "id": "call-abc", "args": {"instance_ids": ["i-1"]}}
    tc2 = {"name": "delete_ebs", "id": "call-def", "args": {"volume_ids": ["vol-1"]}}
    msg = MagicMock(spec=AIMessage)
    msg.tool_calls = [tc1, tc2]
    msg.content = ""
    state = {"messages": [msg]}

    with patch("typer.prompt", return_value="n"), patch("aws_lighthouse.agent.logger"):
        result = approval_node(state)

    assert result is not None
    # approved flag must be False so _route_after_approval does NOT reach ToolNode
    assert result.get("approved") is False, (
        "approval_node must set approved=False on denial so tools are never executed."
    )
    assert "messages" in result
    rejections = result["messages"]
    assert len(rejections) == 2
    ids = {r.tool_call_id for r in rejections}
    assert ids == {"call-abc", "call-def"}
    for r in rejections:
        assert isinstance(r, ToolMessage)
        assert "denied" in r.content.lower()


def test_approval_node_denial_does_not_return_none():
    """Denial must never return None — that would be interpreted as approval."""
    msg = MagicMock(spec=AIMessage)
    msg.tool_calls = [_tc("terminate_ec2")]
    msg.content = ""
    state = {"messages": [msg]}

    with patch("typer.prompt", return_value="n"), patch("aws_lighthouse.agent.logger"):
        result = approval_node(state)

    assert result is not None, (
        "approval_node returned None on denial. "
        "This is equivalent to approving the action."
    )


# ---------------------------------------------------------------------------
# _route_after_approval — conditional edge routing
# ---------------------------------------------------------------------------


def test_route_after_approval_approved_reaches_tools():
    """approved=True must route to 'tools' so the LLM's intent is executed."""
    assert _route_after_approval({"approved": True}) == "tools"


def test_route_after_approval_denied_returns_to_agent():
    """approved=False must route to 'agent', not 'tools', so tools never execute."""
    assert _route_after_approval({"approved": False}) == "agent"


def test_route_after_approval_missing_key_defaults_safe():
    """If 'approved' is absent (e.g. first invocation), default to 'agent' not 'tools'.

    This is the safe default — unknown approval state must never reach ToolNode.
    """
    assert _route_after_approval({}) == "agent"
    assert _route_after_approval({"messages": []}) == "agent"


def test_denial_never_reaches_tools():
    """End-to-end: approval_node denial sets approved=False, route resolves to 'agent'.

    This is the key invariant: a user saying 'n' must NEVER result in ToolNode executing.
    """
    msg = MagicMock(spec=AIMessage)
    msg.tool_calls = [_tc("terminate_ec2"), _tc("delete_ebs")]
    msg.content = "I will terminate instances and delete volumes."
    state = {"messages": [msg]}

    with patch("typer.prompt", return_value="n"), patch("aws_lighthouse.agent.logger"):
        result = approval_node(state)

    # The state after denial must route away from tools
    next_node = _route_after_approval({**state, **result})
    assert next_node == "agent", (
        f"After denial, graph must route to 'agent' but got {next_node!r}. "
        "ToolNode would have executed the denied tools."
    )


def test_approval_reaches_tools():
    """End-to-end: approval_node approval sets approved=True, route resolves to 'tools'."""
    msg = MagicMock(spec=AIMessage)
    msg.tool_calls = [_tc("terminate_ec2")]
    msg.content = "I will terminate the instance."
    state = {"messages": [msg]}

    with patch("typer.prompt", return_value="y"), patch("aws_lighthouse.agent.logger"):
        result = approval_node(state)

    next_node = _route_after_approval({**state, **result})
    assert next_node == "tools", (
        f"After approval, graph must route to 'tools' but got {next_node!r}."
    )


def test_classify_tool_result_detects_error_prefix():
    status, error = _classify_tool_result("Error: boom")
    assert status == "failed"
    assert error == "Error: boom"


def test_classify_tool_result_detects_json_error_field():
    status, error = _classify_tool_result('{"stdout":"","error":"Timeout"}')
    assert status == "failed"
    assert error == "Timeout"


def test_record_tool_execution_results_updates_audit_log():
    msg = MagicMock(spec=AIMessage)
    msg.tool_calls = [{"name": "tool_execute_bash", "id": "call-xyz", "args": {}}]
    msg.content = ""
    state = {"messages": [msg]}
    output = {
        "messages": [
            ToolMessage(
                content='{"stdout":"","error":"Timeout"}', tool_call_id="call-xyz"
            )
        ]
    }

    with patch(
        "aws_lighthouse.agent.db_manager.update_audit_log_result"
    ) as mock_update:
        _record_tool_execution_results(state, output)

    mock_update.assert_called_once_with(
        tool_call_id="call-xyz",
        result='{"stdout":"","error":"Timeout"}',
        execution_status="failed",
        error="Timeout",
    )


def test_check_ollama_runtime_reports_ready_when_model_is_present():
    response = MagicMock()
    response.__enter__.return_value = response
    response.read.return_value = (
        f'{{"models":[{{"name":"{OLLAMA_MODEL_NAME}"}}]}}'.encode()
    )
    response.status = 200

    with (
        patch.dict("os.environ", {"OLLAMA_HOST": "http://localhost:11434"}),
        patch("aws_lighthouse.agent.urlopen", return_value=response),
    ):
        status = check_ollama_runtime()

    assert status["ok"] is True
    assert status["reason"] == "ok"
    assert status["model"] == OLLAMA_MODEL_NAME


def test_check_ollama_runtime_reports_missing_model_when_not_installed():
    response = MagicMock()
    response.__enter__.return_value = response
    response.read.return_value = b'{"models":[{"name":"llama3.2:latest"}]}'
    response.status = 200

    with (
        patch.dict("os.environ", {"OLLAMA_HOST": "http://localhost:11434"}),
        patch("aws_lighthouse.agent.urlopen", return_value=response),
    ):
        status = check_ollama_runtime()

    assert status["ok"] is False
    assert status["reason"] == "model_missing"
    assert status["model"] == OLLAMA_MODEL_NAME


def test_check_ollama_runtime_reports_unavailable_when_runtime_is_down():
    with (
        patch.dict("os.environ", {"OLLAMA_HOST": "http://localhost:11434"}),
        patch(
            "aws_lighthouse.agent.urlopen",
            side_effect=OSError("Connection refused"),
        ),
    ):
        status = check_ollama_runtime()

    assert status["ok"] is False
    assert status["reason"] == "unavailable"
    assert "Connection refused" in status["detail"]


def test_read_only_tool_schema_v1_returns_legacy_payload():
    with patch(
        "aws_lighthouse.agent._get_ec2_inventory",
        return_value={"ok": True, "data": [{"id": "i-1"}], "errors": []},
    ):
        payload = tool_get_ec2_inventory.invoke({"region": "us-east-1"})
    assert payload == '[{"id": "i-1"}]'


def test_read_only_tool_schema_v2_returns_envelope_payload():
    with patch(
        "aws_lighthouse.agent._get_ec2_inventory",
        return_value={
            "ok": False,
            "data": [{"id": "i-1"}],
            "errors": [
                {
                    "code": "AccessDenied",
                    "message": "denied",
                    "service": "ec2",
                    "operation": "DescribeInstances",
                }
            ],
        },
    ):
        payload = tool_get_ec2_inventory.invoke({"region": "us-east-1", "schema": "v2"})
    assert (
        payload
        == '{"ok": false, "data": [{"id": "i-1"}], "errors": [{"code": "AccessDenied", "message": "denied", "service": "ec2", "operation": "DescribeInstances"}]}'
    )


def test_classify_tool_result_detects_envelope_failure():
    status, error = _classify_tool_result(
        '{"ok": false, "data": [], "errors": [{"code": "ThrottlingException", "message": "Rate exceeded", "service": "ce", "operation": "GetCostAndUsage"}]}'
    )
    assert status == "failed"
    assert error == "Rate exceeded"


def test_schema_defaults_to_v1_for_read_only_tools():
    with patch(
        "aws_lighthouse.agent._detect_cost_anomalies",
        return_value={"ok": True, "data": [{"service": "EC2"}], "errors": []},
    ):
        payload = tool_detect_cost_anomalies.invoke({})
    assert payload == '[{"service": "EC2"}]'


def test_normalize_schema_like_args_maps_schema_version_to_schema():
    normalized, note = _normalize_schema_like_args(
        "tool_get_enabled_regions", {"schema_version": "v2"}
    )

    assert normalized == {"schema": "v2"}
    assert note is not None
    assert "mapped schema_version to schema" in note


def test_normalize_schema_like_args_replaces_invalid_schema_with_v1():
    normalized, note = _normalize_schema_like_args(
        "tool_get_enabled_regions", {"schema_version": "2024-07-01"}
    )

    assert normalized == {"schema": "v1"}
    assert note is not None
    assert "replaced invalid schema with v1" in note


def test_tools_node_repairs_schema_like_args_before_execution():
    msg = AIMessage(
        content="",
        tool_calls=[
            {
                "name": "tool_get_enabled_regions",
                "id": "call-1",
                "args": {"schema_version": "2024-07-01"},
            }
        ],
    )
    state = {"messages": [msg]}
    output = {"messages": [ToolMessage(content='["us-east-1"]', tool_call_id="call-1")]}

    with (
        patch("aws_lighthouse.agent.logger.error") as mock_error,
        patch(
            "aws_lighthouse.agent._tool_node.invoke", return_value=output
        ) as mock_invoke,
        patch("aws_lighthouse.agent.db_manager.update_audit_log_result"),
    ):
        result = tools_node(state)

    assert result == output
    invoked_state = mock_invoke.call_args.args[0]
    tool_call = invoked_state["messages"][-1].tool_calls[0]
    assert tool_call["args"] == {"schema": "v1"}
    mock_error.assert_called_once()


def test_local_opportunity_tools_are_safe():
    for name in (
        "tool_list_opportunities",
        "tool_get_opportunity_details",
        "tool_update_opportunity",
        "tool_plan_opportunities",
    ):
        assert name in SAFE_TOOLS


def test_list_opportunities_returns_db_rows_as_json():
    with (
        patch(
            "aws_lighthouse.agent.db_manager.get_latest_scan_activity",
            return_value={
                "recorded_at": "2026-03-06T11:00:00+00:00",
                "account_id": "123456789012",
                "scope_key": "multi-region:days=14",
            },
        ),
        patch(
            "aws_lighthouse.agent.db_manager.list_opportunities",
            return_value=[
                {
                    "account_id": "123456789012",
                    "fingerprint": "abc123",
                    "source_kind": "security",
                    "title": "Security finding: sg-1",
                    "summary": "Open SSH",
                    "severity": "HIGH",
                    "resource_type": None,
                    "resource_id": "sg-1",
                    "resource_name": "sg-1",
                    "region": "us-east-1",
                    "raw_payload": {"resource": "sg-1"},
                    "first_seen_at": "2026-03-06T10:00:00+00:00",
                    "last_seen_at": "2026-03-06T10:00:00+00:00",
                    "seen_count": 1,
                    "status": "open",
                    "owner": None,
                    "snooze_until": None,
                    "notes": "",
                    "resolution_reason": None,
                    "resolution_note": None,
                    "resolved_at": None,
                    "last_scan_scope": "multi-region:days=14",
                }
            ],
        ) as mock_list,
    ):
        payload = tool_list_opportunities.invoke({})

    mock_list.assert_called_once_with(
        account_id="123456789012",
        statuses=["open", "triaged", "in_progress", "snoozed"],
        source_kinds=None,
        severities=None,
        region=None,
        owner=None,
        limit=25,
    )
    assert "abc123" in payload
    assert "security" in payload


def test_get_opportunity_details_combines_state_and_history():
    opportunity = {
        "account_id": "123456789012",
        "fingerprint": "abc123",
        "source_kind": "security",
        "title": "Security finding: sg-1",
        "summary": "Open SSH",
        "severity": "HIGH",
        "resource_type": None,
        "resource_id": "sg-1",
        "resource_name": "sg-1",
        "region": "us-east-1",
        "raw_payload": {"resource": "sg-1"},
        "first_seen_at": "2026-03-06T10:00:00+00:00",
        "last_seen_at": "2026-03-06T10:00:00+00:00",
        "seen_count": 1,
        "status": "open",
        "owner": None,
        "snooze_until": None,
        "notes": "",
        "resolution_reason": None,
        "resolution_note": None,
        "resolved_at": None,
        "last_scan_scope": "multi-region:days=14",
    }
    with (
        patch(
            "aws_lighthouse.agent.db_manager.get_latest_scan_activity",
            return_value={
                "recorded_at": "2026-03-06T11:00:00+00:00",
                "account_id": "123456789012",
                "scope_key": "multi-region:days=14",
            },
        ),
        patch(
            "aws_lighthouse.agent.db_manager.get_opportunity",
            return_value=opportunity,
        ) as mock_get,
        patch(
            "aws_lighthouse.agent.db_manager.get_opportunity_events",
            return_value=[
                {
                    "account_id": "123456789012",
                    "fingerprint": "abc123",
                    "event_type": "created",
                    "timestamp": "2026-03-06 10:00:00",
                    "data": {"status": "open"},
                }
            ],
        ),
    ):
        payload = tool_get_opportunity_details.invoke({"fingerprint": "abc123"})

    mock_get.assert_called_once_with(
        fingerprint="abc123",
        account_id="123456789012",
    )
    assert "created" in payload
    assert "abc123" in payload


def test_update_opportunity_routes_to_db_manager():
    updated = {
        "account_id": "123456789012",
        "fingerprint": "abc123",
        "source_kind": "security",
        "title": "Security finding: sg-1",
        "summary": "Open SSH",
        "severity": "HIGH",
        "resource_type": None,
        "resource_id": "sg-1",
        "resource_name": "sg-1",
        "region": "us-east-1",
        "raw_payload": {"resource": "sg-1"},
        "first_seen_at": "2026-03-06T10:00:00+00:00",
        "last_seen_at": "2026-03-06T10:00:00+00:00",
        "seen_count": 1,
        "status": "snoozed",
        "owner": "platform",
        "snooze_until": "2026-03-13T00:00:00+00:00",
        "notes": "[2026-03-06T10:00:00+00:00] Waiting on owner",
        "resolution_reason": None,
        "resolution_note": None,
        "resolved_at": None,
        "last_scan_scope": "multi-region:days=14",
    }
    with (
        patch(
            "aws_lighthouse.agent.db_manager.get_latest_scan_activity",
            return_value={
                "recorded_at": "2026-03-06T11:00:00+00:00",
                "account_id": "123456789012",
                "scope_key": "multi-region:days=14",
            },
        ),
        patch(
            "aws_lighthouse.agent.db_manager.update_opportunity_state",
            return_value=updated,
        ) as mock_update,
    ):
        payload = tool_update_opportunity.invoke(
            {
                "fingerprint": "abc123",
                "status": "snoozed",
                "owner": "platform",
                "snooze_until": "2026-03-13T00:00:00+00:00",
                "note": "Waiting on owner",
            }
        )

    mock_update.assert_called_once_with(
        fingerprint="abc123",
        account_id="123456789012",
        status="snoozed",
        owner="platform",
        snooze_until="2026-03-13T00:00:00+00:00",
        note="Waiting on owner",
    )
    assert "snoozed" in payload
    assert "platform" in payload


def test_plan_opportunities_groups_results():
    with (
        patch(
            "aws_lighthouse.agent.db_manager.get_latest_scan_activity",
            return_value={
                "recorded_at": "2026-03-06T11:00:00+00:00",
                "account_id": "123456789012",
                "scope_key": "multi-region:days=14",
            },
        ),
        patch(
            "aws_lighthouse.agent.db_manager.list_opportunities",
            return_value=[
                {
                    "account_id": "123456789012",
                    "fingerprint": "abc123",
                    "source_kind": "security",
                    "title": "Security finding: sg-1",
                    "summary": "Open SSH",
                    "severity": "HIGH",
                    "resource_type": None,
                    "resource_id": "sg-1",
                    "resource_name": "sg-1",
                    "region": "us-east-1",
                    "raw_payload": {"resource": "sg-1"},
                    "first_seen_at": "2026-03-06T10:00:00+00:00",
                    "last_seen_at": "2026-03-06T10:00:00+00:00",
                    "seen_count": 1,
                    "status": "open",
                    "owner": None,
                    "snooze_until": None,
                    "notes": "",
                    "resolution_reason": None,
                    "resolution_note": None,
                    "resolved_at": None,
                    "last_scan_scope": "multi-region:days=14",
                }
            ],
        ) as mock_list,
    ):
        payload = tool_plan_opportunities.invoke({})

    mock_list.assert_called_once_with(
        account_id="123456789012",
        statuses=["open", "triaged", "in_progress", "snoozed"],
        source_kinds=None,
        severities=None,
        region=None,
        owner=None,
        limit=25,
    )
    assert "groups" in payload
    assert "security" in payload


# ---------------------------------------------------------------------------
# CRIT-1: Guard state["messages"][-1] empty-state edge cases
# ---------------------------------------------------------------------------


def test_should_require_approval_empty_messages_returns_end():
    """An empty messages list must not raise IndexError — must return 'end'."""
    assert should_require_approval({"messages": []}) == "end"


def test_approval_node_empty_messages_returns_not_approved():
    """approval_node with empty messages must return approved=False without crashing."""
    result = approval_node({"messages": []})
    assert result.get("approved") is False


def test_should_require_approval_non_ai_message_returns_end():
    """A HumanMessage as the last message should not trigger approval."""
    state = {"messages": [HumanMessage(content="hello")]}
    assert should_require_approval(state) == "end"


# ---------------------------------------------------------------------------
# HIGH-2: isinstance(AIMessage) guard in approval_node
# ---------------------------------------------------------------------------


def test_approval_node_non_ai_message_returns_not_approved():
    """approval_node must handle non-AIMessage last message gracefully."""
    state = {"messages": [HumanMessage(content="hello")]}
    result = approval_node(state)
    assert result.get("approved") is False
    assert result.get("messages") == []


# ---------------------------------------------------------------------------
# CRIT-2: Runtime validation in _parse_*_filter helpers
# ---------------------------------------------------------------------------


def test_parse_status_filter_accepts_valid_statuses():
    result = _parse_status_filter("open,resolved")
    assert result == ["open", "resolved"]


def test_parse_status_filter_rejects_invalid_status():
    import pytest

    with pytest.raises(ValueError, match="Unknown opportunity status"):
        _parse_status_filter("open,bogus_status")


def test_parse_status_filter_empty_string_returns_none():
    assert _parse_status_filter("") is None


def test_parse_source_kind_filter_rejects_invalid_kind():
    import pytest

    with pytest.raises(ValueError, match="Unknown opportunity source kind"):
        _parse_source_kind_filter("security,not_a_kind")


def test_parse_severity_filter_accepts_valid_severities():
    result = _parse_severity_filter("HIGH,LOW")
    assert result == ["HIGH", "LOW"]


def test_parse_severity_filter_rejects_invalid_severity():
    import pytest

    with pytest.raises(ValueError, match="Unknown severity"):
        _parse_severity_filter("HIGH,CRITICAL")


def test_list_opportunities_returns_error_on_invalid_status():
    with patch(
        "aws_lighthouse.agent.db_manager.get_latest_scan_activity",
        return_value={
            "recorded_at": "2026-03-06T11:00:00+00:00",
            "account_id": "123456789012",
            "scope_key": "multi-region:days=14",
        },
    ):
        payload = tool_list_opportunities.invoke({"statuses": "open,not_real"})
    import json

    data = json.loads(payload)
    assert "error" in data


# ---------------------------------------------------------------------------
# HIGH-3: Malformed JSON returns failed classification with warning
# ---------------------------------------------------------------------------


def test_classify_tool_result_malformed_json_returns_failed():
    with patch("aws_lighthouse.agent.logger.warn") as mock_warn:
        status, error = _classify_tool_result("{not valid json}")
    assert status == "failed"
    assert error is not None
    assert "malformed" in error
    mock_warn.assert_called_once()


# ---------------------------------------------------------------------------
# HIGH-4: SAFE_TOOLS cross-check against actual tools list
# ---------------------------------------------------------------------------


def test_safe_tools_all_exist_in_tools_list():
    """Every name in SAFE_TOOLS must correspond to a real tool in the tools list."""
    tool_names = {t.name for t in tools}
    unknown = SAFE_TOOLS - tool_names
    assert not unknown, (
        f"SAFE_TOOLS references tool(s) that don't exist: {unknown}. "
        "This is a silent approval bypass — remove or rename to match."
    )


# ---------------------------------------------------------------------------
# TEST-2: End-to-end state machine — full graph cycle
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_full_cycle_safe_tool_auto_approved_then_ends():
    """
    Simulate: agent calls a safe read-only tool → auto-approved → tool executes
    → agent called again with result → ends.

    Node sequence: agent → (should_require_approval='tools') → tools_node
                   → agent → (should_require_approval='end').
    The approval_node is never reached for safe-only calls.
    """
    safe_tc = {
        "name": "tool_get_ec2_inventory",
        "id": "call-safe-1",
        "args": {"region": "us-east-1"},
    }
    tool_result_msg = ToolMessage(
        content='[{"InstanceId":"i-abc","State":"running"}]',
        tool_call_id="call-safe-1",
    )
    final_ai_msg = AIMessage(content="Found 1 running EC2 instance.", tool_calls=[])

    # Turn 1: agent returns a safe tool call
    turn1_ai = AIMessage(content="", tool_calls=[safe_tc])
    state1 = {"messages": [HumanMessage(content="List my EC2 instances"), turn1_ai]}

    # safe tool → routed directly to tools (no approval)
    assert should_require_approval(state1) == "tools"

    # tools_node executes the safe tool
    tool_output = {"messages": [tool_result_msg]}
    with (
        patch("aws_lighthouse.agent._tool_node.invoke", return_value=tool_output),
        patch("aws_lighthouse.agent.db_manager.record_audit_log"),
        patch("aws_lighthouse.agent.db_manager.update_audit_log_result"),
    ):
        tools_result = tools_node(state1)

    assert tools_result == tool_output

    # Turn 2: agent receives tool result and decides to end (no tool calls)
    state2 = {
        "messages": [
            HumanMessage(content="List my EC2 instances"),
            turn1_ai,
            tool_result_msg,
            final_ai_msg,
        ]
    }
    assert should_require_approval(state2) == "end"


@pytest.mark.integration
def test_full_cycle_destructive_tool_denied_returns_to_agent():
    """
    Simulate: agent calls a destructive tool → approval_node shown → user denies
    → rejections injected → routed back to agent → agent replies without tools → ends.

    Node sequence: agent → (should_require_approval='approval') → approval_node
                   [denied] → _route_after_approval='agent' → agent → end.
    """
    destructive_tc = {
        "name": "terminate_ec2",
        "id": "call-destr-1",
        "args": {"instance_ids": ["i-badcafe"]},
    }
    # Turn 1: agent calls a destructive tool
    agent_msg = AIMessage(
        content="I will terminate the instance.", tool_calls=[destructive_tc]
    )
    state = {"messages": [HumanMessage(content="Terminate i-badcafe"), agent_msg]}

    # destructive tool → requires approval
    assert should_require_approval(state) == "approval"

    # User denies
    with patch("typer.prompt", return_value="n"), patch("aws_lighthouse.agent.logger"):
        approval_result = approval_node(state)

    assert approval_result["approved"] is False
    rejections = approval_result["messages"]
    assert len(rejections) == 1
    assert rejections[0].tool_call_id == "call-destr-1"

    # After denial, route is back to agent (not tools)
    merged_state = {**state, **approval_result}
    assert _route_after_approval(merged_state) == "agent"

    # Agent replies acknowledging the denial — no more tool calls
    ack_msg = AIMessage(
        content="Understood, I will not terminate the instance.", tool_calls=[]
    )
    final_state = {
        "messages": [
            HumanMessage(content="Terminate i-badcafe"),
            agent_msg,
            *rejections,
            ack_msg,
        ]
    }
    assert should_require_approval(final_state) == "end"


@pytest.mark.integration
def test_full_cycle_safe_plus_destructive_batch_requires_approval():
    """
    A batch with one safe and one destructive tool must still require approval.
    The safe tool must NOT auto-execute if any sibling is destructive.
    """
    tcs = [
        {"name": "tool_get_ec2_inventory", "id": "call-safe", "args": {}},
        {
            "name": "terminate_ec2",
            "id": "call-destr",
            "args": {"instance_ids": ["i-1"]},
        },
    ]
    ai_msg = AIMessage(content="", tool_calls=tcs)
    state = {"messages": [HumanMessage(content="Inspect then terminate"), ai_msg]}

    # Mixed batch must go to approval, NOT directly to tools
    route = should_require_approval(state)
    assert route == "approval", (
        f"Mixed safe+destructive batch routed to {route!r} instead of 'approval'. "
        "This would let the destructive tool bypass the approval gate."
    )

    # User approves
    with patch("typer.prompt", return_value="y"), patch("aws_lighthouse.agent.logger"):
        approval_result = approval_node(state)

    assert approval_result.get("approved") is True
    assert _route_after_approval({**state, **approval_result}) == "tools"
