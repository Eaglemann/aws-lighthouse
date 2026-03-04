"""
Tests for the LangGraph agent security gate (should_require_approval)
and the approval_node approval/denial paths.
"""

from unittest.mock import MagicMock, patch

from langchain_core.messages import AIMessage, ToolMessage

from aws_lighthouse.agent import (
    SAFE_TOOLS,
    _classify_tool_result,
    _record_tool_execution_results,
    _route_after_approval,
    approval_node,
    should_require_approval,
)

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
        "messages": [ToolMessage(content='{"stdout":"","error":"Timeout"}', tool_call_id="call-xyz")]
    }

    with patch("aws_lighthouse.agent.db_manager.update_audit_log_result") as mock_update:
        _record_tool_execution_results(state, output)

    mock_update.assert_called_once_with(
        tool_call_id="call-xyz",
        result='{"stdout":"","error":"Timeout"}',
        execution_status="failed",
        error="Timeout",
    )
