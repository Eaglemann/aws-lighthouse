# ruff: noqa: E402
import json
import os
from collections.abc import Sequence
from typing import Annotated, Any, NotRequired, TypedDict, cast

from langchain_core.messages import AIMessage, BaseMessage, ToolMessage
from langchain_core.tools import tool
from langchain_ollama import ChatOllama
from langgraph.graph import END, StateGraph
from langgraph.graph.message import add_messages

from .db import db_manager
from .logger import logger
from .scan_contract import error_result, ok_result, to_v1_payload, to_v2_payload
from .tools.bash import execute_bash, read_file, write_file
from .types import ScanResult


# 1. State Definition
class AgentState(TypedDict):
    """The complete state of the LangGraph execution loop."""

    messages: Annotated[Sequence[BaseMessage], add_messages]
    # Set by approval_node: True = user approved, False = user denied.
    # Consumed by _route_after_approval to decide whether to run tools.
    approved: NotRequired[bool]


# 3. Tool Binding
# Convert bare functions to LangChain @tools based on Bash specs from Phase 1
@tool
def tool_read_file(filepath: str, max_lines: int | None = None) -> str:
    """Reads the contents of a local file safely."""
    # Convert kwargs to BaseModel instance dynamically or pass directly
    from .tools.bash import ReadFileInput

    return read_file(ReadFileInput(filepath=filepath, max_lines=max_lines))


@tool
def tool_write_file(filepath: str, content: str, overwrite: bool = False) -> str:
    """Writes content to a local file, creating parent directories if needed."""
    from .tools.bash import WriteFileInput

    return write_file(
        WriteFileInput(filepath=filepath, content=content, overwrite=overwrite)
    )


@tool
def tool_execute_bash(
    command: str, cwd: str | None = None, timeout_seconds: int = 60
) -> str:
    """Executes a bash command and returns stdout/stderr."""
    from .tools.bash import ExecuteBashInput

    res = execute_bash(
        ExecuteBashInput(command=command, cwd=cwd, timeout_seconds=timeout_seconds)
    )
    return json.dumps(res)


from .tools.cloudwatch_scan import detect_cloudwatch_gaps as _detect_cloudwatch_gaps
from .tools.cost_anomaly import detect_cost_anomalies as _detect_cost_anomalies
from .tools.cost_scan import run_cost_scan as _run_cost_scan
from .tools.iam_scan import detect_overpermissive_iam as _detect_overpermissive_iam
from .tools.inventory import (
    get_ec2_inventory as _get_ec2_inventory,
)
from .tools.inventory import (
    get_lambda_inventory as _get_lambda_inventory,
)
from .tools.inventory import (
    get_rds_inventory as _get_rds_inventory,
)
from .tools.inventory import (
    get_s3_inventory as _get_s3_inventory,
)
from .tools.multi_region import get_enabled_regions as _get_enabled_regions
from .tools.remediation import delete_ebs, terminate_ec2
from .tools.ri_sp_coverage import get_ri_sp_coverage as _get_ri_sp_coverage
from .tools.security import s3_block_public_access
from .tools.security_scan import run_security_scan as _run_security_scan
from .tools.tagging import check_tagging_compliance as _check_tagging_compliance
from .tools.terraform import parse_terraform_context


@tool
def tool_get_enabled_regions(schema: str = "v1") -> str:
    """
    List all AWS regions that are enabled for this account (opted-in or opt-in-not-required).
    Call this first when the user asks for a multi-region analysis so you know which regions to scan.
    """
    result = _get_enabled_regions()
    return json.dumps(to_v2_payload(result) if schema == "v2" else to_v1_payload(result))


@tool
def tool_get_ec2_inventory(region: str = "", schema: str = "v1") -> str:
    """Retrieve all EC2 instances and their current state.
    Pass a region name (e.g. 'us-west-2') to scan a specific region, or leave empty for the default."""
    result = _get_ec2_inventory(region=region or None)
    return json.dumps(to_v2_payload(result) if schema == "v2" else to_v1_payload(result))


@tool
def tool_get_rds_inventory(region: str = "", schema: str = "v1") -> str:
    """Retrieve all RDS instances and their current state.
    Pass a region name (e.g. 'eu-west-1') to scan a specific region, or leave empty for the default."""
    result = _get_rds_inventory(region=region or None)
    return json.dumps(to_v2_payload(result) if schema == "v2" else to_v1_payload(result))


@tool
def tool_get_s3_inventory(schema: str = "v1") -> str:
    """List all S3 buckets. S3 is a global service — no region parameter needed."""
    result = _get_s3_inventory()
    return json.dumps(to_v2_payload(result) if schema == "v2" else to_v1_payload(result))


@tool
def tool_get_lambda_inventory(region: str = "", schema: str = "v1") -> str:
    """List all Lambda functions with runtime, memory size, timeout, code size, and whether they are stale (>180 days since last deploy).
    Pass a region name to scan a specific region, or leave empty for the default."""
    result = _get_lambda_inventory(region=region or None)
    return json.dumps(to_v2_payload(result) if schema == "v2" else to_v1_payload(result))


@tool
def tool_detect_cloudwatch_gaps(region: str = "", schema: str = "v1") -> str:
    """
    Find EC2 instances, RDS databases, and Lambda functions missing CloudWatch alarms.
    EC2: CPUUtilization, StatusCheckFailed.
    RDS: CPUUtilization, FreeStorageSpace.
    Lambda: Errors, Throttles.
    Returns one finding per resource listing every uncovered metric.
    Pass a region name to check a specific region, or leave empty for the default.
    """
    result = _detect_cloudwatch_gaps(region=region or None)
    return json.dumps(to_v2_payload(result) if schema == "v2" else to_v1_payload(result))


@tool
def tool_detect_overpermissive_iam(schema: str = "v1") -> str:
    """
    Scan IAM users, roles, and groups for over-permissive policies.
    Flags Action:* on Resource:* as HIGH (full admin) and
    Action:<service>:* on Resource:* as MEDIUM (service-level wildcard).
    Covers inline policies, customer-managed policies, and known dangerous
    AWS-managed policies (AdministratorAccess, PowerUserAccess).
    """
    result = _detect_overpermissive_iam()
    return json.dumps(to_v2_payload(result) if schema == "v2" else to_v1_payload(result))


@tool
def tool_check_tagging_compliance(
    required_tags: str = "Environment,Owner", region: str = "", schema: str = "v1"
) -> str:
    """
    Check EC2, RDS, S3, and Lambda resources for missing required tags.
    Pass a comma-separated list of tag keys to enforce (default: Environment,Owner).
    Pass a region name to check a specific region, or leave empty for the default.
    Returns one finding per non-compliant resource.
    """
    tags = [t.strip() for t in required_tags.split(",") if t.strip()]
    result = _check_tagging_compliance(required_tags=tags, region=region or None)
    return json.dumps(to_v2_payload(result) if schema == "v2" else to_v1_payload(result))


@tool
def tool_get_ri_sp_coverage(days: int = 30, schema: str = "v1") -> str:
    """
    Fetch Reserved Instance and Savings Plan coverage and utilization from Cost Explorer.
    Shows what % of eligible spend is covered by commitments vs on-demand,
    how well existing commitments are utilized, and the dollar value of uncovered spend.
    """
    result = _get_ri_sp_coverage(days=days)
    return json.dumps(to_v2_payload(result) if schema == "v2" else to_v1_payload(result))


@tool
def tool_detect_cost_anomalies(threshold_pct: float = 50.0, schema: str = "v1") -> str:
    """
    Compare the last 7 days of per-service AWS spend against the prior 7-day baseline.
    Returns services whose cost increased by more than threshold_pct (default 50%).
    Useful for spotting unexpected spending spikes before the bill arrives.
    """
    result = _detect_cost_anomalies(threshold_pct=threshold_pct)
    return json.dumps(to_v2_payload(result) if schema == "v2" else to_v1_payload(result))


@tool
def tool_run_security_scan(
    region: str = "", include_global: bool = True, schema: str = "v1"
) -> str:
    """
    Run a comprehensive security scan against the current AWS account.
    Checks: root MFA, IAM access key age (>90 days), IAM users without MFA,
    open security groups (SSH/RDP), publicly accessible RDS instances,
    S3 Block Public Access, S3 default encryption, IMDSv2 enforcement,
    EBS encryption at rest, CloudTrail logging, and GuardDuty enabled.

    Pass a region name to target a specific region; leave empty for the default region.
    Set include_global=False when calling in a loop over multiple regions to avoid
    duplicate account-wide findings (root MFA, IAM key age, S3).

    Returns a list of findings, each with severity (HIGH/MEDIUM), resource, and finding.
    """
    r = region or None
    s3_result: ScanResult = _get_s3_inventory() if include_global else ok_result([])
    rds_result = _get_rds_inventory(region=r)
    sec_result = _run_security_scan(
        s3s=s3_result["data"],
        rdss=rds_result["data"],
        region=r,
        include_global=include_global,
    )
    combined = error_result(
        data=sec_result["data"],
        errors=[*s3_result["errors"], *rds_result["errors"], *sec_result["errors"]],
    )
    return json.dumps(to_v2_payload(combined) if schema == "v2" else to_v1_payload(combined))


@tool
def tool_run_cost_scan(region: str = "", schema: str = "v1") -> str:
    """
    Scan for cost waste in the AWS account.
    Checks: unattached EBS volumes, stopped EC2 instances (still paying for EBS),
    EBS snapshots older than 90 days, and unassociated Elastic IPs (~$0.005/hr each).

    Pass a region name to target a specific region; leave empty for the default region.
    Returns a list of findings with resource ID, description, and remediation hints.
    """
    result = _run_cost_scan(region=region or None)
    return json.dumps(to_v2_payload(result) if schema == "v2" else to_v1_payload(result))


tools = [
    tool_read_file,
    tool_write_file,
    tool_execute_bash,
    terminate_ec2,
    delete_ebs,
    s3_block_public_access,
    parse_terraform_context,
    tool_get_enabled_regions,
    tool_get_ec2_inventory,
    tool_get_rds_inventory,
    tool_get_s3_inventory,
    tool_get_lambda_inventory,
    tool_get_ri_sp_coverage,
    tool_detect_cost_anomalies,
    tool_run_cost_scan,
    tool_check_tagging_compliance,
    tool_detect_overpermissive_iam,
    tool_detect_cloudwatch_gaps,
    tool_run_security_scan,
]

from langgraph.prebuilt import ToolNode

# The ToolNode executes the functions requested by the LLM
_tool_node = ToolNode(tools)


def _classify_tool_result(content: str) -> tuple[str, str | None]:
    """Return (execution_status, error) for a tool output payload."""
    stripped = content.strip()
    if stripped.lower().startswith("error:"):
        return "failed", stripped
    if stripped.startswith("{"):
        try:
            payload = json.loads(stripped)
            if isinstance(payload, dict) and payload.get("error"):
                return "failed", str(payload["error"])
            if isinstance(payload, dict) and payload.get("ok") is False:
                errors = payload.get("errors", [])
                if isinstance(errors, list) and errors:
                    first = errors[0]
                    if isinstance(first, dict):
                        message = first.get("message")
                        if message:
                            return "failed", str(message)
                    return "failed", str(first)
                return "failed", "Tool reported ok=false"
        except ValueError:
            pass
    return "executed", None


def _record_tool_execution_results(state: AgentState, output: dict) -> None:
    """Persist execution outcomes for every ToolMessage emitted by ToolNode."""
    for msg in output.get("messages", []):
        if not isinstance(msg, ToolMessage):
            continue
        tool_call_id = msg.tool_call_id
        if not tool_call_id:
            continue
        content = str(msg.content)
        status, error = _classify_tool_result(content)
        db_manager.update_audit_log_result(
            tool_call_id=tool_call_id,
            result=content,
            execution_status=status,
            error=error,
        )


def tools_node(state: AgentState) -> dict:
    """Execute tools then persist execution outcomes in the audit log."""
    output = cast(dict[str, Any], _tool_node.invoke(state))
    _record_tool_execution_results(state, output)
    return output


def approval_node(state: AgentState) -> dict:
    """The Human-in-the-loop intercept node.

    Sets state["approved"] = True on approval, False on denial.
    On denial, also injects synthetic ToolMessage rejections so the LLM
    receives a well-formed response for each pending tool call.
    _route_after_approval() reads the approved flag to decide the next node.
    """
    import typer

    # Find the last AIMessage with tool calls
    last_message: AIMessage = state["messages"][-1]  # type: ignore[assignment]

    logger.print_header("AWS Lighthouse - Execution Plan")
    logger.warn("The agent has proposed the following infrastructure changes:")

    if last_message.content:
        logger.console.print(
            f"\n[bold yellow]Agent Reasoning:[/bold yellow]\n{last_message.content}\n"
        )

    for tc in last_message.tool_calls:
        logger.step(f"Tool: [bold cyan]{tc['name']}[/bold cyan]")
        logger.step(f"Arguments: {json.dumps(tc['args'], indent=2)}")

    choice = typer.prompt("\nDo you approve these actions? (y/n)", default="n")
    if choice.lower() != "y":
        logger.error("User denied the execution plan.")

        rejections = []
        for tc in last_message.tool_calls:
            db_manager.record_audit_log(
                tc["name"],
                json.dumps(tc["args"]),
                "denied",
                result="User explicitly denied execution of this tool.",
                tool_call_id=tc["id"],
                execution_status="denied",
            )
            rejections.append(
                ToolMessage(
                    content="User explicitly denied execution of this tool.",
                    tool_call_id=tc["id"],
                )
            )
        # approved=False prevents _route_after_approval from reaching ToolNode
        return {"approved": False, "messages": rejections}

    for tc in last_message.tool_calls:
        db_manager.record_audit_log(
            tc["name"],
            json.dumps(tc["args"]),
            "approved",
            tool_call_id=tc["id"],
            execution_status="pending",
        )
    logger.success("Execution plan approved. Proceeding...")
    return {"approved": True}


def _route_after_approval(state: AgentState) -> str:
    """Conditional edge: route to tools only if the user approved.

    Defaults to 'agent' when approved is absent or False, so a denial
    always routes back to the LLM (which can acknowledge the denial and
    ask the user what to do next) rather than executing the tools.
    """
    return "tools" if state.get("approved") else "agent"


# SAFE_TOOLS: exact tool name strings that bypass the human approval node.
# Only read-only, non-mutative tools belong here.
# NEVER add a destructive tool — doing so silently removes user approval for that tool.
# The routing function should_require_approval() consults this set.
SAFE_TOOLS = {
    # tool_read_file intentionally excluded: it can access any local path,
    # including ~/.aws/credentials and ~/.ssh/. Requires approval + path check in bash.py.
    "parse_terraform_context",
    "tool_get_enabled_regions",
    "tool_get_ec2_inventory",
    "tool_get_rds_inventory",
    "tool_get_s3_inventory",
    "tool_get_lambda_inventory",
    "tool_get_ri_sp_coverage",
    "tool_detect_cost_anomalies",
    "tool_run_cost_scan",
    "tool_check_tagging_compliance",
    "tool_detect_overpermissive_iam",
    "tool_detect_cloudwatch_gaps",
    "tool_run_security_scan",
}


def should_require_approval(state: AgentState) -> str:
    """Routing logic to intercept dangerous tools before they hit ToolNode."""
    last_message: AIMessage = state["messages"][-1]  # type: ignore[assignment]
    if not last_message.tool_calls:
        return "end"

    # Only require approval if at least one called tool is destructive
    for tc in last_message.tool_calls:
        if tc["name"] not in SAFE_TOOLS:
            return "approval"

    # All tools are safe — log as auto_approved before ToolNode runs
    for tc in last_message.tool_calls:
        db_manager.record_audit_log(
            tc["name"],
            json.dumps(tc["args"]),
            "auto_approved",
            tool_call_id=tc["id"],
            execution_status="pending",
        )
    return "tools"


def create_agent_graph():
    """Instantiate and compile the baseline LangGraph agent with a memory checkpointer."""
    from langgraph.checkpoint.memory import MemorySaver

    # Deferred from module scope so importing agent.py never connects to Ollama.
    # This lets --help, tests, and any non-shell code path import freely.
    _ollama_host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    llm = ChatOllama(model="gpt-oss:120b-cloud", temperature=0, base_url=_ollama_host)
    llm_with_tools = llm.bind_tools(tools)

    def agent_node(state: AgentState):
        """The primary reasoning node."""
        logger.action_start("Agent is thinking...")
        response = llm_with_tools.invoke(state["messages"])
        return {"messages": [response]}

    workflow = StateGraph(AgentState)

    workflow.add_node("agent", agent_node)
    workflow.add_node("approval", approval_node)
    workflow.add_node("tools", tools_node)

    workflow.set_entry_point("agent")

    # After the agent thinks, it either ends, goes to approval, or runs safe tools directly
    workflow.add_conditional_edges(
        "agent",
        should_require_approval,
        {"end": END, "approval": "approval", "tools": "tools"},
    )

    # After approval: run tools on approval, return to agent on denial.
    # The unconditional add_edge("approval","tools") was the bug: it routed
    # to ToolNode regardless of the user's decision, relying on ToolNode's
    # undefined behaviour when all tool_call_ids already had ToolMessage responses.
    workflow.add_conditional_edges(
        "approval",
        _route_after_approval,
        {"tools": "tools", "agent": "agent"},
    )

    # After tools execute, we go back to the agent
    workflow.add_edge("tools", "agent")

    return workflow.compile(checkpointer=MemorySaver())
