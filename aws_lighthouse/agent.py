# ruff: noqa: E402
import json
import os
from typing import TypedDict, Annotated, Sequence
from langchain_core.messages import AIMessage, BaseMessage
from langchain_ollama import ChatOllama
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from langchain_core.tools import tool

from .logger import logger
from .tools.bash import read_file, write_file, execute_bash


# 1. State Definition
class AgentState(TypedDict):
    """The complete state of the LangGraph execution loop."""

    messages: Annotated[Sequence[BaseMessage], add_messages]
    # Approval state is handled externally via should_require_approval() and approval_node.


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


from .tools.remediation import terminate_ec2, delete_ebs
from .tools.security import s3_block_public_access
from .tools.terraform import parse_terraform_context
from .tools.inventory import (
    get_ec2_inventory as _get_ec2_inventory,
    get_rds_inventory as _get_rds_inventory,
    get_s3_inventory as _get_s3_inventory,
    get_lambda_inventory as _get_lambda_inventory,
)
from .tools.cost_anomaly import detect_cost_anomalies as _detect_cost_anomalies
from .tools.cost_scan import run_cost_scan as _run_cost_scan
from .tools.tagging import check_tagging_compliance as _check_tagging_compliance
from .tools.iam_scan import detect_overpermissive_iam as _detect_overpermissive_iam
from .tools.cloudwatch_scan import detect_cloudwatch_gaps as _detect_cloudwatch_gaps
from .tools.multi_region import get_enabled_regions as _get_enabled_regions
from .tools.ri_sp_coverage import get_ri_sp_coverage as _get_ri_sp_coverage
from .tools.security_scan import run_security_scan as _run_security_scan


@tool
def tool_get_enabled_regions() -> str:
    """
    List all AWS regions that are enabled for this account (opted-in or opt-in-not-required).
    Call this first when the user asks for a multi-region analysis so you know which regions to scan.
    """
    return json.dumps(_get_enabled_regions())


@tool
def tool_get_ec2_inventory(region: str = "") -> str:
    """Retrieve all EC2 instances and their current state.
    Pass a region name (e.g. 'us-west-2') to scan a specific region, or leave empty for the default."""
    return json.dumps(_get_ec2_inventory(region=region or None))


@tool
def tool_get_rds_inventory(region: str = "") -> str:
    """Retrieve all RDS instances and their current state.
    Pass a region name (e.g. 'eu-west-1') to scan a specific region, or leave empty for the default."""
    return json.dumps(_get_rds_inventory(region=region or None))


@tool
def tool_get_s3_inventory() -> str:
    """List all S3 buckets. S3 is a global service — no region parameter needed."""
    return json.dumps(_get_s3_inventory())


@tool
def tool_get_lambda_inventory(region: str = "") -> str:
    """List all Lambda functions with runtime, memory size, timeout, code size, and whether they are stale (>180 days since last deploy).
    Pass a region name to scan a specific region, or leave empty for the default."""
    return json.dumps(_get_lambda_inventory(region=region or None))


@tool
def tool_detect_cloudwatch_gaps(region: str = "") -> str:
    """
    Find EC2 instances, RDS databases, and Lambda functions missing CloudWatch alarms.
    EC2: CPUUtilization, StatusCheckFailed.
    RDS: CPUUtilization, FreeStorageSpace.
    Lambda: Errors, Throttles.
    Returns one finding per resource listing every uncovered metric.
    Pass a region name to check a specific region, or leave empty for the default.
    """
    return json.dumps(_detect_cloudwatch_gaps(region=region or None))


@tool
def tool_detect_overpermissive_iam() -> str:
    """
    Scan IAM users, roles, and groups for over-permissive policies.
    Flags Action:* on Resource:* as HIGH (full admin) and
    Action:<service>:* on Resource:* as MEDIUM (service-level wildcard).
    Covers inline policies, customer-managed policies, and known dangerous
    AWS-managed policies (AdministratorAccess, PowerUserAccess).
    """
    return json.dumps(_detect_overpermissive_iam())


@tool
def tool_check_tagging_compliance(
    required_tags: str = "Environment,Owner", region: str = ""
) -> str:
    """
    Check EC2, RDS, S3, and Lambda resources for missing required tags.
    Pass a comma-separated list of tag keys to enforce (default: Environment,Owner).
    Pass a region name to check a specific region, or leave empty for the default.
    Returns one finding per non-compliant resource.
    """
    tags = [t.strip() for t in required_tags.split(",") if t.strip()]
    return json.dumps(
        _check_tagging_compliance(required_tags=tags, region=region or None)
    )


@tool
def tool_get_ri_sp_coverage(days: int = 30) -> str:
    """
    Fetch Reserved Instance and Savings Plan coverage and utilization from Cost Explorer.
    Shows what % of eligible spend is covered by commitments vs on-demand,
    how well existing commitments are utilized, and the dollar value of uncovered spend.
    """
    return json.dumps(_get_ri_sp_coverage(days=days))


@tool
def tool_detect_cost_anomalies(threshold_pct: float = 50.0) -> str:
    """
    Compare the last 7 days of per-service AWS spend against the prior 7-day baseline.
    Returns services whose cost increased by more than threshold_pct (default 50%).
    Useful for spotting unexpected spending spikes before the bill arrives.
    """
    return json.dumps(_detect_cost_anomalies(threshold_pct=threshold_pct))


@tool
def tool_run_security_scan(region: str = "", include_global: bool = True) -> str:
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
    s3s = _get_s3_inventory() if include_global else []
    rdss = _get_rds_inventory(region=r)
    return json.dumps(
        _run_security_scan(s3s=s3s, rdss=rdss, region=r, include_global=include_global)
    )


@tool
def tool_run_cost_scan(region: str = "") -> str:
    """
    Scan for cost waste in the AWS account.
    Checks: unattached EBS volumes, stopped EC2 instances (still paying for EBS),
    EBS snapshots older than 90 days, and unassociated Elastic IPs (~$0.005/hr each).

    Pass a region name to target a specific region; leave empty for the default region.
    Returns a list of findings with resource ID, description, and remediation hints.
    """
    return json.dumps(_run_cost_scan(region=region or None))


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
tool_node = ToolNode(tools)


def approval_node(state: AgentState):
    """The Human-in-the-loop intercept node."""
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
        # Returning a synthetic tool error so the LLM knows it was rejected
        from langchain_core.messages import ToolMessage

        rejections = []
        for tc in last_message.tool_calls:
            rejections.append(
                ToolMessage(
                    content="User explicitly denied execution of this tool.",
                    tool_call_id=tc["id"],
                )
            )
        return {"messages": rejections}

    logger.success("Execution plan approved. Proceeding...")
    return {}  # Empty update — proceed with existing tool calls in state


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
    workflow.add_node("tools", tool_node)

    workflow.set_entry_point("agent")

    # After the agent thinks, it either ends, goes to approval, or runs safe tools directly
    workflow.add_conditional_edges(
        "agent",
        should_require_approval,
        {"end": END, "approval": "approval", "tools": "tools"},
    )

    # After approval, we execute tools
    workflow.add_edge("approval", "tools")

    # After tools execute, we go back to the agent
    workflow.add_edge("tools", "agent")

    return workflow.compile(checkpointer=MemorySaver())
