# ruff: noqa: E402
import json
import os
from collections.abc import Sequence
from typing import Annotated, Any, Literal, NotRequired, TypedDict, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import urlopen

from langchain_core.messages import AIMessage, BaseMessage, ToolMessage
from langchain_core.tools import tool
from langchain_ollama import ChatOllama
from langgraph.graph import END, StateGraph
from langgraph.graph.message import add_messages
from pydantic import BaseModel, ConfigDict, Field

from .db import db_manager
from .logger import logger
from .opportunities import build_opportunity_plan, default_list_statuses
from .scan_contract import error_result, ok_result, to_v1_payload, to_v2_payload
from .tools.bash import execute_bash, read_file, write_file
from .types import OpportunitySourceKind, OpportunityStatus, ScanResult, Severity

OLLAMA_DEFAULT_HOST = "http://localhost:11434"
OLLAMA_MODEL_NAME = "gpt-oss:120b-cloud"
OllamaRuntimeReason = Literal["ok", "unavailable", "invalid_response", "model_missing"]
_SCHEMA_GUARDED_TOOLS: frozenset[str] = frozenset(
    {
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
)


class OllamaRuntimeStatus(TypedDict):
    """Health check result for the local Ollama runtime."""

    ok: bool
    reason: OllamaRuntimeReason
    host: str
    model: str
    detail: str


def get_ollama_host() -> str:
    """Return the effective Ollama host, normalized for URL composition."""
    return os.getenv("OLLAMA_HOST", OLLAMA_DEFAULT_HOST).rstrip("/")


def check_ollama_runtime(timeout_seconds: float = 2.0) -> OllamaRuntimeStatus:
    """Probe the local Ollama runtime and verify the configured model is present."""
    host = get_ollama_host()
    model = OLLAMA_MODEL_NAME
    parsed_host = urlsplit(host)
    if parsed_host.scheme not in {"http", "https"}:
        return {
            "ok": False,
            "reason": "unavailable",
            "host": host,
            "model": model,
            "detail": (
                "OLLAMA_HOST must use http or https; "
                f"received scheme '{parsed_host.scheme or 'none'}'."
            ),
        }
    try:
        with urlopen(  # noqa: S310 - scheme is validated against http/https above
            f"{host}/api/tags",
            timeout=timeout_seconds,
        ) as response:
            status = getattr(response, "status", response.getcode())
            payload_bytes = response.read()
    except HTTPError as exc:
        return {
            "ok": False,
            "reason": "unavailable",
            "host": host,
            "model": model,
            "detail": f"HTTP {exc.code}: {exc.reason}",
        }
    except URLError as exc:
        return {
            "ok": False,
            "reason": "unavailable",
            "host": host,
            "model": model,
            "detail": str(exc.reason),
        }
    except OSError as exc:
        return {
            "ok": False,
            "reason": "unavailable",
            "host": host,
            "model": model,
            "detail": str(exc),
        }

    if status != 200:
        return {
            "ok": False,
            "reason": "unavailable",
            "host": host,
            "model": model,
            "detail": f"Unexpected HTTP status: {status}",
        }

    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {
            "ok": False,
            "reason": "invalid_response",
            "host": host,
            "model": model,
            "detail": f"Invalid response from Ollama: {exc}",
        }

    raw_models = payload.get("models")
    if not isinstance(raw_models, list):
        return {
            "ok": False,
            "reason": "invalid_response",
            "host": host,
            "model": model,
            "detail": "The /api/tags response did not include a models list.",
        }

    installed_models: list[str] = []
    for entry in raw_models:
        if not isinstance(entry, dict):
            continue
        model_name = entry.get("name") or entry.get("model")
        if isinstance(model_name, str):
            installed_models.append(model_name)

    if model not in installed_models:
        detail = (
            "Installed models: " + ", ".join(installed_models[:5])
            if installed_models
            else "Ollama is reachable but reported no installed models."
        )
        return {
            "ok": False,
            "reason": "model_missing",
            "host": host,
            "model": model,
            "detail": detail,
        }

    return {
        "ok": True,
        "reason": "ok",
        "host": host,
        "model": model,
        "detail": "ready",
    }


def _default_opportunity_account_id(account_id: str | None = None) -> str | None:
    if account_id:
        return account_id
    latest_scan = db_manager.get_latest_scan_activity()
    if latest_scan is None:
        return None
    latest_account_id = latest_scan.get("account_id")
    return (
        latest_account_id
        if isinstance(latest_account_id, str) and latest_account_id
        else None
    )


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


def _format_scan_payload(result: ScanResult, schema_version: str) -> str:
    return json.dumps(
        to_v2_payload(result) if schema_version == "v2" else to_v1_payload(result)
    )


def _parse_csv_filter(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


_VALID_OPPORTUNITY_STATUSES: frozenset[str] = frozenset(
    {"open", "triaged", "in_progress", "snoozed", "resolved", "ignored"}
)
_VALID_SOURCE_KINDS: frozenset[str] = frozenset(
    {"cost_anomaly", "cost_waste", "security", "iam", "cloudwatch", "tagging"}
)
_VALID_SEVERITIES: frozenset[str] = frozenset({"HIGH", "MEDIUM", "LOW"})


def _parse_status_filter(value: str) -> list[OpportunityStatus] | None:
    """Parse CSV status string, rejecting unknown status values."""
    items = _parse_csv_filter(value)
    if not items:
        return None
    unknown = [s for s in items if s not in _VALID_OPPORTUNITY_STATUSES]
    if unknown:
        raise ValueError(f"Unknown opportunity status(es): {', '.join(unknown)}")
    return cast(list[OpportunityStatus], items)


def _parse_source_kind_filter(value: str) -> list[OpportunitySourceKind] | None:
    """Parse CSV source_kind string, rejecting unknown kind values."""
    items = _parse_csv_filter(value)
    if not items:
        return None
    unknown = [s for s in items if s not in _VALID_SOURCE_KINDS]
    if unknown:
        raise ValueError(f"Unknown opportunity source kind(s): {', '.join(unknown)}")
    return cast(list[OpportunitySourceKind], items)


def _parse_severity_filter(value: str) -> list[Severity] | None:
    """Parse CSV severity string, rejecting unknown severity values."""
    items = _parse_csv_filter(value)
    if not items:
        return None
    unknown = [s for s in items if s not in _VALID_SEVERITIES]
    if unknown:
        raise ValueError(f"Unknown severity value(s): {', '.join(unknown)}")
    return cast(list[Severity], items)


class _SchemaArgs(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    schema_version: Literal["v1", "v2"] = Field(default="v1", alias="schema")


class _RegionSchemaArgs(_SchemaArgs):
    region: str = ""


class _TaggingSchemaArgs(_RegionSchemaArgs):
    required_tags: str = "Environment,Owner"


class _DaysSchemaArgs(_SchemaArgs):
    days: int = 30


class _ThresholdSchemaArgs(_SchemaArgs):
    threshold_pct: float = 50.0


class _SecurityScanArgs(_RegionSchemaArgs):
    include_global: bool = True


class _OpportunityListArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    account_id: str = ""
    statuses: str = ",".join(default_list_statuses())
    source_kinds: str = ""
    severities: str = ""
    region: str = ""
    owner: str = ""
    limit: int = 25


class _OpportunityDetailsArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fingerprint: str
    account_id: str = ""
    history_limit: int = 20


class _OpportunityUpdateArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fingerprint: str
    account_id: str = ""
    status: OpportunityStatus | None = None
    owner: str | None = None
    snooze_until: str | None = None
    note: str | None = None


@tool(args_schema=_SchemaArgs)
def tool_get_enabled_regions(schema_version: Literal["v1", "v2"] = "v1") -> str:
    """
    List all AWS regions that are enabled for this account (opted-in or opt-in-not-required).
    Call this first when the user asks for a multi-region analysis so you know which regions to scan.
    """
    result = _get_enabled_regions()
    return _format_scan_payload(result, schema_version)


@tool(args_schema=_RegionSchemaArgs)
def tool_get_ec2_inventory(
    region: str = "",
    schema_version: Literal["v1", "v2"] = "v1",
) -> str:
    """Retrieve all EC2 instances and their current state.
    Pass a region name (e.g. 'us-west-2') to scan a specific region, or leave empty for the default."""
    result = _get_ec2_inventory(region=region or None)
    return _format_scan_payload(result, schema_version)


@tool(args_schema=_RegionSchemaArgs)
def tool_get_rds_inventory(
    region: str = "",
    schema_version: Literal["v1", "v2"] = "v1",
) -> str:
    """Retrieve all RDS instances and their current state.
    Pass a region name (e.g. 'eu-west-1') to scan a specific region, or leave empty for the default."""
    result = _get_rds_inventory(region=region or None)
    return _format_scan_payload(result, schema_version)


@tool(args_schema=_SchemaArgs)
def tool_get_s3_inventory(schema_version: Literal["v1", "v2"] = "v1") -> str:
    """List all S3 buckets. S3 is a global service — no region parameter needed."""
    result = _get_s3_inventory()
    return _format_scan_payload(result, schema_version)


@tool(args_schema=_RegionSchemaArgs)
def tool_get_lambda_inventory(
    region: str = "",
    schema_version: Literal["v1", "v2"] = "v1",
) -> str:
    """List all Lambda functions with runtime, memory size, timeout, code size, and whether they are stale (>180 days since last deploy).
    Pass a region name to scan a specific region, or leave empty for the default."""
    result = _get_lambda_inventory(region=region or None)
    return _format_scan_payload(result, schema_version)


@tool(args_schema=_RegionSchemaArgs)
def tool_detect_cloudwatch_gaps(
    region: str = "",
    schema_version: Literal["v1", "v2"] = "v1",
) -> str:
    """
    Find EC2 instances, RDS databases, and Lambda functions missing CloudWatch alarms.
    EC2: CPUUtilization, StatusCheckFailed.
    RDS: CPUUtilization, FreeStorageSpace.
    Lambda: Errors, Throttles.
    Returns one finding per resource listing every uncovered metric.
    Pass a region name to check a specific region, or leave empty for the default.
    """
    result = _detect_cloudwatch_gaps(region=region or None)
    return _format_scan_payload(result, schema_version)


@tool(args_schema=_SchemaArgs)
def tool_detect_overpermissive_iam(schema_version: Literal["v1", "v2"] = "v1") -> str:
    """
    Scan IAM users, roles, and groups for over-permissive policies.
    Flags Action:* on Resource:* as HIGH (full admin) and
    Action:<service>:* on Resource:* as MEDIUM (service-level wildcard).
    Covers inline policies, customer-managed policies, and known dangerous
    AWS-managed policies (AdministratorAccess, PowerUserAccess).
    """
    result = _detect_overpermissive_iam()
    return _format_scan_payload(result, schema_version)


@tool(args_schema=_TaggingSchemaArgs)
def tool_check_tagging_compliance(
    required_tags: str = "Environment,Owner",
    region: str = "",
    schema_version: Literal["v1", "v2"] = "v1",
) -> str:
    """
    Check EC2, RDS, S3, and Lambda resources for missing required tags.
    Pass a comma-separated list of tag keys to enforce (default: Environment,Owner).
    Pass a region name to check a specific region, or leave empty for the default.
    Returns one finding per non-compliant resource.
    """
    tags = [t.strip() for t in required_tags.split(",") if t.strip()]
    result = _check_tagging_compliance(required_tags=tags, region=region or None)
    return _format_scan_payload(result, schema_version)


@tool(args_schema=_DaysSchemaArgs)
def tool_get_ri_sp_coverage(
    days: int = 30,
    schema_version: Literal["v1", "v2"] = "v1",
) -> str:
    """
    Fetch Reserved Instance and Savings Plan coverage and utilization from Cost Explorer.
    Shows what % of eligible spend is covered by commitments vs on-demand,
    how well existing commitments are utilized, and the dollar value of uncovered spend.
    """
    result = _get_ri_sp_coverage(days=days)
    return _format_scan_payload(result, schema_version)


@tool(args_schema=_ThresholdSchemaArgs)
def tool_detect_cost_anomalies(
    threshold_pct: float = 50.0,
    schema_version: Literal["v1", "v2"] = "v1",
) -> str:
    """
    Compare the last 7 days of per-service AWS spend against the prior 7-day baseline.
    Returns services whose cost increased by more than threshold_pct (default 50%).
    Useful for spotting unexpected spending spikes before the bill arrives.
    """
    result = _detect_cost_anomalies(threshold_pct=threshold_pct)
    return _format_scan_payload(result, schema_version)


@tool(args_schema=_SecurityScanArgs)
def tool_run_security_scan(
    region: str = "",
    include_global: bool = True,
    schema_version: Literal["v1", "v2"] = "v1",
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
    return _format_scan_payload(combined, schema_version)


@tool(args_schema=_RegionSchemaArgs)
def tool_run_cost_scan(
    region: str = "",
    schema_version: Literal["v1", "v2"] = "v1",
) -> str:
    """
    Scan for cost waste in the AWS account.
    Checks: unattached EBS volumes, stopped EC2 instances (still paying for EBS),
    EBS snapshots older than 90 days, and unassociated Elastic IPs (~$0.005/hr each).

    Pass a region name to target a specific region; leave empty for the default region.
    Returns a list of findings with resource ID, description, and remediation hints.
    """
    result = _run_cost_scan(region=region or None)
    return _format_scan_payload(result, schema_version)


@tool(args_schema=_OpportunityListArgs)
def tool_list_opportunities(
    account_id: str = "",
    statuses: str = ",".join(default_list_statuses()),
    source_kinds: str = "",
    severities: str = "",
    region: str = "",
    owner: str = "",
    limit: int = 25,
) -> str:
    """
    List locally persisted opportunities created by prior analyze/watch runs.
    Use this first for questions like "what changed", "what should I fix",
    "what's new", "top risks", or "show unresolved issues".
    """
    try:
        parsed_statuses = _parse_status_filter(statuses)
        parsed_source_kinds = _parse_source_kind_filter(source_kinds)
        parsed_severities = _parse_severity_filter(severities)
    except ValueError as exc:
        return json.dumps({"error": str(exc)})
    opportunities = db_manager.list_opportunities(
        account_id=_default_opportunity_account_id(account_id or None),
        statuses=parsed_statuses,
        source_kinds=parsed_source_kinds,
        severities=parsed_severities,
        region=region or None,
        owner=owner or None,
        limit=limit,
    )
    return json.dumps(opportunities, default=str)


@tool(args_schema=_OpportunityDetailsArgs)
def tool_get_opportunity_details(
    fingerprint: str,
    account_id: str = "",
    history_limit: int = 20,
) -> str:
    """Fetch one local opportunity with its lifecycle history."""
    try:
        opportunity = db_manager.get_opportunity(
            fingerprint=fingerprint,
            account_id=_default_opportunity_account_id(account_id or None),
        )
    except ValueError as exc:
        return json.dumps({"error": str(exc)})
    if opportunity is None:
        return json.dumps({"error": "opportunity not found"})

    events = db_manager.get_opportunity_events(
        fingerprint=fingerprint,
        account_id=opportunity["account_id"],
        limit=history_limit,
    )
    return json.dumps(
        {"opportunity": opportunity, "events": events},
        default=str,
    )


@tool(args_schema=_OpportunityUpdateArgs)
def tool_update_opportunity(
    fingerprint: str,
    account_id: str = "",
    status: OpportunityStatus | None = None,
    owner: str | None = None,
    snooze_until: str | None = None,
    note: str | None = None,
) -> str:
    """
    Update local-only opportunity metadata such as status, owner, snooze, or notes.
    This never mutates AWS resources and is safe for agent-driven triage.
    """
    try:
        opportunity = db_manager.update_opportunity_state(
            fingerprint=fingerprint,
            account_id=_default_opportunity_account_id(account_id or None),
            status=status,
            owner=owner,
            snooze_until=snooze_until,
            note=note,
        )
    except ValueError as exc:
        return json.dumps({"error": str(exc)})
    if opportunity is None:
        return json.dumps({"error": "opportunity not found"})
    return json.dumps(opportunity, default=str)


@tool(args_schema=_OpportunityListArgs)
def tool_plan_opportunities(
    account_id: str = "",
    statuses: str = ",".join(default_list_statuses()),
    source_kinds: str = "",
    severities: str = "",
    region: str = "",
    owner: str = "",
    limit: int = 25,
) -> str:
    """
    Build a grouped remediation and triage plan over locally persisted opportunities.
    Use this when the user asks for a plan rather than immediate execution.
    """
    try:
        parsed_statuses = _parse_status_filter(statuses)
        parsed_source_kinds = _parse_source_kind_filter(source_kinds)
        parsed_severities = _parse_severity_filter(severities)
    except ValueError as exc:
        return json.dumps({"error": str(exc)})
    opportunities = db_manager.list_opportunities(
        account_id=_default_opportunity_account_id(account_id or None),
        statuses=parsed_statuses,
        source_kinds=parsed_source_kinds,
        severities=parsed_severities,
        region=region or None,
        owner=owner or None,
        limit=max(limit, 1),
    )
    return json.dumps(build_opportunity_plan(opportunities, limit=limit), default=str)


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
    tool_list_opportunities,
    tool_get_opportunity_details,
    tool_update_opportunity,
    tool_plan_opportunities,
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
        except json.JSONDecodeError:
            logger.warn(f"Tool returned malformed JSON: {stripped[:120]}")
            return "failed", "malformed JSON response from tool"
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


def _normalize_schema_like_args(
    tool_name: str, args: dict[str, Any]
) -> tuple[dict[str, Any], str | None]:
    """Normalize schema-like args for read-only tools and report any repair note."""
    if tool_name not in _SCHEMA_GUARDED_TOOLS:
        return args, None

    normalized = dict(args)
    repair_notes: list[str] = []

    if "schema_version" in normalized:
        schema_value = normalized.pop("schema_version")
        repair_notes.append("mapped schema_version to schema")
        if "schema" not in normalized:
            normalized["schema"] = schema_value

    if "schema" in normalized:
        schema_value = str(normalized["schema"]).lower()
        if schema_value not in {"v1", "v2"}:
            normalized["schema"] = "v1"
            repair_notes.append("replaced invalid schema with v1")
        else:
            normalized["schema"] = schema_value

    if repair_notes:
        return normalized, "; ".join(repair_notes)
    return normalized, None


def _normalize_safe_tool_calls(state: AgentState) -> dict | None:
    """Repair safe tool calls in-place before ToolNode executes them."""
    if not state["messages"]:
        return None
    last_message = state["messages"][-1]
    if not isinstance(last_message, AIMessage) or not last_message.tool_calls:
        return None

    repaired = False
    synthetic_errors: list[ToolMessage] = []
    updated_tool_calls: list[dict[str, Any]] = []
    for tool_call in last_message.tool_calls:
        tool_name = str(tool_call["name"])
        original_args = cast(dict[str, Any], tool_call["args"])
        try:
            normalized_args, repair_note = _normalize_schema_like_args(
                tool_name, original_args
            )
        except Exception as exc:
            synthetic_errors.append(
                ToolMessage(
                    content=(
                        "Error: Tool arguments could not be normalized for "
                        f"{tool_name}: {exc}"
                    ),
                    tool_call_id=tool_call["id"],
                )
            )
            continue

        if repair_note:
            logger.error(
                "Normalized tool arguments for "
                f"{tool_name}: {repair_note}; original={original_args}; "
                f"normalized={normalized_args}"
            )
            repaired = True
            updated_tool_calls.append({**tool_call, "args": normalized_args})
        else:
            updated_tool_calls.append(dict(tool_call))

    if synthetic_errors:
        return {"messages": synthetic_errors}
    if repaired:
        copied_message = AIMessage(
            content=last_message.content,
            tool_calls=updated_tool_calls,
        )
        messages = list(state["messages"])
        messages[-1] = copied_message
        state["messages"] = messages
    return None


def tools_node(state: AgentState) -> dict:
    """Execute tools then persist execution outcomes in the audit log."""
    normalization_result = _normalize_safe_tool_calls(state)
    if normalization_result is not None:
        _record_tool_execution_results(state, normalization_result)
        return normalization_result
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
    if not state["messages"]:
        return {"approved": False, "messages": []}
    last_message = state["messages"][-1]
    if not isinstance(last_message, AIMessage) or not last_message.tool_calls:
        # Nothing to approve — route back to agent
        return {"approved": False, "messages": []}

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
    "tool_list_opportunities",
    "tool_get_opportunity_details",
    "tool_update_opportunity",
    "tool_plan_opportunities",
}

# Validate at module load: every name in SAFE_TOOLS must appear in the tools list.
# This catches renames that would silently remove the approval gate.
_tool_names: frozenset[str] = frozenset(t.name for t in tools)
_unknown_safe_tools = SAFE_TOOLS - _tool_names
if _unknown_safe_tools:
    raise ValueError(
        f"SAFE_TOOLS contains tool name(s) not in the tools list: {_unknown_safe_tools}. "
        "Update SAFE_TOOLS to match the current tool names."
    )


def should_require_approval(state: AgentState) -> str:
    """Routing logic to intercept dangerous tools before they hit ToolNode."""
    if not state["messages"]:
        return "end"
    last_message = state["messages"][-1]
    if not isinstance(last_message, AIMessage) or not last_message.tool_calls:
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
    llm = ChatOllama(
        model=OLLAMA_MODEL_NAME,
        temperature=0,
        base_url=get_ollama_host(),
    )
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
