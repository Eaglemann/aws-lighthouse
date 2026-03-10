import io
import json
import re
import shlex
import time
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Any, cast

import typer
from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.console import Console, Group
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from .auth import get_aws_session, profile_context
from .db import db_manager
from .logger import logger
from .opportunities import (
    SECTION_TO_SOURCE_KIND,
    build_opportunity_plan,
    is_global_security_finding,
    is_global_tagging_finding,
    sync_opportunities_from_scan,
)
from .policy import PolicyConfigError, ScanPolicy, load_policy_config
from .scan_contract import (
    error_result,
    is_expected_unavailable_scan_error,
    merge_list_results,
    ok_result,
    scan_error_reason,
)
from .tools.cloudtrail_attribution import get_cost_attribution
from .tools.cloudwatch_scan import detect_cloudwatch_gaps
from .tools.compute_optimizer import get_compute_optimizer_recommendations
from .tools.cost import get_cost_forecast, get_monthly_cost_summary
from .tools.cost_anomaly import detect_cost_anomalies
from .tools.cost_scan import run_cost_scan
from .tools.iam_scan import detect_overpermissive_iam
from .tools.inventory import (
    get_ec2_inventory,
    get_lambda_inventory,
    get_rds_inventory,
    get_s3_inventory,
)
from .tools.multi_region import get_enabled_regions
from .tools.notify import build_alert_payload, send_webhook, should_alert
from .tools.remediation_plan import build_remediation_plan, parse_phase_selection
from .tools.ri_sp_advisor import get_ri_recommendations, get_sp_recommendations
from .tools.ri_sp_coverage import get_ri_sp_coverage
from .tools.security_scan import run_security_scan
from .tools.sg_blast_radius import get_sg_blast_radius
from .tools.tag_cost_enforcer import get_untagged_spend
from .tools.tagging import check_tagging_compliance
from .tools.terraform_drift import classify_findings_by_iac
from .types import (
    CostFinding,
    OpportunitySourceKind,
    OpportunityStatus,
    RemediationPlan,
    ScanError,
    ScanResult,
    SecurityFinding,
    SGBlastRadius,
)

app = typer.Typer(
    help="AWS Lighthouse: Terminal-first FinOps, Security, and Scaffolding Agent.",
    add_completion=False,
    invoke_without_command=True,
)


@app.callback()
def main(ctx: typer.Context) -> None:
    """AWS Lighthouse: Terminal-first FinOps, Security, and Scaffolding Agent."""
    if ctx.invoked_subcommand is None:
        shell()


# Max parallel region workers — balances throughput against boto3 connection pool
_MAX_WORKERS = 5

# ── Severity colour map ──────────────────────────────────────────────────────
_SEV_STYLE = {"HIGH": "bold red", "MEDIUM": "bold yellow", "LOW": "bold blue"}
_SEV_LABEL = {"HIGH": "● HIGH", "MEDIUM": "● MED ", "LOW": "● LOW "}


def _severity_text(sev: str) -> Text:
    return Text(_SEV_LABEL.get(sev, sev), style=_SEV_STYLE.get(sev, "white"))


def _count(lst: list) -> str:
    """Return resource count."""
    return str(len(lst))


def _pct_style(val: float | None, low: float = 60.0, high: float = 80.0) -> str:
    """Return a colored percentage string based on thresholds."""
    if val is None:
        return "[dim]N/A[/dim]"
    color = "green" if val >= high else ("yellow" if val >= low else "red")
    return f"[{color}]{val:.1f}%[/{color}]"


def _dollar(val: float | None) -> str:
    return f"${val:,.2f}" if val is not None else "[dim]N/A[/dim]"


_DELTA_SECTION_KEYS = (
    "inventory",
    "costs",
    "cost_anomalies",
    "ri_sp_coverage",
    "security_findings",
    "iam_findings",
    "cloudwatch_findings",
    "cost_waste",
    "tagging_findings",
)

_DB_HEALTH_LABELS = {
    "initialize": "SQLite initialization",
    "record_cost_snapshot": "Cost snapshot writes",
    "get_latest_cost_snapshot": "Cost snapshot reads",
    "record_scan_snapshot": "Scan snapshot writes",
    "get_latest_scan_snapshot": "Scan snapshot reads",
    "get_previous_scan_snapshot": "Previous snapshot reads",
    "get_latest_scan_activity": "Latest scan activity reads",
    "record_audit_log": "Audit log writes",
    "update_audit_log_result": "Audit log result updates",
    "sync_opportunities": "Opportunity sync",
    "list_opportunities": "Opportunity list reads",
    "summarize_opportunities": "Opportunity summary reads",
    "get_opportunity": "Opportunity detail reads",
    "get_opportunity_events": "Opportunity history reads",
    "update_opportunity_state": "Opportunity state updates",
}


def _parse_profiles(raw: str) -> list[str]:
    """Parse comma-separated AWS profile names, strip whitespace, deduplicate preserving order."""
    seen: set[str] = set()
    result: list[str] = []
    for p in raw.split(","):
        name = p.strip()
        if name and name not in seen:
            seen.add(name)
            result.append(name)
    return result


def _scan_scope_key(
    region: str | None, days: int, policy_scope_token: str | None = None
) -> str:
    """Return persistence scope key for scan snapshots."""
    if region:
        base = f"single-region:{region}:days={days}"
    else:
        base = f"multi-region:days={days}"
    if not policy_scope_token:
        return base
    return f"{base}:policy={policy_scope_token}"


def _normalize_snapshot_payload(data: dict[str, Any]) -> dict[str, Any]:
    """Deep-copy payload into a deterministic JSON-safe structure."""
    return cast(
        dict[str, Any],
        json.loads(json.dumps(data, sort_keys=True, default=str)),
    )


def _canonicalize_for_diff(value: Any) -> str:
    """Create a stable string identity for list/set diffing."""
    return json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))


def _diff_lists(previous: list[Any], current: list[Any]) -> dict[str, Any]:
    prev_map = {_canonicalize_for_diff(item): item for item in previous}
    curr_map = {_canonicalize_for_diff(item): item for item in current}
    prev_keys = set(prev_map.keys())
    curr_keys = set(curr_map.keys())
    new_keys = sorted(curr_keys - prev_keys)
    resolved_keys = sorted(prev_keys - curr_keys)
    unchanged_keys = prev_keys & curr_keys
    return {
        "new": [curr_map[key] for key in new_keys],
        "resolved": [prev_map[key] for key in resolved_keys],
        "unchanged_count": len(unchanged_keys),
    }


def _diff_mappings(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    new: list[dict[str, Any]] = []
    resolved: list[dict[str, Any]] = []
    unchanged = 0
    for key in sorted(set(previous.keys()) | set(current.keys())):
        prev_exists = key in previous
        curr_exists = key in current
        if not prev_exists and curr_exists:
            new.append({"field": key, "value": current[key]})
            continue
        if prev_exists and not curr_exists:
            resolved.append({"field": key, "value": previous[key]})
            continue

        prev_value = previous[key]
        curr_value = current[key]
        if _canonicalize_for_diff(prev_value) == _canonicalize_for_diff(curr_value):
            unchanged += 1
            continue
        new.append({"field": key, "value": curr_value, "previous": prev_value})
        resolved.append({"field": key, "value": prev_value, "current": curr_value})
    return {"new": new, "resolved": resolved, "unchanged_count": unchanged}


def _build_section_delta(previous: Any, current: Any) -> dict[str, Any]:
    if isinstance(previous, list) and isinstance(current, list):
        return _diff_lists(previous, current)
    if isinstance(previous, dict) and isinstance(current, dict):
        return _diff_mappings(previous, current)

    same = _canonicalize_for_diff(previous) == _canonicalize_for_diff(current)
    return {
        "new": [] if same else [current],
        "resolved": [] if same else [previous],
        "unchanged_count": 1 if same else 0,
    }


def _build_delta_payload(
    *,
    baseline_snapshot: dict[str, Any] | None,
    current_sections: dict[str, Any],
    scope_key: str,
    overall_errors: list[ScanError],
) -> dict[str, Any]:
    baseline_found = baseline_snapshot is not None
    previous_sections = (
        cast(dict[str, Any], baseline_snapshot.get("data", {}))
        if baseline_snapshot
        else {}
    )

    section_deltas: dict[str, dict[str, Any]] = {}
    total_new = 0
    total_resolved = 0
    sections_with_new: list[str] = []
    sections_with_resolved: list[str] = []

    for section in _DELTA_SECTION_KEYS:
        if baseline_found:
            section_delta = _build_section_delta(
                previous_sections.get(section),
                current_sections.get(section),
            )
        else:
            section_delta = {"new": [], "resolved": [], "unchanged_count": 0}

        section_deltas[section] = section_delta
        if section_delta["new"]:
            sections_with_new.append(section)
        if section_delta["resolved"]:
            sections_with_resolved.append(section)
        total_new += len(section_delta["new"])
        total_resolved += len(section_delta["resolved"])

    summary = {
        "total_new": total_new,
        "total_resolved": total_resolved,
        "sections_with_new": sections_with_new,
        "sections_with_resolved": sections_with_resolved,
        "degraded": bool(overall_errors),
        "error_count": len(overall_errors),
    }
    return {
        "baseline_found": baseline_found,
        "baseline_recorded_at": baseline_snapshot.get("recorded_at")
        if baseline_snapshot
        else None,
        "scope_key": scope_key,
        "summary": summary,
        "sections": section_deltas,
    }


def _load_scan_policy(config_path: Path | None) -> ScanPolicy | None:
    if config_path is None:
        return None
    try:
        return load_policy_config(config_path)
    except PolicyConfigError as exc:
        raise typer.BadParameter(
            f"Invalid --config file '{config_path}': {exc}"
        ) from exc


def _render_skipped_panel(c: Console, title: str) -> None:
    c.print(
        Panel(
            "[dim]Skipped by policy config.[/dim]",
            title=f"{title}  [dim]disabled by policy[/dim]",
            border_style="dim",
            padding=(0, 1),
        )
    )
    c.print()


def _skipped_result(c: Console, title: str, data: Any) -> ScanResult:  # noqa: ARG001
    return error_result(data=data, errors=[])


def _render_opportunity_sync_summary(c: Console, summary: dict[str, int]) -> None:
    c.print(
        "[dim]Opportunities synced:"
        f" {summary['created']} new,"
        f" {summary['reopened']} reopened,"
        f" {summary['resolved']} resolved,"
        f" {summary['still_open']} still open.[/dim]"
    )
    c.print()


def _render_delta_panel(
    c: Console, delta: dict[str, Any], errors: list[ScanError]
) -> None:
    """Render high-level delta summary in text mode."""
    summary = cast(dict[str, Any], delta["summary"])
    if not delta.get("baseline_found", False):
        c.print(
            Panel(
                "[cyan]No previous baseline was found for this scope. A new baseline has been recorded.[/cyan]",
                title="[bold cyan]Δ Delta[/bold cyan]  [dim]baseline created[/dim]",
                border_style="cyan",
                padding=(0, 1),
            )
        )
        c.print()
        return

    table = Table(
        box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1), show_edge=False
    )
    table.add_column("Section", style="dim", no_wrap=True)
    table.add_column("New", justify="right", style="green")
    table.add_column("Resolved", justify="right", style="yellow")
    table.add_column("Unchanged", justify="right", style="dim")
    for section in _DELTA_SECTION_KEYS:
        section_delta = cast(dict[str, Any], delta["sections"][section])
        table.add_row(
            section,
            str(len(section_delta["new"])),
            str(len(section_delta["resolved"])),
            str(section_delta["unchanged_count"]),
        )

    border = "yellow" if errors else "cyan"
    title = (
        "[bold yellow]Δ Delta (Degraded)[/bold yellow]"
        if errors
        else "[bold cyan]Δ Delta[/bold cyan]"
    )
    c.print(
        Panel(
            table,
            title=(
                f"{title}  [dim]+{summary['total_new']} / -{summary['total_resolved']}[/dim]"
            ),
            border_style=border,
            padding=(0, 1),
        )
    )
    c.print()


_ACTIVE_OPPORTUNITY_STATUSES: tuple[OpportunityStatus, ...] = (
    "open",
    "triaged",
    "in_progress",
    "snoozed",
)
_SUMMARY_SECTION_LABELS = {
    "inventory": "Inventory",
    "costs": "Cost",
    "cost_forecast": "Cost Forecast",
    "cost_anomalies": "Cost Anomalies",
    "cost_attribution": "Cost Attribution",
    "ri_sp_coverage": "RI/SP Coverage",
    "ri_recommendations": "RI Recommendations",
    "sp_recommendations": "SP Recommendations",
    "security_findings": "Security",
    "sg_blast_radius": "SG Blast Radius",
    "iam_findings": "IAM",
    "cloudwatch_findings": "CloudWatch",
    "compute_optimizer": "Compute Optimizer",
    "tag_cost_coverage": "Tag Cost Coverage",
    "cost_waste": "Cost Waste",
    "tagging_findings": "Tagging",
}

_ERROR_SERVICE_LABELS = {
    "ce": "Cost Explorer",
    "guardduty": "GuardDuty",
}


def _display_scope_label(region: str | None) -> str:
    return region or "global"


def _error_service_label(service: str) -> str:
    return _ERROR_SERVICE_LABELS.get(service, service)


def _group_expected_unavailable_errors(
    errors: Sequence[ScanError],
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for error in errors:
        if not is_expected_unavailable_scan_error(error):
            continue
        reason = scan_error_reason(error)
        key = (error["service"], reason)
        entry = grouped.setdefault(
            key,
            {
                "service": error["service"],
                "reason": reason,
                "regions": set(),
            },
        )
        region = error.get("region")
        if region:
            cast(set[str], entry["regions"]).add(region)
    return sorted(
        grouped.values(),
        key=lambda entry: (str(entry["service"]), str(entry["reason"])),
    )


def _format_degraded_scope(regions: set[str]) -> str:
    if not regions:
        return "global"
    ordered = sorted(regions)
    if len(ordered) == 1:
        return ordered[0]
    sample = ", ".join(ordered[:3])
    if len(ordered) > 3:
        sample = f"{sample}, +{len(ordered) - 3} more"
    return f"{len(ordered)} regions ({sample})"


def _collect_degraded_service_rows(
    section_results: Mapping[str, ScanResult],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for section_name, section_result in section_results.items():
        for entry in _group_expected_unavailable_errors(section_result["errors"]):
            rows.append(
                {
                    "section_name": section_name,
                    "service": entry["service"],
                    "reason": entry["reason"],
                    "scope": _format_degraded_scope(cast(set[str], entry["regions"])),
                }
            )
    section_order = {name: index for index, name in enumerate(_SUMMARY_SECTION_LABELS)}
    return sorted(
        rows,
        key=lambda row: (
            section_order.get(str(row["section_name"]), 999),
            str(row["service"]),
            str(row["reason"]),
        ),
    )


def _render_degraded_services_panel(
    c: Console, section_results: Mapping[str, ScanResult]
) -> None:
    rows = _collect_degraded_service_rows(section_results)
    if not rows:
        return
    table = Table(
        box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1), show_edge=False
    )
    table.add_column("Section", style="dim", no_wrap=True)
    table.add_column("Service", style="dim", no_wrap=True)
    table.add_column("Scope", style="dim")
    table.add_column("Reason")
    for row in rows:
        table.add_row(
            _SUMMARY_SECTION_LABELS.get(
                str(row["section_name"]), str(row["section_name"])
            ),
            _error_service_label(str(row["service"])),
            str(row["scope"]),
            str(row["reason"]),
        )
    c.print(
        Panel(
            table,
            title="[bold yellow]Degraded Services[/bold yellow]",
            border_style="yellow",
            padding=(0, 1),
        )
    )
    c.print()


def _render_db_health_panel(c: Console, health_status: Mapping[str, Any]) -> None:
    issues = cast(list[dict[str, str]], health_status.get("issues", []))
    if not issues:
        return
    table = Table(
        box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1), show_edge=False
    )
    table.add_column("Local State", style="dim", no_wrap=True)
    table.add_column("Impact")
    for issue in issues:
        operation = issue.get("operation", "")
        table.add_row(
            _DB_HEALTH_LABELS.get(operation, operation.replace("_", " ").title()),
            issue.get("detail", ""),
        )
    c.print(
        Panel(
            Group(
                Text.from_markup(
                    "[yellow]Snapshots, audit history, or opportunities may be incomplete until local SQLite access recovers.[/yellow]"
                ),
                table,
            ),
            title="[bold yellow]Local State Degraded[/bold yellow]",
            border_style="yellow",
            padding=(0, 1),
        )
    )
    c.print()


def _format_expected_unavailable_note(
    service: str,
    reason: str,
    regions: set[str],
) -> str:
    if service == "guardduty":
        if not regions:
            return f"GuardDuty checks unavailable ({reason})."
        if len(regions) == 1:
            return f"GuardDuty checks unavailable in {sorted(regions)[0]} ({reason})."
        return f"GuardDuty checks unavailable in {len(regions)} regions ({reason})."
    if reason.endswith("."):
        return reason
    return f"{reason[0].upper()}{reason[1:]}."


def _section_degraded_notes(errors: Sequence[ScanError]) -> list[str]:
    notes = [
        _format_expected_unavailable_note(
            str(entry["service"]),
            str(entry["reason"]),
            cast(set[str], entry["regions"]),
        )
        for entry in _group_expected_unavailable_errors(errors)
    ]
    unexpected_errors = [
        error for error in errors if not is_expected_unavailable_scan_error(error)
    ]
    if unexpected_errors:
        notes.append("Additional API errors occurred. Findings may be incomplete.")
    return notes


def _render_degraded_notes(notes: Sequence[str]) -> Group | None:
    if not notes:
        return None
    lines = [Text.from_markup(f"[yellow]⚠  {note}[/yellow]") for note in notes]
    return Group(*lines)


def _format_counts_for_summary(counts: dict[str, int], *, empty: str) -> str:
    if not counts:
        return empty
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return " · ".join(f"{label}:{count}" for label, count in ordered)


def _format_section_group(section_names: list[str], *, empty: str) -> str:
    if not section_names:
        return empty
    labels = [_SUMMARY_SECTION_LABELS[name] for name in sorted(section_names)]
    return ", ".join(labels)


def _render_executive_summary(
    c: Console,
    *,
    account_id: str,
    scanned_at: str,
    regions: list[str | None],
    scope_key: str,
    degraded_sections: list[str],
    skipped_sections: list[str],
    opportunity_summary: dict[str, Any],
    opportunity_sync_summary: dict[str, int],
    delta_data: dict[str, Any] | None,
) -> None:
    healthy_count = (
        len(_SUMMARY_SECTION_LABELS) - len(degraded_sections) - len(skipped_sections)
    )
    scope_label = (
        f"{len([region for region in regions if region])} regions"
        if len(regions) > 1
        else _display_scope_label(regions[0] if regions else None)
    )
    severity_counts = cast(dict[str, int], opportunity_summary.get("by_severity", {}))
    source_counts = cast(dict[str, int], opportunity_summary.get("by_source", {}))

    table = Table(
        box=box.SIMPLE_HEAD, show_header=False, padding=(0, 1), show_edge=False
    )
    table.add_column("Label", style="dim", no_wrap=True)
    table.add_column("Value")
    table.add_row("Account", f"[bold]{account_id}[/bold]")
    table.add_row("Scanned", scanned_at)
    table.add_row("Scope", f"{scope_label}  [dim]· {scope_key}[/dim]")
    table.add_row(
        "Section Health",
        (
            f"[green]{healthy_count} healthy[/green] · "
            f"[yellow]{len(degraded_sections)} degraded[/yellow] · "
            f"[dim]{len(skipped_sections)} skipped by policy[/dim]"
        ),
    )
    table.add_row(
        "Healthy",
        _format_section_group(
            [
                section_name
                for section_name in _SUMMARY_SECTION_LABELS
                if section_name not in degraded_sections
                and section_name not in skipped_sections
            ],
            empty="None",
        ),
    )
    table.add_row(
        "Degraded",
        _format_section_group(degraded_sections, empty="None"),
    )
    table.add_row(
        "Skipped",
        _format_section_group(skipped_sections, empty="None"),
    )
    table.add_row(
        "Priorities",
        _format_counts_for_summary(
            severity_counts,
            empty="No open opportunities",
        ),
    )
    table.add_row(
        "Opportunities",
        (
            f"[bold]{opportunity_summary.get('total', 0)}[/bold] open · "
            f"{_format_counts_for_summary(source_counts, empty='none')}"
        ),
    )
    if delta_data is not None:
        delta_summary = cast(dict[str, Any], delta_data["summary"])
        if delta_data.get("baseline_found"):
            delta_text = (
                f"[green]+{delta_summary['total_new']}[/green] / "
                f"[yellow]-{delta_summary['total_resolved']}[/yellow]"
            )
        else:
            delta_text = "[cyan]baseline created[/cyan]"
        table.add_row("Delta", delta_text)
    table.add_row(
        "Last Sync",
        (
            f"{opportunity_sync_summary['created']} new · "
            f"{opportunity_sync_summary['reopened']} reopened · "
            f"{opportunity_sync_summary['resolved']} resolved"
        ),
    )
    c.print(
        Panel(
            table,
            title="[bold cyan]Executive Summary[/bold cyan]",
            border_style="cyan",
            padding=(0, 1),
        )
    )
    c.print()


def _render_top_opportunities_panel(
    c: Console,
    opportunities: Sequence[Mapping[str, Any]],
) -> None:
    if not opportunities:
        c.print(
            Panel(
                "[green]No unresolved opportunities are currently open.[/green]",
                title="[bold green]Top Opportunities[/bold green]",
                border_style="green",
                padding=(0, 1),
            )
        )
        c.print()
        return

    table = Table(
        box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1), show_edge=False
    )
    table.add_column("Severity", no_wrap=True)
    table.add_column("Source", style="dim", no_wrap=True)
    table.add_column("Scope", style="dim", no_wrap=True)
    table.add_column("Resource", style="cyan", no_wrap=True)
    table.add_column("Summary")
    for opportunity in opportunities:
        severity = opportunity.get("severity")
        severity_cell: str | Text
        severity_cell = _severity_text(severity) if severity else Text("—", style="dim")
        table.add_row(
            severity_cell,
            str(opportunity["source_kind"]),
            _display_scope_label(cast(str | None, opportunity.get("region"))),
            str(opportunity.get("resource_name") or opportunity["resource_id"]),
            str(opportunity["summary"]),
        )
    c.print(
        Panel(
            table,
            title="[bold magenta]Top Opportunities[/bold magenta]",
            border_style="magenta",
            padding=(0, 1),
        )
    )
    c.print()


def _render_watch_compact_panel(
    c: Console,
    *,
    degraded_sections: list[str],
    skipped_sections: list[str],
    delta_data: dict[str, Any] | None,
    opportunity_sync_summary: dict[str, int],
) -> None:
    table = Table(
        box=box.SIMPLE_HEAD, show_header=False, padding=(0, 1), show_edge=False
    )
    table.add_column("Label", style="dim", no_wrap=True)
    table.add_column("Value")
    table.add_row(
        "Health",
        (
            f"[green]{len(_SUMMARY_SECTION_LABELS) - len(degraded_sections) - len(skipped_sections)} healthy[/green] · "
            f"[yellow]{len(degraded_sections)} degraded[/yellow] · "
            f"[dim]{len(skipped_sections)} skipped[/dim]"
        ),
    )
    if delta_data is None:
        table.add_row("Delta", "Disabled")
        table.add_row("Changed", "None")
    else:
        delta_summary = cast(dict[str, Any], delta_data["summary"])
        changed_sections: list[str] = []
        for section_name in _DELTA_SECTION_KEYS:
            section_delta = cast(dict[str, Any], delta_data["sections"][section_name])
            if section_delta["new"] or section_delta["resolved"]:
                changed_sections.append(section_name)
        table.add_row(
            "Delta",
            (
                "[cyan]baseline created[/cyan]"
                if not delta_data.get("baseline_found")
                else (
                    f"[green]+{delta_summary['total_new']}[/green] / "
                    f"[yellow]-{delta_summary['total_resolved']}[/yellow]"
                )
            ),
        )
        table.add_row(
            "Changed",
            _format_section_group(changed_sections[:3], empty="None"),
        )
    table.add_row(
        "Opportunities",
        (
            f"{opportunity_sync_summary['created']} new · "
            f"{opportunity_sync_summary['reopened']} reopened · "
            f"{opportunity_sync_summary['resolved']} resolved · "
            f"{opportunity_sync_summary['still_open']} still open"
        ),
    )
    c.print(
        Panel(
            table,
            title="[bold cyan]Watch Digest[/bold cyan]",
            border_style="cyan",
            padding=(0, 1),
        )
    )
    c.print()


def _render_inventory_cost_columns(
    c: Console,
    *,
    inv_table: Table,
    costs_result: ScanResult,
    display_meta: dict[str, str],
    regions: list[str | None],
    multi_region: bool,
) -> None:
    costs = cast(dict[str, Any], costs_result["data"])
    cost_table = Table(
        box=box.SIMPLE_HEAD, show_header=False, padding=(0, 1), show_edge=False
    )
    cost_table.add_column("Service", style="dim")
    cost_table.add_column("USD", justify="right")
    if costs_result["ok"]:
        cost_table.add_row(
            Text("Total", style="bold white"),
            Text(f"${costs['total_usd']:,.2f}", style="bold yellow"),
        )
        for svc, amt in list(costs.get("breakdown", {}).items())[:6]:
            cost_table.add_row(svc, f"${amt:,.2f}")
    else:
        err_msg = (
            costs_result["errors"][0]["message"]
            if costs_result["errors"]
            else "Unknown error"
        )
        cost_table.add_row("Error", err_msg)

    inv_region_note = f"  [dim]· {len(regions)} regions[/dim]" if multi_region else ""
    c.print(
        Columns(
            [
                Panel(
                    inv_table,
                    title=f"[bold blue]📦 Inventory[/bold blue]{inv_region_note}",
                    border_style="blue",
                    padding=(0, 1),
                ),
                Panel(
                    cost_table,
                    title=(
                        "[bold yellow]💰 Cost[/bold yellow]  "
                        f"[dim]{display_meta['period_label']}[/dim]"
                        f"{display_meta['trend_suffix']}"
                    ),
                    border_style="yellow",
                    padding=(0, 1),
                ),
            ]
        )
    )
    c.print()


def _render_cost_anomalies_panel(c: Console, anomalies_result: ScanResult) -> None:
    anomalies = cast(list[dict[str, Any]], anomalies_result["data"])
    if anomalies:
        anomaly_table = Table(
            box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1), show_edge=False
        )
        anomaly_table.add_column("Service", style="cyan")
        anomaly_table.add_column("Baseline 30d", justify="right", style="dim")
        anomaly_table.add_column("Recent 30d", justify="right")
        anomaly_table.add_column("Change", justify="right")
        for anomaly in anomalies:
            anomaly_table.add_row(
                anomaly["service"],
                f"${anomaly['baseline_30d']:,.2f}",
                f"[bold yellow]${anomaly['recent_30d']:,.2f}[/bold yellow]",
                f"[bold red]▲ {anomaly['pct_change']:+.1f}%[/bold red]",
            )
        c.print(
            Panel(
                anomaly_table,
                title=(
                    "[bold red]🚨 Cost Anomalies[/bold red]  "
                    f"[dim]{len(anomalies)} spike{'s' if len(anomalies) != 1 else ''} vs prior 30d[/dim]"
                ),
                border_style="red",
                padding=(0, 1),
            )
        )
    elif anomalies_result["errors"]:
        c.print(
            Panel(
                "[yellow]⚠  Cost anomaly detection is degraded due to API errors.[/yellow]",
                title="[bold yellow]⚠ Cost Anomalies (Degraded)[/bold yellow]",
                border_style="yellow",
                padding=(0, 1),
            )
        )
    else:
        c.print(
            Panel(
                "[green]✓  No cost spikes detected vs the prior 7-day baseline.[/green]",
                title="[bold green]✅ Cost Anomalies[/bold green]",
                border_style="green",
                padding=(0, 1),
            )
        )
    c.print()


def _render_ri_sp_coverage_panel(c: Console, ri_sp_result: ScanResult) -> None:
    ri_sp = cast(dict[str, Any], ri_sp_result["data"])
    ri_cov = ri_sp.get("ri_coverage_pct")
    ri_util = ri_sp.get("ri_utilization_pct")
    sp_cov = ri_sp.get("sp_coverage_pct")
    sp_util = ri_sp.get("sp_utilization_pct")
    has_any = any(value and value > 0 for value in [ri_cov, ri_util, sp_cov, sp_util])
    notes = _section_degraded_notes(ri_sp_result["errors"])

    table = Table(
        box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1), show_edge=False
    )
    table.add_column("Commitment", style="dim", no_wrap=True)
    table.add_column("Coverage", justify="right", no_wrap=True)
    table.add_column("Utilization", justify="right", no_wrap=True)
    table.add_column("Uncovered Spend", justify="right", no_wrap=True)
    table.add_column("Idle Cost", justify="right", no_wrap=True)
    table.add_row(
        "Reserved Instances",
        _pct_style(ri_cov),
        _pct_style(ri_util),
        _dollar(ri_sp.get("ri_on_demand_cost")),
        _dollar(ri_sp.get("ri_unused_cost")),
    )
    table.add_row(
        "Savings Plans",
        _pct_style(sp_cov),
        _pct_style(sp_util),
        _dollar(ri_sp.get("sp_on_demand_cost")),
        _dollar(ri_sp.get("sp_unused_commitment")),
    )
    border = "yellow" if has_any else "dim"
    title = (
        "[bold yellow]📊 RI / Savings Plan Coverage[/bold yellow]"
        if has_any
        else "[bold dim]📊 RI / Savings Plan Coverage[/bold dim]  [dim]no commitments detected[/dim]"
    )
    panel_body: Any = table
    note_block = _render_degraded_notes(notes)
    if note_block is not None:
        panel_body = Group(table, note_block)
    c.print(
        Panel(
            panel_body,
            title=f"{title}  [dim]{ri_sp.get('period', '')}[/dim]",
            border_style="yellow" if ri_sp_result["errors"] else border,
            padding=(0, 1),
        )
    )
    c.print()


def _render_security_panel(
    c: Console,
    sec_result: ScanResult,
    *,
    multi_region: bool,
) -> None:
    sec_findings = cast(list[SecurityFinding], sec_result["data"])
    notes = _section_degraded_notes(sec_result["errors"])
    if sec_findings:
        sec_table = Table(
            box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1), show_edge=False
        )
        sec_table.add_column("Severity", no_wrap=True)
        if multi_region:
            sec_table.add_column("Region", style="dim", no_wrap=True)
        sec_table.add_column("Resource", style="cyan", no_wrap=True)
        sec_table.add_column("Finding")
        for finding in sec_findings:
            row: list[str | Text] = [_severity_text(finding["severity"])]
            if multi_region:
                region = (
                    None
                    if is_global_security_finding(cast(dict[str, Any], finding))
                    else finding.get("region")
                )
                row.append(_display_scope_label(region))
            row += [finding["resource"], finding["finding"]]
            sec_table.add_row(*row)
        panel_body: Any = sec_table
        note_block = _render_degraded_notes(notes)
        if note_block is not None:
            panel_body = Group(sec_table, note_block)
        c.print(
            Panel(
                panel_body,
                title=(
                    f"[bold red]🛡️  Security[/bold red]  [dim]{len(sec_findings)} finding{'s' if len(sec_findings) != 1 else ''}[/dim]"
                    + ("  [yellow]degraded[/yellow]" if sec_result["errors"] else "")
                ),
                border_style="red",
                padding=(0, 1),
            )
        )
    elif sec_result["errors"]:
        note_block = _render_degraded_notes(notes)
        panel_body = (
            Group(
                Text.from_markup(
                    "[yellow]⚠  Security scan is degraded due to API errors. Findings may be incomplete.[/yellow]"
                ),
                note_block,
            )
            if note_block is not None
            else "[yellow]⚠  Security scan is degraded due to API errors. Findings may be incomplete.[/yellow]"
        )
        c.print(
            Panel(
                panel_body,
                title="[bold yellow]⚠ Security (Degraded)[/bold yellow]",
                border_style="yellow",
                padding=(0, 1),
            )
        )
    else:
        c.print(
            Panel(
                "[green]✓  All security checks passed.[/green]",
                title="[bold green]✅ Security[/bold green]",
                border_style="green",
                padding=(0, 1),
            )
        )
    c.print()


def _render_iam_panel(c: Console, iam_result: ScanResult) -> None:
    iam_findings = cast(list[dict[str, Any]], iam_result["data"])
    if iam_findings:
        iam_table = Table(
            box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1), show_edge=False
        )
        iam_table.add_column("Severity", no_wrap=True)
        iam_table.add_column("Principal", style="cyan", no_wrap=True)
        iam_table.add_column("Type", style="dim", no_wrap=True)
        iam_table.add_column("Policy", style="dim", no_wrap=True)
        iam_table.add_column("Reason")
        for finding in iam_findings:
            iam_table.add_row(
                _severity_text(finding["severity"]),
                f"{finding['principal_type']}/{finding['principal_name']}",
                finding["policy_type"],
                finding["policy_name"],
                finding["reason"],
            )
        c.print(
            Panel(
                iam_table,
                title=(
                    "[bold red]🔑 IAM Over-Permissive Policies[/bold red]  "
                    f"[dim]{len(iam_findings)} finding{'s' if len(iam_findings) != 1 else ''}[/dim]"
                ),
                border_style="red",
                padding=(0, 1),
            )
        )
    elif iam_result["errors"]:
        c.print(
            Panel(
                "[yellow]⚠  IAM policy scan is degraded due to API errors.[/yellow]",
                title="[bold yellow]⚠ IAM Policies (Degraded)[/bold yellow]",
                border_style="yellow",
                padding=(0, 1),
            )
        )
    else:
        c.print(
            Panel(
                "[green]✓  No over-permissive IAM policies detected.[/green]",
                title="[bold green]✅ IAM Policies[/bold green]",
                border_style="green",
                padding=(0, 1),
            )
        )
    c.print()


def _render_cloudwatch_panel(
    c: Console,
    cw_result: ScanResult,
    *,
    multi_region: bool,
) -> None:
    cw_findings = cast(list[dict[str, Any]], cw_result["data"])
    if cw_findings:
        table = Table(
            box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1), show_edge=False
        )
        table.add_column("Type", style="dim", no_wrap=True)
        if multi_region:
            table.add_column("Region", style="dim", no_wrap=True)
        table.add_column("Resource", style="cyan", no_wrap=True)
        table.add_column("Missing Alarms")
        for finding in cw_findings:
            row: list[str] = [finding["resource_type"]]
            if multi_region:
                row.append(_display_scope_label(finding.get("region")))
            row += [
                finding["resource_name"],
                "[yellow]" + ", ".join(finding["missing_alarms"]) + "[/yellow]",
            ]
            table.add_row(*row)
        c.print(
            Panel(
                table,
                title=(
                    "[bold yellow]📡 CloudWatch Alarm Gaps[/bold yellow]  "
                    f"[dim]{len(cw_findings)} resource{'s' if len(cw_findings) != 1 else ''} unmonitored[/dim]"
                ),
                border_style="yellow",
                padding=(0, 1),
            )
        )
    elif cw_result["errors"]:
        c.print(
            Panel(
                "[yellow]⚠  CloudWatch alarm coverage scan is degraded due to API errors.[/yellow]",
                title="[bold yellow]⚠ CloudWatch Alarms (Degraded)[/bold yellow]",
                border_style="yellow",
                padding=(0, 1),
            )
        )
    else:
        c.print(
            Panel(
                "[green]✓  All EC2, RDS, and Lambda resources have required CloudWatch alarms.[/green]",
                title="[bold green]✅ CloudWatch Alarms[/bold green]",
                border_style="green",
                padding=(0, 1),
            )
        )
    c.print()


def _render_cost_waste_panel(
    c: Console,
    cost_result: ScanResult,
    *,
    multi_region: bool,
) -> None:
    cost_findings = cast(list[CostFinding], cost_result["data"])
    if cost_findings:
        table = Table(
            box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1), show_edge=False
        )
        if multi_region:
            table.add_column("Region", style="dim", no_wrap=True)
        table.add_column("Resource", style="cyan", no_wrap=True)
        table.add_column("Finding")
        for finding in cost_findings:
            row: list[str] = []
            if multi_region:
                row.append(_display_scope_label(finding.get("region")))
            row += [finding["resource"], finding["finding"]]
            table.add_row(*row)
        c.print(
            Panel(
                table,
                title=(
                    "[bold yellow]🗑️  Cost Waste[/bold yellow]  "
                    f"[dim]{len(cost_findings)} finding{'s' if len(cost_findings) != 1 else ''}[/dim]"
                ),
                border_style="yellow",
                padding=(0, 1),
            )
        )
    elif cost_result["errors"]:
        c.print(
            Panel(
                "[yellow]⚠  Cost waste scan is degraded due to API errors.[/yellow]",
                title="[bold yellow]⚠ Cost Waste (Degraded)[/bold yellow]",
                border_style="yellow",
                padding=(0, 1),
            )
        )
    else:
        c.print(
            Panel(
                "[green]✓  No cost waste detected.[/green]",
                title="[bold green]✅ Cost Waste[/bold green]",
                border_style="green",
                padding=(0, 1),
            )
        )
    c.print()


def _render_tagging_panel(
    c: Console,
    tag_result: ScanResult,
    *,
    multi_region: bool,
) -> None:
    tag_findings = cast(list[dict[str, Any]], tag_result["data"])
    if tag_findings:
        table = Table(
            box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1), show_edge=False
        )
        table.add_column("Type", style="dim", no_wrap=True)
        if multi_region:
            table.add_column("Region", style="dim", no_wrap=True)
        table.add_column("Resource", style="cyan", no_wrap=True)
        table.add_column("Missing Tags")
        for finding in tag_findings:
            row: list[str] = [finding["resource_type"]]
            if multi_region:
                region = (
                    None
                    if is_global_tagging_finding(cast(dict[str, Any], finding))
                    else finding.get("region")
                )
                row.append(_display_scope_label(region))
            row += [
                finding["resource_name"],
                "[yellow]" + ", ".join(finding["missing_tags"]) + "[/yellow]",
            ]
            table.add_row(*row)
        c.print(
            Panel(
                table,
                title=(
                    "[bold yellow]🏷️  Tagging Compliance[/bold yellow]  "
                    f"[dim]{len(tag_findings)} resource{'s' if len(tag_findings) != 1 else ''} untagged[/dim]"
                ),
                border_style="yellow",
                padding=(0, 1),
            )
        )
    elif tag_result["errors"]:
        c.print(
            Panel(
                "[yellow]⚠  Tagging compliance scan is degraded due to API errors.[/yellow]",
                title="[bold yellow]⚠ Tagging Compliance (Degraded)[/bold yellow]",
                border_style="yellow",
                padding=(0, 1),
            )
        )
    else:
        c.print(
            Panel(
                "[green]✓  All resources carry the required tags.[/green]",
                title="[bold green]✅ Tagging Compliance[/bold green]",
                border_style="green",
                padding=(0, 1),
            )
        )
    c.print()


# ─────────────────────────────────────────────────────────────────────────────
# Section functions
# ─────────────────────────────────────────────────────────────────────────────


def _section_inventory(
    c: Console,
    regions: list[str | None],
    multi_region: bool,
) -> tuple[Table, ScanResult, ScanResult, ScanResult, ScanResult, bool]:
    """Fetch inventory across all regions; return data for downstream sections."""
    ec2_region_results: list[ScanResult] = []
    rds_region_results: list[ScanResult] = []
    lambda_region_results: list[ScanResult] = []

    def _inv_region(reg: str | None) -> tuple[ScanResult, ScanResult, ScanResult]:
        _ec2 = get_ec2_inventory(region=reg)
        _rds = get_rds_inventory(region=reg)
        _lmb = get_lambda_inventory(region=reg)
        if multi_region and reg is not None:
            for item in _ec2["data"]:
                item["region"] = reg
            for item in _rds["data"]:
                item["region"] = reg
            for item in _lmb["data"]:
                item["region"] = reg
        return _ec2, _rds, _lmb

    with c.status("[cyan]📦  Scanning inventory...[/cyan]", spinner="dots"):
        s3_result = get_s3_inventory()
        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
            for _ec2, _rds, _lmb in pool.map(_inv_region, regions):
                ec2_region_results.append(_ec2)
                rds_region_results.append(_rds)
                lambda_region_results.append(_lmb)

    ec2_result = merge_list_results(ec2_region_results)
    rds_result = merge_list_results(rds_region_results)
    lambda_result = merge_list_results(lambda_region_results)
    s3s = s3_result["data"]
    ec2s = ec2_result["data"]
    rdss = rds_result["data"]
    lambdas = lambda_result["data"]

    cur_bucket_exists = False
    if s3s:
        cur_bucket_exists = any(
            b.get("BucketName", "").startswith("cur-data-lighthouse-") for b in s3s
        )

    inv_table = Table(
        box=box.SIMPLE_HEAD, show_header=False, padding=(0, 1), show_edge=False
    )
    inv_table.add_column("Resource", style="dim")
    inv_table.add_column("Count", justify="right", style="bold white")
    inv_table.add_row("⚡ EC2 Instances", _count(ec2s))
    inv_table.add_row("🗄  RDS Databases", _count(rdss))
    inv_table.add_row("🪣 S3 Buckets", _count(s3s))
    inv_table.add_row("λ  Lambda", _count(lambdas))

    return (
        inv_table,
        s3_result,
        ec2_result,
        rds_result,
        lambda_result,
        cur_bucket_exists,
    )


def _section_cost_columns(
    c: Console,
    inv_table: Table,
    days: int,
    account_id: str,
    regions: list[str | None],
    multi_region: bool,
    render: bool = True,
) -> tuple[ScanResult, dict[str, str]]:
    """Fetch costs, build trend, and render inventory + cost side-by-side."""
    with c.status(f"[cyan]💰  Fetching costs ({days}d)...[/cyan]", spinner="dots"):
        costs_result = get_monthly_cost_summary(days=days)
    costs = cast(dict[str, Any], costs_result["data"])

    prev_snapshot = db_manager.get_latest_cost_snapshot(account_id)
    if costs_result["ok"]:
        db_manager.record_cost_snapshot(
            account_id=account_id,
            start=costs["start"],
            end=costs["end"],
            total=costs["total_usd"],
            breakdown=costs["breakdown"],
        )

    trend_suffix = ""
    if prev_snapshot and costs_result["ok"]:
        prev_total = prev_snapshot["total_usd"]
        curr_total = costs["total_usd"]
        if prev_total > 0:
            pct = ((curr_total - prev_total) / prev_total) * 100
            arrow = "▲" if pct > 0 else "▼"
            color = "red" if pct > 0 else "green"
            trend_suffix = (
                f"  [{color}]{arrow} {pct:+.1f}%[/{color}] [dim]vs last scan[/dim]"
            )

    period_label = costs.get("period", "—")
    display_meta = {
        "period_label": period_label,
        "trend_suffix": trend_suffix,
    }
    if render:
        _render_inventory_cost_columns(
            c,
            inv_table=inv_table,
            costs_result=costs_result,
            display_meta=display_meta,
            regions=regions,
            multi_region=multi_region,
        )
    return costs_result, display_meta


def _section_cost_anomalies(
    c: Console, threshold_pct: float = 50.0, render: bool = True
) -> ScanResult:
    """Detect and render cost anomaly panel."""
    with c.status("[cyan]🚨  Detecting cost anomalies...[/cyan]", spinner="dots"):
        anomalies_result = detect_cost_anomalies(threshold_pct=threshold_pct)
    if render:
        _render_cost_anomalies_panel(c, anomalies_result)
    return anomalies_result


def _section_cost_forecast(c: Console, render: bool = True) -> ScanResult:
    """Fetch and optionally render a 30-day cost forecast."""
    with c.status("[cyan]📈  Fetching 30-day cost forecast...[/cyan]", spinner="dots"):
        forecast_result = get_cost_forecast()
    if render and forecast_result["ok"]:
        fc = cast(dict[str, Any], forecast_result["data"])
        total = fc.get("total_usd")
        period = f"{fc.get('forecast_start')} → {fc.get('forecast_end')}"
        if total is not None:
            c.print(
                f"[bold cyan]📈 30-Day Forecast[/bold cyan]  "
                f"[bold yellow]${total:,.2f}[/bold yellow]  "
                f"[dim]{period}[/dim]"
            )
    return forecast_result


def _render_cost_attribution_panel(c: Console, attribution_result: ScanResult) -> None:
    attributions = cast(list[dict[str, Any]], attribution_result["data"])
    if not attributions:
        return
    for attr in attributions:
        table = Table(
            box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1), show_edge=False
        )
        table.add_column("Event", style="cyan", no_wrap=True)
        table.add_column("Actor", style="bold")
        table.add_column("Time", style="dim")
        table.add_column("Region", style="dim")
        for ev in attr.get("events", []):
            table.add_row(
                ev.get("event_name", ""),
                ev.get("actor", "unknown"),
                str(ev.get("event_time", ""))[:19],
                ev.get("region", ""),
            )
        c.print(
            Panel(
                table,
                title=(
                    f"[bold magenta]🔍 Attribution: {attr['service']}[/bold magenta]  "
                    f"[dim]{attr['pct_change']:+.1f}% spend change[/dim]"
                ),
                border_style="magenta",
                padding=(0, 1),
            )
        )
    c.print()


def _section_cost_attribution(
    c: Console,
    anomalies_result: ScanResult,
    render: bool = True,
) -> ScanResult:
    """Correlate cost anomalies with CloudTrail events and optionally render."""
    anomalies = anomalies_result.get("data") or []
    with c.status(
        "[cyan]🔍  Attributing cost anomalies via CloudTrail...[/cyan]", spinner="dots"
    ):
        attribution_result = get_cost_attribution(anomalies)
    if render:
        _render_cost_attribution_panel(c, attribution_result)
    return attribution_result


def _section_ri_sp_coverage(c: Console, days: int, render: bool = True) -> ScanResult:
    """Fetch and render RI / Savings Plan coverage panel."""
    with c.status(
        "[cyan]📊  Checking RI / Savings Plan coverage...[/cyan]", spinner="dots"
    ):
        ri_sp_result = get_ri_sp_coverage(days=days)
    if render:
        _render_ri_sp_coverage_panel(c, ri_sp_result)
    return ri_sp_result


def _render_ri_sp_advisor_panel(
    c: Console,
    ri_result: ScanResult,
    sp_result: ScanResult,
) -> None:
    """Render RI and SP purchase recommendations as a single panel."""
    ri_recs = cast(list[dict[str, Any]], ri_result["data"])
    sp_recs = cast(list[dict[str, Any]], sp_result["data"])
    if not ri_recs and not sp_recs:
        return

    groups: list[Any] = []

    if ri_recs:
        ri_table = Table(
            box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1), show_edge=False
        )
        ri_table.add_column("Service", style="dim", no_wrap=True)
        ri_table.add_column("Instance", style="cyan", no_wrap=True)
        ri_table.add_column("Region", style="dim", no_wrap=True)
        ri_table.add_column("Term", no_wrap=True)
        ri_table.add_column("Qty", justify="right")
        ri_table.add_column("Monthly Savings", justify="right", style="bold green")
        ri_table.add_column("Break-even", justify="right", style="dim")
        for rec in ri_recs[:10]:
            be = rec["break_even_months"]
            be_str = "immediate" if be <= 0 else f"{be:.1f} mo"
            ri_table.add_row(
                rec["service"],
                rec["instance_type"],
                rec["region"],
                rec["term"],
                str(rec["count"]),
                f"${rec['monthly_savings_usd']:,.0f}",
                be_str,
            )
        groups.append(Text("Reserved Instances", style="bold dim"))
        groups.append(ri_table)

    if sp_recs:
        sp_table = Table(
            box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1), show_edge=False
        )
        sp_table.add_column("Plan Type", style="cyan", no_wrap=True)
        sp_table.add_column("Term", no_wrap=True)
        sp_table.add_column("Hourly Commit", justify="right")
        sp_table.add_column("Monthly Savings", justify="right", style="bold green")
        sp_table.add_column("Savings %", justify="right")
        for rec in sp_recs:
            sp_table.add_row(
                rec["savings_plan_type"],
                rec["term"],
                f"${rec['hourly_commitment_usd']:.4f}",
                f"${rec['estimated_monthly_savings_usd']:,.0f}",
                f"{rec['estimated_savings_pct']:.1f}%",
            )
        if ri_recs:
            groups.append(Text(""))
        groups.append(Text("Savings Plans", style="bold dim"))
        groups.append(sp_table)

    total_ri_savings = sum(r["monthly_savings_usd"] for r in ri_recs)
    total_sp_savings = sum(r["estimated_monthly_savings_usd"] for r in sp_recs)
    total_savings = total_ri_savings + total_sp_savings

    c.print(
        Panel(
            Group(*groups),
            title=(
                "[bold green]💡 RI / SP Purchase Advisor[/bold green]  "
                f"[dim]potential savings [bold]${total_savings:,.0f}[/bold]/mo[/dim]"
            ),
            border_style="green",
            padding=(0, 1),
        )
    )
    c.print()


def _section_ri_sp_advisor(c: Console, render: bool = True) -> dict[str, ScanResult]:
    """Fetch RI and SP purchase recommendations and optionally render them."""
    with c.status(
        "[cyan]💡  Fetching RI / SP purchase recommendations...[/cyan]", spinner="dots"
    ):
        ri_result = get_ri_recommendations()
        sp_result = get_sp_recommendations()
    if render:
        _render_ri_sp_advisor_panel(c, ri_result, sp_result)
    return {"ri": ri_result, "sp": sp_result}


def _render_compute_optimizer_panel(
    c: Console,
    result: ScanResult,
) -> None:
    """Render Compute Optimizer EC2 rightsizing recommendations as a panel."""
    recs = cast(list[dict[str, Any]], result["data"])
    if not result["ok"] or not recs:
        return

    _RISK_STYLE = {
        "VeryLow": "green",
        "Low": "green",
        "Medium": "yellow",
        "High": "red",
    }

    table = Table(
        box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1), show_edge=False
    )
    table.add_column("Instance", style="cyan", no_wrap=True)
    table.add_column("Current", style="dim", no_wrap=True)
    table.add_column("Recommended", no_wrap=True)
    table.add_column("Savings/mo", justify="right", style="bold green")
    table.add_column("Savings%", justify="right")
    table.add_column("Risk", no_wrap=True)
    table.add_column("Graviton", no_wrap=True)

    for rec in recs[:20]:
        instance_label = (
            f"{rec['instance_name']} ({rec['instance_id']})"
            if rec.get("instance_name")
            else rec["instance_id"]
        )
        rec_style = "green" if rec.get("is_graviton") else "cyan"
        risk_style = _RISK_STYLE.get(rec["performance_risk"], "white")
        graviton_mark = "[green]\u2713[/green]" if rec.get("is_graviton") else ""

        table.add_row(
            instance_label,
            rec["current_type"],
            f"[{rec_style}]{rec['recommended_type']}[/{rec_style}]",
            f"${rec['estimated_monthly_savings_usd']:.2f}",
            f"{rec['estimated_savings_pct']:.1f}%",
            f"[{risk_style}]{rec['performance_risk']}[/{risk_style}]",
            graviton_mark,
        )

    total_savings = sum(r["estimated_monthly_savings_usd"] for r in recs)
    c.print(
        Panel(
            table,
            title=(
                f"[bold cyan]Compute Optimizer — {len(recs)} recommendation(s)[/bold cyan]  "
                f"[dim]potential savings [bold]${total_savings:,.0f}[/bold]/mo[/dim]"
            ),
            border_style="cyan",
            padding=(0, 1),
        )
    )
    c.print()


def _section_compute_optimizer(c: Console, render: bool = True) -> ScanResult:
    """Fetch Compute Optimizer recommendations and optionally render them."""
    with c.status(
        "[cyan]Fetching Compute Optimizer recommendations...[/cyan]",
        spinner="dots",
    ):
        result = get_compute_optimizer_recommendations()
    if render:
        _render_compute_optimizer_panel(c, result)
    return result


def _render_tag_cost_panel(c: Console, result: ScanResult) -> None:
    """Render cost allocation tag coverage as a panel."""
    rows = result["data"] if result["ok"] else []
    if not rows:
        c.print(
            Panel(
                "[dim]No spend data available[/dim]",
                title="Cost Allocation Tag Coverage",
            )
        )
        return
    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
    table.add_column("Tag Key", style="bold")
    table.add_column("Untagged", justify="right")
    table.add_column("Tagged", justify="right")
    table.add_column("Total", justify="right")
    table.add_column("% Untagged", justify="right")
    for row in rows:
        pct = row["untagged_pct"]
        pct_style = "red" if pct >= 50 else ("yellow" if pct >= 20 else "green")
        table.add_row(
            row["tag_key"],
            f"${row['untagged_usd']:,.2f}",
            f"${row['tagged_usd']:,.2f}",
            f"${row['total_usd']:,.2f}",
            f"[{pct_style}]{pct:.1f}%[/{pct_style}]",
        )
    c.print(Panel(table, title="Cost Allocation Tag Coverage"))


def _section_tag_cost(c: Console, render: bool = True) -> ScanResult:
    """Fetch untagged spend data and optionally render the panel."""
    with c.status(
        "[cyan]Checking cost allocation tag coverage...[/cyan]",
        spinner="dots",
    ):
        result = get_untagged_spend()
    if render:
        _render_tag_cost_panel(c, result)
    return result


def _section_security(
    c: Console,
    s3s: list,
    rdss: list,
    regions: list[str | None],
    multi_region: bool,
    render: bool = True,
) -> ScanResult:
    """Run security scan across all regions and render findings panel."""
    sec_results: list[ScanResult] = []

    def _sec_region(args: tuple[str | None, bool]) -> ScanResult:
        reg, include_global = args
        _rdss_r = [r for r in rdss if r.get("region") == reg] if multi_region else rdss
        _sec = run_security_scan(
            s3s=s3s, rdss=_rdss_r, region=reg, include_global=include_global
        )
        if multi_region and reg is not None:
            for f in _sec["data"]:
                if "region" not in f and not is_global_security_finding(f):
                    f["region"] = reg
        return _sec

    region_args = [(reg, i == 0) for i, reg in enumerate(regions)]
    with c.status("[cyan]🛡️   Running security checks...[/cyan]", spinner="dots"):
        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
            for result in pool.map(_sec_region, region_args):
                sec_results.append(result)
    sec_result = merge_list_results(sec_results)
    if render:
        _render_security_panel(c, sec_result, multi_region=multi_region)
    return sec_result


def _render_sg_blast_radius_panel(
    c: Console,
    blast_result: ScanResult,
) -> None:
    """Render a panel showing blast-radius details for each open security group."""
    blast_list = cast(list[SGBlastRadius], blast_result["data"])
    if not blast_list:
        return

    _EXPOSURE_STYLE = {
        "INTERNET_EXPOSED": "bold red",
        "UNKNOWN": "bold yellow",
        "PRIVATE": "bold green",
    }

    groups: list[Any] = []
    for br in blast_list:
        exposure = br["exposure"]
        style = _EXPOSURE_STYLE.get(exposure, "white")
        header = Text()
        header.append(br["sg_id"], style="bold cyan")
        header.append("  ·  ")
        header.append(exposure, style=style)
        if br["sg_name"] != br["sg_id"]:
            header.append(f"  ({br['sg_name']})", style="dim")

        resource_table = Table(
            box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1), show_edge=False
        )
        resource_table.add_column("Type", style="dim", no_wrap=True)
        resource_table.add_column("Resource ID", style="cyan", no_wrap=True)
        resource_table.add_column("Public IP", no_wrap=True)

        for res in br["attached_resources"]:
            pub_ip = res["public_ip"] or "[dim]-[/dim]"
            resource_table.add_row(res["resource_type"], res["resource_id"], pub_ip)

        if not br["attached_resources"]:
            resource_table.add_row("[dim]none[/dim]", "", "")

        igw_str = "[green]yes[/green]" if br["has_igw"] else "[dim]no[/dim]"
        ct_str = str(br["recent_connection_count"])
        ips_str = (
            ", ".join(br["top_source_ips"]) if br["top_source_ips"] else "[dim]-[/dim]"
        )

        meta = Text()
        meta.append(f"IGW: {igw_str}  ")
        meta.append(f"CT events (30d): {ct_str}  ")
        meta.append(f"Top IPs: {ips_str}")

        groups.extend([header, resource_table, meta, Text("")])

    if not groups:
        return

    c.print(
        Panel(
            Group(*groups),
            title="[bold red]🔍 Security Group Blast Radius[/bold red]",
            border_style="red",
            padding=(0, 1),
        )
    )
    c.print()


def _section_sg_blast_radius(
    c: Console,
    sec_result: ScanResult,
    region: str | None = None,
    render: bool = True,
) -> ScanResult:
    """Enrich open-SG findings with blast radius data and optionally render."""
    sg_ids = list(
        dict.fromkeys(
            f["resource"]
            for f in (sec_result.get("data") or [])
            if str(f.get("resource", "")).startswith("sg-")
        )
    )
    if not sg_ids:
        return ok_result([])

    with c.status("[cyan]🔍  Analysing SG blast radius...[/cyan]", spinner="dots"):
        blast_result = get_sg_blast_radius(sg_ids, region=region)
    if render:
        _render_sg_blast_radius_panel(c, blast_result)
    return blast_result


def _section_iam(c: Console, render: bool = True) -> ScanResult:
    """Scan for over-permissive IAM policies and render findings panel."""
    with c.status("[cyan]🔑  Scanning IAM policies...[/cyan]", spinner="dots"):
        iam_result = cast(ScanResult, detect_overpermissive_iam())
    if render:
        _render_iam_panel(c, iam_result)
    return iam_result


def _section_cloudwatch(
    c: Console,
    regions: list[str | None],
    multi_region: bool,
    render: bool = True,
) -> ScanResult:
    """Check CloudWatch alarm coverage across all regions and render panel."""
    cw_results: list[ScanResult] = []

    def _cw_region(reg: str | None) -> ScanResult:
        _cw = detect_cloudwatch_gaps(region=reg)
        if multi_region and reg is not None:
            for f in _cw["data"]:
                f["region"] = reg
        return cast(ScanResult, _cw)

    with c.status(
        "[cyan]📡  Checking CloudWatch alarm coverage...[/cyan]", spinner="dots"
    ):
        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
            for result in pool.map(_cw_region, regions):
                cw_results.append(result)
    cw_result = merge_list_results(cw_results)
    if render:
        _render_cloudwatch_panel(c, cw_result, multi_region=multi_region)
    return cw_result


def _section_cost_waste(
    c: Console,
    regions: list[str | None],
    multi_region: bool,
    render: bool = True,
) -> ScanResult:
    """Scan for cost waste across all regions and render findings panel."""
    cost_results: list[ScanResult] = []

    def _cost_region(reg: str | None) -> ScanResult:
        _cost = run_cost_scan(region=reg)
        if multi_region and reg is not None:
            for f in _cost["data"]:
                f["region"] = reg
        return cast(ScanResult, _cost)

    with c.status("[cyan]🗑️   Scanning for cost waste...[/cyan]", spinner="dots"):
        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
            for result in pool.map(_cost_region, regions):
                cost_results.append(result)
    cost_result = merge_list_results(cost_results)
    if render:
        _render_cost_waste_panel(c, cost_result, multi_region=multi_region)
    return cost_result


def _section_tagging(
    c: Console,
    regions: list[str | None],
    multi_region: bool,
    required_tags: list[str] | None = None,
    render: bool = True,
) -> ScanResult:
    """Check tagging compliance across all regions and render panel."""
    tag_results: list[ScanResult] = []

    def _tag_region(args: tuple[str | None, bool]) -> ScanResult:
        reg, include_s3 = args
        _tag = check_tagging_compliance(
            region=reg,
            include_s3=include_s3,
            required_tags=required_tags,
        )
        if multi_region and reg is not None:
            for f in _tag["data"]:
                if "region" not in f and not is_global_tagging_finding(f):
                    f["region"] = reg
        return cast(ScanResult, _tag)

    tag_args = [(reg, i == 0) for i, reg in enumerate(regions)]
    with c.status("[cyan]🏷️   Checking tag compliance...[/cyan]", spinner="dots"):
        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
            for result in pool.map(_tag_region, tag_args):
                tag_results.append(result)
    tag_result = merge_list_results(tag_results)
    if render:
        _render_tagging_panel(c, tag_result, multi_region=multi_region)
    return tag_result


def _section_lambda_detail(c: Console, lambdas: list) -> None:
    """Render Lambda function detail panel if any valid functions exist."""
    valid_lambdas = [
        fn for fn in lambdas if isinstance(fn, dict) and "FunctionName" in fn
    ]
    if not valid_lambdas:
        return

    lambda_table = Table(
        box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1), show_edge=False
    )
    lambda_table.add_column("Function", style="cyan", no_wrap=True)
    lambda_table.add_column("Runtime", style="dim")
    lambda_table.add_column("Memory (MB)", justify="right")
    lambda_table.add_column("Code (MB)", justify="right", style="dim")
    lambda_table.add_column("Last Deploy", style="dim")
    for fn in valid_lambdas:
        name = fn["FunctionName"]
        if fn.get("Stale"):
            name = f"[yellow]{name}[/yellow]"
        memory_str = (
            f"[yellow]{fn['MemorySize']}[/yellow]"
            if fn["MemorySize"] >= 1024
            else str(fn["MemorySize"])
        )
        lambda_table.add_row(
            name,
            fn["Runtime"],
            memory_str,
            str(fn["CodeSizeMB"]),
            fn["LastModified"],
        )
    stale_count = sum(1 for fn in valid_lambdas if fn.get("Stale"))
    stale_note = f"  [dim]· {stale_count} stale (>{180}d)[/dim]" if stale_count else ""
    c.print(
        Panel(
            lambda_table,
            title=f"[bold blue]⚡ Lambda Functions[/bold blue]  [dim]{len(valid_lambdas)} total[/dim]{stale_note}",
            border_style="blue",
            padding=(0, 1),
        )
    )
    c.print()


def _remediation_sort_key(finding: dict[str, Any]) -> tuple[int, str, str]:
    severity_rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, None: 3}
    return (
        severity_rank.get(cast(str | None, finding.get("severity")), 3),
        str(finding.get("_source", "")),
        str(finding.get("resource", "")),
    )


def _parse_remediation_selection(raw: str, total: int) -> list[int]:
    normalized = raw.strip().lower()
    if not normalized:
        return []
    if normalized == "all":
        return list(range(total))
    if normalized == "top":
        return [0] if total else []

    indices: list[int] = []
    invalid: list[str] = []
    for chunk in raw.split(","):
        value = chunk.strip()
        if not value:
            continue
        if not value.isdigit():
            invalid.append(value)
            continue
        idx = int(value) - 1
        if idx < 0 or idx >= total:
            invalid.append(value)
            continue
        if idx not in indices:
            indices.append(idx)
    if invalid:
        joined = ", ".join(invalid)
        raise ValueError(f"Invalid selection: {joined}")
    if not indices:
        raise ValueError("No valid remediation selections were provided.")
    return indices


def _render_remediation_plan_panel(c: Console, plan: RemediationPlan) -> None:
    groups: list[Any] = []
    for phase in plan["phases"]:
        color = phase["color"]
        risk = phase["risk"]
        count = len(phase["actions"])
        header = Text(
            f"  {phase['title']}  ·  {risk}  ({count} action{'s' if count != 1 else ''})",
            style=f"bold {color}",
        )
        phase_table = Table(
            box=box.SIMPLE_HEAD, show_header=False, padding=(0, 2), show_edge=False
        )
        phase_table.add_column("Label", no_wrap=True)
        phase_table.add_column("Source", style="dim", no_wrap=True)
        phase_table.add_column("Resource", no_wrap=True)
        for action in phase["actions"]:
            phase_table.add_row(action["label"], action["source"], action["resource"])
        groups.append(header)
        groups.append(phase_table)
    c.print(
        Panel(
            Group(*groups),
            title="[bold cyan]🔧 Remediation Plan[/bold cyan]",
            border_style="cyan",
            padding=(0, 1),
        )
    )
    c.print()


def _render_remediation_preview(c: Console, selections: list[dict[str, Any]]) -> None:
    preview = Table(
        box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1), show_edge=False
    )
    preview.add_column("Action", style="bold cyan", no_wrap=True)
    preview.add_column("Source", style="dim", no_wrap=True)
    preview.add_column("Scope", style="dim", no_wrap=True)
    preview.add_column("Resource", no_wrap=True)
    for finding in selections:
        preview.add_row(
            str(finding["remediation_label"]),
            str(finding["_source"]),
            _display_scope_label(cast(str | None, finding.get("region"))),
            str(finding["resource"]),
        )
    c.print(
        Panel(
            preview,
            title="[bold cyan]Remediation Preview[/bold cyan]",
            border_style="cyan",
            padding=(0, 1),
        )
    )
    c.print()


def _section_remediation(
    c: Console,
    sec_findings: list[SecurityFinding],
    cost_findings: list[CostFinding],
) -> None:
    """Offer one-click remediation for actionable findings."""
    remediable: list[dict[str, Any]] = []
    for security_finding in sec_findings:
        if security_finding.get("remediation_type"):
            remediable.append({**security_finding, "_source": "security"})
    for cost_finding in cost_findings:
        if cost_finding.get("remediation_type"):
            remediable.append({**cost_finding, "_source": "cost_waste"})
    remediable.sort(key=_remediation_sort_key)
    if not remediable:
        return

    from .tools.remediation_actions import (
        apply_s3_block_public_access,
        apply_s3_default_encryption,
        delete_ebs_volume,
        enable_cloudtrail_logging,
        enable_guardduty,
        enforce_imdsv2,
        release_eip,
    )

    _ACTIONS = {
        "s3_block_public_access": apply_s3_block_public_access,
        "delete_ebs_volume": delete_ebs_volume,
        "release_eip": release_eip,
        "enable_guardduty": enable_guardduty,
        "enable_cloudtrail_logging": enable_cloudtrail_logging,
        "enforce_imdsv2": enforce_imdsv2,
        "s3_default_encryption": apply_s3_default_encryption,
    }
    _REGION_REQUIRED = {
        "delete_ebs_volume",
        "release_eip",
        "enable_guardduty",
        "enable_cloudtrail_logging",
        "enforce_imdsv2",
    }

    plan = build_remediation_plan(remediable)
    _render_remediation_plan_panel(c, plan)

    available_phases = [p["phase"] for p in plan["phases"]]
    phase_labels = " / ".join(str(p) for p in available_phases)
    raw = Prompt.ask(
        f"  [bold cyan]Approve phases[/bold cyan] "
        f"[dim](all / {phase_labels} / none, Enter=skip)[/dim]",
        default="",
    )

    if not raw.strip():
        c.print()
        return

    try:
        approved = parse_phase_selection(raw, available_phases)
    except ValueError as exc:
        logger.error(str(exc))
        c.print()
        return

    if not approved:
        c.print("  [dim]No phases approved. Skipped.[/dim]")
        c.print()
        return

    applied = 0
    failed = 0
    for phase in plan["phases"]:
        if phase["phase"] not in approved:
            continue
        for action in phase["actions"]:
            rtype = action["remediation_type"]
            resource = action["resource"]
            label = action["label"]
            fn = _ACTIONS.get(rtype)
            if not fn:
                logger.error(f"Unknown remediation type: {rtype}")
                failed += 1
                continue
            region = action["region"]
            if rtype in _REGION_REQUIRED and not region:
                logger.error(f"Missing region for {rtype} on {resource}; skipping.")
                failed += 1
                continue
            with c.status(
                f"[cyan]🔧  Applying {label} on {resource}...[/cyan]", spinner="dots"
            ):
                ok = fn(resource, region=region)
            if ok:
                logger.success(f"{label} applied to {resource}.")
                applied += 1
            else:
                logger.error(f"Failed to apply {label} on {resource}.")
                failed += 1

    parts = []
    if applied:
        parts.append(f"[green]✅ {applied} applied[/green]")
    if failed:
        parts.append(f"[red]❌ {failed} failed[/red]")
    if parts:
        c.print(f"  {' · '.join(parts)}")
    c.print()


def _section_cur_upsell(
    c: Console,
    cur_bucket_exists: bool,
    account_id: str,
) -> None:
    """Show CUR upsell panel and optionally deploy the CloudFormation stack."""
    if cur_bucket_exists:
        return

    c.print(
        Panel(
            "AWS Cost Explorer shows only daily service-level totals. "
            "Enable [bold]Cost & Usage Reports (CUR)[/bold] for per-resource attribution and long-term FinOps analysis.\n\n"
            "[bold cyan]Ask the agent:[/bold cyan]  [italic]'Deploy CUR Export'[/italic]",
            title="[bold yellow]⚡ Enable Deep FinOps[/bold yellow]",
            border_style="yellow",
            padding=(1, 2),
        )
    )

    if typer.confirm("\nDeploy the CUR CloudFormation stack now?"):
        import uuid

        cust_id = typer.prompt("Customer resource ID (e.g. cust-abc123)")
        ext_id = typer.prompt("External ID for trust relationship")
        s3_bucket = f"cur-data-lighthouse-{uuid.uuid4().hex[:8]}"

        from .tools.cfn_deploy import deploy_cur_template

        logger.action_start("Deploying CUR CloudFormation stack...")
        success = deploy_cur_template(
            account_id=account_id,
            cust_id=cust_id,
            ext_id=ext_id,
            s3_bucket=s3_bucket,
        )
        if success:
            logger.success("CUR deployment initiated successfully.")
        else:
            logger.error("CUR deployment failed.")


# ─────────────────────────────────────────────────────────────────────────────
# SARIF 2.1.0 output helpers
# ─────────────────────────────────────────────────────────────────────────────


def _finding_to_rule_id(text: str) -> str:
    """Convert a finding description to a kebab-case SARIF rule ID."""
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:64]


def _rule_id_to_name(rule_id: str) -> str:
    """Convert a kebab-case rule ID to CamelCase rule name."""
    return "".join(part.capitalize() for part in rule_id.split("-"))


def _severity_to_sarif_level(severity: str | None) -> str:
    """Map scan severity to SARIF level."""
    if severity in ("CRITICAL", "HIGH"):
        return "error"
    if severity == "MEDIUM":
        return "warning"
    if severity == "LOW":
        return "note"
    return "warning"


def _build_sarif_output(payloads: dict[str, Any], account_id: str) -> dict[str, Any]:
    """Build a SARIF 2.1.0 document from scan payloads."""
    v1 = payloads.get("v1", {})

    # Collect all (finding_text, resource_id, severity) tuples
    raw_findings: list[tuple[str, str, str | None]] = []
    for f in v1.get("security_findings", []):
        raw_findings.append(
            (str(f.get("finding", "")), str(f.get("resource", "")), f.get("severity"))
        )
    for f in v1.get("iam_findings", []):
        raw_findings.append(
            (
                str(f.get("reason", "")),
                str(f.get("principal_name", "")),
                f.get("severity"),
            )
        )
    for f in v1.get("cost_waste", []):
        raw_findings.append(
            (str(f.get("finding", "")), str(f.get("resource", "")), None)
        )
    for f in v1.get("tagging_findings", []):
        missing = f.get("missing_tags", [])
        text = (
            "Missing tags: " + ", ".join(missing)
            if missing
            else "Missing required tags"
        )
        raw_findings.append((text, str(f.get("resource_id", "")), None))
    for f in v1.get("cloudwatch_findings", []):
        missing = f.get("missing_alarms", [])
        text = (
            "Missing alarms: " + ", ".join(missing)
            if missing
            else "Missing CloudWatch alarms"
        )
        raw_findings.append((text, str(f.get("resource_id", "")), None))
    for f in v1.get("compute_optimizer", []):
        text = (
            f"EC2 rightsizing: {f.get('current_type', '')} -> "
            f"{f.get('recommended_type', '')} "
            f"(saves ${f.get('estimated_monthly_savings_usd', 0):.2f}/mo)"
        )
        raw_findings.append((text, str(f.get("instance_id", "")), None))
    for f in v1.get("tag_cost_coverage", []):
        if f.get("untagged_pct", 0) > 20:
            text = (
                f"Tag '{f['tag_key']}' missing on {f['untagged_pct']:.1f}% of spend"
                f" (${f['untagged_usd']:.2f} untagged)"
            )
            raw_findings.append((text, f["tag_key"], None))

    # Build unique rules (dedup by rule_id)
    seen_rules: dict[str, dict[str, Any]] = {}
    for finding_text, _, severity in raw_findings:
        rid = _finding_to_rule_id(finding_text)
        if rid and rid not in seen_rules:
            level = _severity_to_sarif_level(severity)
            seen_rules[rid] = {
                "id": rid,
                "name": _rule_id_to_name(rid),
                "shortDescription": {"text": finding_text},
                "defaultConfiguration": {"level": level},
            }

    # Build results
    results: list[dict[str, Any]] = []
    for finding_text, resource_id, severity in raw_findings:
        rid = _finding_to_rule_id(finding_text)
        if not rid:
            continue
        results.append(
            {
                "ruleId": rid,
                "level": _severity_to_sarif_level(severity),
                "message": {"text": finding_text},
                "locations": [
                    {
                        "logicalLocations": [
                            {
                                "name": resource_id,
                                "kind": "aws-resource",
                                "fullyQualifiedName": f"aws://{account_id}/{resource_id}",
                            }
                        ]
                    }
                ],
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "aws-lighthouse",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/your-org/aws-lighthouse",
                        "rules": list(seen_rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


# ─────────────────────────────────────────────────────────────────────────────
# analyze command
# ─────────────────────────────────────────────────────────────────────────────
def _validate_output_options(output: str, json_schema: str) -> tuple[str, str]:
    output_mode = output.lower().strip()
    schema = json_schema.lower().strip()
    if output_mode not in {"text", "json", "sarif"}:
        raise typer.BadParameter("--output must be 'text', 'json', or 'sarif'")
    if schema not in {"v1", "v2"}:
        raise typer.BadParameter("--json-schema must be either 'v1' or 'v2'")
    return output_mode, schema


def _validate_watch_view(view: str) -> str:
    normalized = view.lower().strip()
    if normalized not in {"compact", "full"}:
        raise typer.BadParameter("--view must be either 'compact' or 'full'")
    return normalized


def _run_analyze_cycle(
    *,
    days: int,
    region: str | None,
    output_mode: str,
    interactive: bool,
    since_last: bool,
    policy: ScanPolicy | None = None,
    watch_cycle: int | None = None,
    watch_view: str = "full",
) -> dict[str, dict[str, Any]]:
    """Execute one analyze cycle and return both v1 and v2 machine payloads."""
    effective_policy = policy or ScanPolicy.default()
    json_mode = output_mode in {"json", "sarif"}
    c = Console(file=io.StringIO(), no_color=True) if json_mode else logger.console
    original_logger_console = logger.console
    if json_mode:
        logger.console = c

    try:
        if watch_cycle is not None and not json_mode:
            c.print()
            c.print(
                Rule(
                    f" 🔁  AWS LIGHTHOUSE WATCH · cycle {watch_cycle} ",
                    style="bold cyan",
                    align="center",
                )
            )
            c.print()

        c.print()
        c.print(Rule(" 🔦  AWS LIGHTHOUSE ", style="bold cyan", align="center"))
        c.print()

        with c.status("[cyan]🔐  Authenticating...[/cyan]", spinner="dots"):
            session = get_aws_session()
            account_id = session.client("sts").get_caller_identity()["Account"]

        c.print(
            f"  [dim]🔐 Account[/dim]  [bold]{account_id}[/bold]  "
            f"[dim]·  📅 {datetime.now().strftime('%Y-%m-%d  %H:%M')}[/dim]"
        )
        c.print()

        region_errors: list[ScanError] = []
        if region:
            regions: list[str | None] = [region]
            c.print(f"  [dim]🌍 Region[/dim]  [bold]{region}[/bold]")
            c.print()
        else:
            with c.status(
                "[cyan]🌍  Detecting enabled regions...[/cyan]", spinner="dots"
            ):
                region_result = get_enabled_regions()
            raw_regions = list(region_result["data"])
            region_errors.extend(region_result["errors"])
            if effective_policy.regions.active():
                if region_result["errors"] and not raw_regions:
                    raise typer.BadParameter(
                        "Configured --config region filters require successful region discovery."
                    )
                try:
                    raw_regions = effective_policy.resolve_regions(raw_regions)
                except PolicyConfigError as exc:
                    raise typer.BadParameter(
                        f"--config region filter error: {exc}"
                    ) from exc
            if raw_regions:
                regions = list(raw_regions)
            else:
                regions = [None]

        multi_region = len(regions) > 1
        if multi_region:
            c.print(
                f"  [dim]🌍 Scanning [bold]{len(regions)}[/bold] regions:[/dim] "
                + ", ".join(r for r in regions if r)
            )
            c.print()

        (
            inv_table,
            s3_result,
            ec2_result,
            rds_result,
            lambda_result,
            cur_bucket_exists,
        ) = _section_inventory(c, regions, multi_region)
        inventory_result = error_result(
            data={
                "ec2": ec2_result["data"],
                "rds": rds_result["data"],
                "s3": s3_result["data"],
                "lambda": lambda_result["data"],
            },
            errors=[
                *s3_result["errors"],
                *ec2_result["errors"],
                *rds_result["errors"],
                *lambda_result["errors"],
            ],
        )
        costs_result, cost_display_meta = _section_cost_columns(
            c, inv_table, days, account_id, regions, multi_region, render=False
        )
        anomalies_result = (
            _section_cost_anomalies(
                c,
                threshold_pct=effective_policy.cost_anomaly_threshold_pct,
                render=False,
            )
            if effective_policy.scan_enabled("cost_anomalies")
            else _skipped_result(c, "[bold dim]🚨 Cost Anomalies[/bold dim]", [])
        )
        forecast_result = _section_cost_forecast(c, render=False)
        attribution_result = _section_cost_attribution(
            c, anomalies_result, render=False
        )
        ri_sp_result = (
            _section_ri_sp_coverage(c, days, render=False)
            if effective_policy.scan_enabled("ri_sp_coverage")
            else _skipped_result(
                c, "[bold dim]📊 RI / Savings Plan Coverage[/bold dim]", {}
            )
        )
        advisor_results = _section_ri_sp_advisor(c, render=False)
        compute_optimizer_result = _section_compute_optimizer(c, render=False)
        tag_cost_result = _section_tag_cost(c, render=False)
        sec_result = (
            _section_security(
                c,
                s3_result["data"],
                rds_result["data"],
                regions,
                multi_region,
                render=False,
            )
            if effective_policy.scan_enabled("security")
            else _skipped_result(c, "[bold dim]🛡️ Security[/bold dim]", [])
        )
        iam_result = (
            _section_iam(c, render=False)
            if effective_policy.scan_enabled("iam")
            else _skipped_result(
                c, "[bold dim]🔑 IAM Over-Permissive Policies[/bold dim]", []
            )
        )
        cw_result = (
            _section_cloudwatch(c, regions, multi_region, render=False)
            if effective_policy.scan_enabled("cloudwatch")
            else _skipped_result(c, "[bold dim]📡 CloudWatch Alarm Gaps[/bold dim]", [])
        )
        cost_waste_result = (
            _section_cost_waste(c, regions, multi_region, render=False)
            if effective_policy.scan_enabled("cost_waste")
            else _skipped_result(c, "[bold dim]🗑️ Cost Waste[/bold dim]", [])
        )
        tag_result = (
            _section_tagging(
                c,
                regions,
                multi_region,
                required_tags=list(effective_policy.required_tags),
                render=False,
            )
            if effective_policy.scan_enabled("tagging")
            else _skipped_result(c, "[bold dim]🏷️ Tagging Compliance[/bold dim]", [])
        )
        sg_blast_result = _section_sg_blast_radius(
            c, sec_result, region=region, render=False
        )
        sec_findings: list[SecurityFinding] = sec_result["data"]
        cost_findings: list[CostFinding] = cost_waste_result["data"]

        section_results: dict[str, ScanResult] = {
            "inventory": inventory_result,
            "costs": costs_result,
            "cost_forecast": forecast_result,
            "cost_anomalies": anomalies_result,
            "cost_attribution": attribution_result,
            "ri_sp_coverage": ri_sp_result,
            "ri_recommendations": advisor_results["ri"],
            "sp_recommendations": advisor_results["sp"],
            "compute_optimizer": compute_optimizer_result,
            "tag_cost_coverage": tag_cost_result,
            "security_findings": sec_result,
            "sg_blast_radius": sg_blast_result,
            "iam_findings": iam_result,
            "cloudwatch_findings": cw_result,
            "cost_waste": cost_waste_result,
            "tagging_findings": tag_result,
        }
        all_errors = list(region_errors)
        degraded_sections: list[str] = []
        for section_name, section_result in section_results.items():
            all_errors.extend(section_result["errors"])
            if section_result["errors"]:
                degraded_sections.append(section_name)
        overall_result = error_result(
            data={
                "degraded_sections": degraded_sections,
                "error_count": len(all_errors),
            },
            errors=all_errors,
        )

        scanned_at = datetime.now().isoformat()
        rendered_regions = [r for r in regions if r]
        section_payloads = {
            section_name: section_result["data"]
            for section_name, section_result in section_results.items()
        }
        v1_payload: dict[str, Any] = {
            "account_id": account_id,
            "scanned_at": scanned_at,
            "regions": rendered_regions,
            **section_payloads,
        }
        v2_payload: dict[str, Any] = {
            "account_id": account_id,
            "scanned_at": scanned_at,
            "regions": rendered_regions,
            "overall": overall_result,
            **section_results,
        }

        delta_data: dict[str, Any] | None = None
        scope_key = _scan_scope_key(
            region,
            days,
            policy_scope_token=effective_policy.scope_token(explicit_region=region),
        )
        enabled_opportunity_sources: list[OpportunitySourceKind] = [
            source_kind
            for section_name, source_kind in SECTION_TO_SOURCE_KIND.items()
            if (
                (
                    section_name == "cost_anomalies"
                    and effective_policy.scan_enabled("cost_anomalies")
                )
                or (
                    section_name == "cost_waste"
                    and effective_policy.scan_enabled("cost_waste")
                )
                or (
                    section_name == "security_findings"
                    and effective_policy.scan_enabled("security")
                )
                or (
                    section_name == "iam_findings"
                    and effective_policy.scan_enabled("iam")
                )
                or (
                    section_name == "cloudwatch_findings"
                    and effective_policy.scan_enabled("cloudwatch")
                )
                or (
                    section_name == "tagging_findings"
                    and effective_policy.scan_enabled("tagging")
                )
            )
        ]
        if since_last:
            baseline_snapshot = db_manager.get_latest_scan_snapshot(
                account_id, scope_key
            )
            delta_data = _build_delta_payload(
                baseline_snapshot=baseline_snapshot,
                current_sections=section_payloads,
                scope_key=scope_key,
                overall_errors=all_errors,
            )
            v1_payload["delta"] = delta_data
            v2_payload["delta"] = error_result(data=delta_data, errors=all_errors)

        db_manager.record_scan_snapshot(
            account_id=account_id,
            scope_key=scope_key,
            data=_normalize_snapshot_payload(section_payloads),
        )
        opportunity_summary = sync_opportunities_from_scan(
            db=db_manager,
            account_id=account_id,
            scanned_at=scanned_at,
            scan_scope=scope_key,
            section_payloads=section_payloads,
            scanned_regions=regions,
            enabled_source_kinds=enabled_opportunity_sources,
        )

        if not json_mode:
            skipped_sections = [
                section_name
                for section_name, enabled in {
                    "cost_anomalies": effective_policy.scan_enabled("cost_anomalies"),
                    "ri_sp_coverage": effective_policy.scan_enabled("ri_sp_coverage"),
                    "security_findings": effective_policy.scan_enabled("security"),
                    "iam_findings": effective_policy.scan_enabled("iam"),
                    "cloudwatch_findings": effective_policy.scan_enabled("cloudwatch"),
                    "cost_waste": effective_policy.scan_enabled("cost_waste"),
                    "tagging_findings": effective_policy.scan_enabled("tagging"),
                }.items()
                if not enabled
            ]
            open_opportunity_summary = db_manager.summarize_opportunities(
                account_id=account_id,
                statuses=list(_ACTIVE_OPPORTUNITY_STATUSES),
            )
            top_opportunities = db_manager.list_opportunities(
                account_id=account_id,
                statuses=list(_ACTIVE_OPPORTUNITY_STATUSES),
                limit=5 if watch_view == "full" else 3,
            )
            db_health_status = db_manager.get_health_status()

            _render_executive_summary(
                c,
                account_id=account_id,
                scanned_at=scanned_at,
                regions=regions,
                scope_key=scope_key,
                degraded_sections=degraded_sections,
                skipped_sections=skipped_sections,
                opportunity_summary=open_opportunity_summary,
                opportunity_sync_summary=opportunity_summary,
                delta_data=delta_data,
            )
            _render_db_health_panel(c, db_health_status)
            _render_degraded_services_panel(c, section_results)
            _render_top_opportunities_panel(c, top_opportunities)

            if watch_cycle is not None and watch_view == "compact":
                _render_watch_compact_panel(
                    c,
                    degraded_sections=degraded_sections,
                    skipped_sections=skipped_sections,
                    delta_data=delta_data if since_last else None,
                    opportunity_sync_summary=opportunity_summary,
                )
            else:
                if effective_policy.scan_enabled("security"):
                    _render_security_panel(c, sec_result, multi_region=multi_region)
                    _render_sg_blast_radius_panel(c, sg_blast_result)
                else:
                    _render_skipped_panel(c, "[bold dim]🛡️ Security[/bold dim]")

                if effective_policy.scan_enabled("iam"):
                    _render_iam_panel(c, iam_result)
                else:
                    _render_skipped_panel(
                        c, "[bold dim]🔑 IAM Over-Permissive Policies[/bold dim]"
                    )

                if effective_policy.scan_enabled("cost_anomalies"):
                    _render_cost_anomalies_panel(c, anomalies_result)
                else:
                    _render_skipped_panel(c, "[bold dim]🚨 Cost Anomalies[/bold dim]")

                _render_cost_attribution_panel(c, attribution_result)

                _render_inventory_cost_columns(
                    c,
                    inv_table=inv_table,
                    costs_result=costs_result,
                    display_meta=cost_display_meta,
                    regions=regions,
                    multi_region=multi_region,
                )

                if effective_policy.scan_enabled("ri_sp_coverage"):
                    _render_ri_sp_coverage_panel(c, ri_sp_result)
                else:
                    _render_skipped_panel(
                        c, "[bold dim]📊 RI / Savings Plan Coverage[/bold dim]"
                    )

                _render_ri_sp_advisor_panel(
                    c, advisor_results["ri"], advisor_results["sp"]
                )
                _render_compute_optimizer_panel(c, compute_optimizer_result)
                _render_tag_cost_panel(c, tag_cost_result)

                if effective_policy.scan_enabled("cost_waste"):
                    _render_cost_waste_panel(
                        c, cost_waste_result, multi_region=multi_region
                    )
                else:
                    _render_skipped_panel(c, "[bold dim]🗑️ Cost Waste[/bold dim]")

                if effective_policy.scan_enabled("cloudwatch"):
                    _render_cloudwatch_panel(c, cw_result, multi_region=multi_region)
                else:
                    _render_skipped_panel(
                        c, "[bold dim]📡 CloudWatch Alarm Gaps[/bold dim]"
                    )

                if effective_policy.scan_enabled("tagging"):
                    _render_tagging_panel(c, tag_result, multi_region=multi_region)
                else:
                    _render_skipped_panel(
                        c, "[bold dim]🏷️ Tagging Compliance[/bold dim]"
                    )

                if lambda_result["data"]:
                    _section_lambda_detail(c, lambda_result["data"])
                if since_last and delta_data is not None:
                    _render_delta_panel(c, delta_data, all_errors)
                _render_opportunity_sync_summary(c, opportunity_summary)
                if interactive:
                    _section_remediation(c, sec_findings, cost_findings)
                    _section_cur_upsell(c, cur_bucket_exists, account_id)

        return {"v1": v1_payload, "v2": v2_payload}
    finally:
        if json_mode:
            logger.console = original_logger_console


def _render_multi_profile_summary_panel(
    c: Console,
    profile_results: list[dict[str, Any]],
) -> None:
    """Render a cross-account findings summary after all profiles have been scanned."""
    table = Table(
        box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1), show_edge=False
    )
    table.add_column("Profile", style="bold", no_wrap=True)
    table.add_column("Account", style="dim", no_wrap=True)
    table.add_column("Security", justify="right")
    table.add_column("IAM", justify="right")
    table.add_column("Cost Waste", justify="right")
    table.add_column("Tagging", justify="right")
    for r in profile_results:
        v1 = r.get("v1", {})
        error = r.get("error")
        if error:
            table.add_row(
                r["profile"],
                "[red]FAILED[/red]",
                "-",
                "-",
                "-",
                "-",
            )
        else:
            table.add_row(
                r["profile"],
                v1.get("account_id", "unknown"),
                str(len(v1.get("security_findings", []))),
                str(len(v1.get("iam_findings", []))),
                str(len(v1.get("cost_waste", []))),
                str(len(v1.get("tagging_findings", []))),
            )
    c.print(
        Panel(
            table,
            title="[bold cyan]Multi-Profile Summary[/bold cyan]",
            border_style="cyan",
            padding=(0, 1),
        )
    )
    c.print()


def _render_terraform_drift_panel(
    c: Console,
    drift_result: ScanResult,
    tf_directory: str,
) -> None:
    """Render IaC-managed vs shadow-infra classification for security findings."""
    if not drift_result["ok"]:
        errors = drift_result["errors"]
        msg = errors[0]["message"] if errors else "Unknown error"
        c.print(
            Panel(
                f"[yellow]{msg}[/yellow]",
                title="[bold dim]🏗️ Terraform Drift[/bold dim]",
                border_style="yellow",
                padding=(0, 1),
            )
        )
        c.print()
        return

    findings: list[dict[str, Any]] = cast(list[dict[str, Any]], drift_result["data"])
    if not findings:
        return

    iac = [f for f in findings if f.get("iac_managed")]
    shadow = [f for f in findings if f.get("shadow_infra")]

    content_parts: list[Any] = []

    if iac:
        iac_table = Table(
            box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1), show_edge=False
        )
        iac_table.add_column("Resource", style="dim", no_wrap=True)
        iac_table.add_column("Finding")
        iac_table.add_column("TF Resource", style="dim", no_wrap=True)
        for f in iac:
            tf = cast(dict[str, Any], f.get("tf_resource")) or {}
            tf_label = (
                f"{tf.get('resource_type', '?')}.{tf.get('resource_name', '?')} "
                f"({tf.get('tf_file', '?')})"
                if tf
                else "[dim]found in .tf[/dim]"
            )
            iac_table.add_row(
                str(f.get("resource_id", ""))[:40],
                str(f.get("finding", ""))[:60],
                tf_label,
            )
        content_parts.append(
            Text.from_markup("[bold green]IaC Managed — fix in .tf:[/bold green]")
        )
        content_parts.append(iac_table)

    if shadow:
        shadow_table = Table(
            box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1), show_edge=False
        )
        shadow_table.add_column("Resource", style="dim", no_wrap=True)
        shadow_table.add_column("Finding")
        shadow_table.add_column("HCL Fix", justify="center")
        for f in shadow:
            shadow_table.add_row(
                str(f.get("resource_id", ""))[:40],
                str(f.get("finding", ""))[:60],
                "✓" if f.get("hcl_fix") else "—",
            )
        content_parts.append(
            Text.from_markup(
                "[bold yellow]Shadow Infrastructure — not in .tf:[/bold yellow]"
            )
        )
        content_parts.append(shadow_table)

    if not content_parts:
        content_parts.append(
            Text.from_markup("[green]All findings are IaC-managed.[/green]")
        )

    c.print(
        Panel(
            Group(*content_parts),
            title=(
                f"[bold cyan]🏗️ Terraform Drift[/bold cyan]  "
                f"[dim]dir={tf_directory}  iac={len(iac)}  shadow={len(shadow)}[/dim]"
            ),
            border_style="cyan",
            padding=(0, 1),
        )
    )
    c.print()


def _run_multi_profile_analyze(
    *,
    profiles: list[str],
    days: int,
    output_mode: str,
    json_schema: str,
    since_last: bool,
    interactive: bool,
    policy: ScanPolicy | None,
) -> None:
    """Run analyze sequentially for each profile and render a cross-account summary."""
    profile_results: list[dict[str, Any]] = []
    for profile_name in profiles:
        if output_mode == "text":
            logger.console.print(
                Rule(f" profile: {profile_name} ", style="cyan", align="center")
            )
        try:
            with profile_context(profile_name):
                payloads = _run_analyze_cycle(
                    days=days,
                    region=None,
                    output_mode=output_mode,
                    interactive=interactive,
                    since_last=since_last,
                    policy=policy,
                )
            profile_results.append({"profile": profile_name, **payloads})
        except Exception as exc:
            logger.error(f"Profile '{profile_name}' scan failed: {exc}")
            profile_results.append({"profile": profile_name, "error": str(exc)})

    if output_mode == "json":
        schema = json_schema
        print(
            json.dumps(
                {
                    "profiles": [
                        {
                            "profile": r["profile"],
                            **(
                                {"data": r[schema]}
                                if schema in r
                                else {"error": r.get("error")}
                            ),
                        }
                        for r in profile_results
                    ]
                },
                default=str,
                indent=2,
            )
        )
    else:
        _render_multi_profile_summary_panel(logger.console, profile_results)


@app.command()
def analyze(
    days: int = typer.Option(
        14, "--days", "-d", help="Days of cost history to analyze"
    ),
    region: str | None = typer.Option(
        None,
        "--region",
        "-r",
        help="Scan a single region (default: all enabled regions)",
    ),
    output: str = typer.Option(
        "text",
        "--output",
        "-o",
        help="Output format: text (default), json, or sarif",
    ),
    json_schema: str = typer.Option(
        "v1",
        "--json-schema",
        help="JSON schema version for --output json: v1 (legacy payloads) or v2 (typed envelopes).",
    ),
    since_last: bool = typer.Option(
        False,
        "--since-last/--no-since-last",
        help="Compare current scan against the previous snapshot in the same scope.",
    ),
    config: Path | None = typer.Option(  # noqa: B008
        None,
        "--config",
        help="Path to a TOML policy file for analyze/watch behavior.",
    ),
    interactive: bool = typer.Option(
        False,
        "--interactive/--no-interactive",
        help="Enable interactive remediation and CUR deployment prompts (default: disabled).",
    ),
    profiles: str | None = typer.Option(
        None,
        "--profiles",
        help="Comma-separated AWS profile names to scan (e.g. dev,staging,prod). Cannot be combined with --region.",
    ),
    terraform_dir: str | None = typer.Option(
        None,
        "--terraform-dir",
        help="Path to a Terraform directory. Classifies findings as IaC-managed or shadow infra.",
    ),
) -> None:
    """Retrieve read-only state (inventory, cost, security) and render a dashboard."""
    if profiles is not None and region is not None:
        raise typer.BadParameter(
            "--profiles and --region cannot be used together. "
            "Use --profiles to scan multiple accounts, or --region to target one region."
        )
    if profiles is not None:
        profile_list = _parse_profiles(profiles)
        if not profile_list:
            raise typer.BadParameter(
                "--profiles requires at least one non-empty profile name."
            )
        output_mode, schema = _validate_output_options(output, json_schema)
        policy = _load_scan_policy(config)
        _run_multi_profile_analyze(
            profiles=profile_list,
            days=days,
            output_mode=output_mode,
            json_schema=schema,
            since_last=since_last,
            interactive=interactive,
            policy=policy,
        )
        return
    _run_analyze_command(
        days=days,
        region=region,
        output=output,
        json_schema=json_schema,
        since_last=since_last,
        config=config,
        interactive=interactive,
        terraform_dir=terraform_dir,
    )


def _run_analyze_command(
    *,
    days: int,
    region: str | None,
    output: str,
    json_schema: str,
    since_last: bool,
    config: Path | None,
    interactive: bool,
    terraform_dir: str | None = None,
) -> None:
    """Run the analyze command through the shared validation and execution path."""
    output_mode, schema = _validate_output_options(output, json_schema)
    try:
        policy = _load_scan_policy(config)
        payloads = _run_analyze_cycle(
            days=days,
            region=region,
            output_mode=output_mode,
            interactive=interactive,
            since_last=since_last,
            policy=policy,
        )
        drift_result: ScanResult | None = None
        if terraform_dir:
            security_findings = cast(
                list[dict[str, Any]], payloads["v1"].get("security_findings", [])
            )
            drift_result = classify_findings_by_iac(
                security_findings, terraform_dir, source_kind="security"
            )
            if output_mode == "text":
                _render_terraform_drift_panel(
                    logger.console, drift_result, terraform_dir
                )
        if output_mode == "json":
            out = dict(payloads[schema])
            if drift_result is not None:
                out["terraform_drift"] = (
                    drift_result["data"] if schema == "v1" else drift_result
                )
            print(json.dumps(out, indent=2, default=str))
        elif output_mode == "sarif":
            account_id = payloads["v1"].get("account_id", "unknown")
            sarif_doc = _build_sarif_output(payloads, str(account_id))
            print(json.dumps(sarif_doc, indent=2, default=str))
    except Exception as exc:
        log_path = (
            logger.record_exception("Analyze command failed", exc)
            if output_mode in {"json", "sarif"}
            else logger.exception("Analyze command failed", exc)
        )
        if output_mode in {"json", "sarif"}:
            print(
                json.dumps(
                    {
                        "event": "error",
                        "message": str(exc),
                        "log_path": log_path,
                    },
                    default=str,
                    separators=(",", ":"),
                )
            )
        raise typer.Exit(code=1) from exc


@app.command()
def watch(
    interval_hours: float = typer.Option(
        4.0,
        "--interval-hours",
        help="Hours between scan cycles.",
    ),
    days: int = typer.Option(
        14, "--days", "-d", help="Days of cost history to analyze"
    ),
    region: str | None = typer.Option(
        None,
        "--region",
        "-r",
        help="Scan a single region (default: all enabled regions)",
    ),
    output: str = typer.Option(
        "text",
        "--output",
        "-o",
        help="Output format: text (default) or json",
    ),
    json_schema: str = typer.Option(
        "v1",
        "--json-schema",
        help="JSON schema version for --output json: v1 (legacy payloads) or v2 (typed envelopes).",
    ),
    config: Path | None = typer.Option(  # noqa: B008
        None,
        "--config",
        help="Path to a TOML policy file for analyze/watch behavior.",
    ),
    view: str = typer.Option(
        "compact",
        "--view",
        help="Text rendering mode for watch: compact (default) or full.",
    ),
    notify_webhook: str | None = typer.Option(
        None,
        "--notify-webhook",
        envvar="LIGHTHOUSE_NOTIFY_WEBHOOK",
        help="Webhook URL to POST alerts when new HIGH/CRITICAL findings are detected.",
    ),
) -> None:
    """Continuously run non-interactive analyze cycles and emit deltas."""
    if interval_hours <= 0:
        raise typer.BadParameter("--interval-hours must be greater than zero")
    output_mode, schema = _validate_output_options(output, json_schema)
    watch_view = _validate_watch_view(view)
    policy = _load_scan_policy(config)
    cycle = 0
    try:
        while True:
            cycle += 1
            try:
                payloads = _run_analyze_cycle(
                    days=days,
                    region=region,
                    output_mode=output_mode,
                    interactive=False,
                    since_last=True,
                    policy=policy,
                    watch_cycle=cycle,
                    watch_view=watch_view if output_mode == "text" else "full",
                )
                if output_mode == "json":
                    print(
                        json.dumps(payloads[schema], default=str, separators=(",", ":"))
                    )
                else:
                    logger.console.print(
                        f"[dim]Next scan in {interval_hours:g}h. Press Ctrl+C to stop.[/dim]"
                    )
                if notify_webhook:
                    delta_data = payloads["v1"].get("delta")
                    if delta_data and should_alert(delta_data):
                        sections = delta_data.get("sections", {})
                        alert = build_alert_payload(
                            account_id=str(payloads["v1"].get("account_id", "unknown")),
                            new_security=sections.get("security_findings", {}).get(
                                "new", []
                            ),
                            new_iam=sections.get("iam_findings", {}).get("new", []),
                            new_cost_waste=sections.get("cost_waste", {}).get(
                                "new", []
                            ),
                        )
                        sent = send_webhook(notify_webhook, alert)
                        if output_mode == "text":
                            status = "sent" if sent else "failed"
                            logger.console.print(
                                f"[dim]Webhook notification {status}.[/dim]"
                            )
            except Exception as e:
                log_path = (
                    logger.record_exception(f"Watch cycle {cycle} failed", e)
                    if output_mode == "json"
                    else logger.exception(f"Watch cycle {cycle} failed", e)
                )
                if output_mode == "json":
                    print(
                        json.dumps(
                            {
                                "event": "error",
                                "cycle": cycle,
                                "scanned_at": datetime.now().isoformat(),
                                "message": str(e),
                                "log_path": log_path,
                            },
                            default=str,
                            separators=(",", ":"),
                        )
                    )
            time.sleep(interval_hours * 3600)
    except KeyboardInterrupt:
        if output_mode != "json":
            logger.console.print("\n[dim]Watch stopped.[/dim]")


# ─────────────────────────────────────────────────────────────────────────────
# shell command
# ─────────────────────────────────────────────────────────────────────────────
def _new_shell_config() -> dict[str, dict[str, str]]:
    return {
        "configurable": {"thread_id": datetime.now().strftime("shell-%Y%m%d%H%M%S%f")}
    }


def _render_shell_help(c: Console) -> None:
    help_table = Table(
        box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1), show_edge=False
    )
    help_table.add_column("Command", style="bold cyan", no_wrap=True)
    help_table.add_column("What It Does")
    help_table.add_row("/help", "Show shell commands and starter prompts.")
    help_table.add_row(
        "/status", "Show latest scan activity and open opportunity counts."
    )
    help_table.add_row("/opps", "List the top unresolved opportunities.")
    help_table.add_row(
        "/plan", "Build a local remediation plan from open opportunities."
    )
    help_table.add_row("/logs", "Show recent local aws-lighthouse log entries.")
    help_table.add_row(
        "/analyze", "Run the local analyze command directly (supports CLI flags)."
    )
    help_table.add_row("/clear", "Clear shell conversation memory and start fresh.")
    help_table.add_row("/exit", "Exit the shell.")
    c.print(
        Panel(
            help_table,
            title="[bold cyan]Quick Actions[/bold cyan]",
            border_style="cyan",
            padding=(0, 1),
        )
    )
    c.print()


def _shell_opportunity_account_id(
    latest_scan: dict[str, Any] | None = None,
) -> str | None:
    latest_scan = latest_scan or db_manager.get_latest_scan_activity()
    if latest_scan is None:
        return None
    account_id = latest_scan.get("account_id")
    return account_id if isinstance(account_id, str) and account_id else None


def _render_shell_status(c: Console) -> None:
    latest_scan = db_manager.get_latest_scan_activity()
    account_id = _shell_opportunity_account_id(latest_scan)
    health_status = db_manager.get_health_status()
    summary = db_manager.summarize_opportunities(
        account_id=account_id, statuses=list(_ACTIVE_OPPORTUNITY_STATUSES)
    )
    status_table = Table(
        box=box.SIMPLE_HEAD, show_header=False, padding=(0, 1), show_edge=False
    )
    status_table.add_column("Label", style="dim", no_wrap=True)
    status_table.add_column("Value")
    status_table.add_row(
        "Last Scan",
        latest_scan["recorded_at"] if latest_scan else "No scans recorded yet",
    )
    status_table.add_row(
        "Account",
        latest_scan["account_id"] if latest_scan else "Unknown",
    )
    status_table.add_row(
        "Scope",
        latest_scan["scope_key"] if latest_scan else "Unknown",
    )
    issues = cast(list[dict[str, str]], health_status.get("issues", []))
    status_table.add_row(
        "Local State",
        (
            "[green]Healthy[/green]"
            if not issues
            else "[yellow]Degraded[/yellow] · "
            + ", ".join(
                _DB_HEALTH_LABELS.get(
                    issue.get("operation", ""),
                    issue.get("operation", "").replace("_", " ").title(),
                )
                for issue in issues[:3]
            )
            + ("..." if len(issues) > 3 else "")
        ),
    )
    status_table.add_row(
        "Open Opportunities",
        (
            f"{summary['total']} total · "
            f"{_format_counts_for_summary(cast(dict[str, int], summary['by_severity']), empty='none')}"
        ),
    )
    status_table.add_row(
        "Top Sources",
        _format_counts_for_summary(
            cast(dict[str, int], summary["by_source"]), empty="none"
        ),
    )
    c.print(
        Panel(
            status_table,
            title="[bold cyan]Shell Status[/bold cyan]",
            border_style="cyan",
            padding=(0, 1),
        )
    )
    c.print()


def _render_shell_opportunities(c: Console, *, limit: int = 5) -> None:
    opportunities = db_manager.list_opportunities(
        account_id=_shell_opportunity_account_id(),
        statuses=list(_ACTIVE_OPPORTUNITY_STATUSES),
        limit=limit,
    )
    _render_top_opportunities_panel(c, opportunities)


def _render_shell_plan(c: Console, *, limit: int = 10) -> None:
    opportunities = db_manager.list_opportunities(
        account_id=_shell_opportunity_account_id(),
        statuses=list(_ACTIVE_OPPORTUNITY_STATUSES),
        limit=limit,
    )
    plan = build_opportunity_plan(opportunities, limit=limit)
    groups = cast(list[dict[str, Any]], plan["groups"])
    if not groups:
        c.print(
            Panel(
                "[green]No open opportunities to plan against.[/green]",
                title="[bold green]Opportunity Plan[/bold green]",
                border_style="green",
                padding=(0, 1),
            )
        )
        c.print()
        return

    plan_table = Table(
        box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1), show_edge=False
    )
    plan_table.add_column("Source", style="dim", no_wrap=True)
    plan_table.add_column("Count", justify="right", no_wrap=True)
    plan_table.add_column("Highest", no_wrap=True)
    plan_table.add_column("Suggested Action")
    for group in groups:
        actions = cast(list[str], group["recommended_actions"])
        highest = group.get("highest_severity")
        highest_cell: str | Text
        highest_cell = _severity_text(highest) if highest else Text("—", style="dim")
        plan_table.add_row(
            str(group["source_kind"]),
            str(group["count"]),
            highest_cell,
            actions[0] if actions else "",
        )
    c.print(
        Panel(
            plan_table,
            title="[bold cyan]Opportunity Plan[/bold cyan]",
            border_style="cyan",
            padding=(0, 1),
        )
    )
    c.print()


def _render_shell_logs(c: Console, *, lines: int = 80) -> None:
    c.print(
        Panel(
            logger.tail_log(lines),
            title=(
                "[bold cyan]Recent Logs[/bold cyan]  "
                f"[dim]{logger.get_log_path()}[/dim]"
            ),
            border_style="cyan",
            padding=(0, 1),
        )
    )
    c.print()


def _translate_shell_command(user_input: str) -> tuple[str, str | None]:
    normalized = user_input.strip().lower()
    if normalized == "/help":
        return "help", None
    if normalized == "/status":
        return "status", None
    if normalized == "/opps":
        return "opps", None
    if normalized == "/plan":
        return "plan", None
    if normalized == "/logs":
        return "logs", None
    if normalized == "/clear":
        return "clear", None
    if normalized == "/exit":
        return "exit", None
    if normalized == "/analyze" or normalized.startswith("/analyze "):
        return "analyze", user_input[1:].strip()
    if normalized == "analyze" or normalized.startswith("analyze "):
        return "analyze", user_input.strip()
    return "agent", user_input


def _run_shell_analyze(c: Console, command_text: str) -> None:  # noqa: S105
    """Parse and run analyze inside the shell without using the LLM path."""
    try:
        argv = shlex.split(command_text)
    except ValueError as exc:
        logger.error(f"Invalid analyze command syntax: {exc}")
        return

    if not argv or argv[0] != "analyze":
        logger.error("Internal shell analyze routing error.")
        return

    args = argv[1:]
    days = 14
    region: str | None = None
    output = "text"
    json_schema = "v1"
    since_last = False
    config: Path | None = None
    interactive = False
    profiles: str | None = None
    terraform_dir: str | None = None
    value_flags = {
        "--days": "days",
        "-d": "days",
        "--region": "region",
        "-r": "region",
        "--output": "output",
        "-o": "output",
        "--json-schema": "json_schema",
        "--config": "config",
        "--profiles": "profiles",
        "--terraform-dir": "terraform_dir",
    }
    boolean_flags = {
        "--since-last": ("since_last", True),
        "--no-since-last": ("since_last", False),
        "--interactive": ("interactive", True),
        "--no-interactive": ("interactive", False),
    }

    idx = 0
    while idx < len(args):
        arg_token = args[idx]
        if arg_token in value_flags:
            idx += 1
            option_name = value_flags[arg_token]
            if idx >= len(args):
                logger.error(f"Missing value for {arg_token}")
                return
            option_value = args[idx]
            if option_name == "days":
                try:
                    days = int(option_value)
                except ValueError:
                    logger.error(f"Invalid --days value: {option_value}")
                    return
            elif option_name == "region":
                region = option_value
            elif option_name == "output":
                output = option_value
            elif option_name == "json_schema":
                json_schema = option_value
            elif option_name == "config":
                config = Path(option_value)
            elif option_name == "profiles":
                profiles = option_value
            elif option_name == "terraform_dir":
                terraform_dir = option_value
        elif arg_token in boolean_flags:
            bool_option_name, bool_option_value = boolean_flags[arg_token]
            if bool_option_name == "since_last":
                since_last = bool_option_value
            elif bool_option_name == "interactive":
                interactive = bool_option_value
        else:
            logger.error(f"Unknown analyze option: {arg_token}")
            return
        idx += 1

    if profiles is not None:
        profile_list = _parse_profiles(profiles)
        if profile_list:
            output_mode_val, schema_val = _validate_output_options(output, json_schema)
            policy_val = _load_scan_policy(config)
            _run_multi_profile_analyze(
                profiles=profile_list,
                days=days,
                output_mode=output_mode_val,
                json_schema=schema_val,
                since_last=since_last,
                interactive=interactive,
                policy=policy_val,
            )
            return

    _run_analyze_command(
        days=days,
        region=region,
        output=output,
        json_schema=json_schema,
        since_last=since_last,
        config=config,
        interactive=interactive,
        terraform_dir=terraform_dir,
    )


def _render_ollama_alert(c: Console, runtime_status: Mapping[str, Any]) -> None:
    reason = str(runtime_status["reason"])
    host = str(runtime_status["host"])
    model = str(runtime_status["model"])
    detail = str(runtime_status["detail"])
    if reason == "model_missing":
        title = "[bold yellow]Ollama Model Missing[/bold yellow]"
        border_style = "yellow"
        summary = "[yellow]Ollama is reachable, but the required model is not installed.[/yellow]"
    else:
        title = "[bold red]Ollama Unavailable[/bold red]"
        border_style = "red"
        summary = "[red]The local Ollama runtime is unavailable, so agent actions cannot run.[/red]"
    c.print(
        Panel(
            (
                f"{summary}\n\n"
                f"[dim]Host:[/dim] {host}\n"
                f"[dim]Model:[/dim] {model}\n"
                f"[dim]Detail:[/dim] {detail}\n\n"
                "[dim]Next steps:[/dim]\n"
                "Start Ollama and keep it running.\n"
                f"Run `ollama pull {model}` if the model is missing.\n\n"
                "[dim]Local shell commands still work:[/dim] /help, /status, /opps, /plan, /logs"
            ),
            title=title,
            border_style=border_style,
            padding=(0, 1),
        )
    )
    c.print()


@app.command()
def logs(
    lines: int = typer.Option(
        80,
        "--lines",
        min=1,
        help="Number of recent log lines to show.",
    ),
) -> None:
    """Show recent aws-lighthouse log entries."""
    _render_shell_logs(logger.console, lines=lines)


@app.command()
def shell() -> None:
    """Start the interactive AI agent shell."""
    from langchain_core.messages import HumanMessage, SystemMessage

    from .agent import check_ollama_runtime, create_agent_graph

    c = logger.console

    # ── Welcome banner ───────────────────────────────────────────────────────
    c.print()
    c.print(
        Align.center(
            Panel(
                "🔦  [bold cyan]AWS LIGHTHOUSE[/bold cyan]\n"
                "[dim]FinOps · Security · Infrastructure[/dim]\n"
                "[dim]Type a request or use /help, /status, /opps, /plan, /logs, /analyze.[/dim]\n"
                "[dim]Examples: 'analyze --since-last', 'scan all my regions', 'show top risks'[/dim]",
                border_style="cyan",
                padding=(0, 2),
                expand=False,
            )
        )
    )
    c.print()

    system_prompt = SystemMessage(
        content=(
            "You are AWS Lighthouse, a secure Cloud Infrastructure Agent running locally "
            "on the user's machine with their full AWS credentials loaded.\n"
            "You MUST execute live AWS operations yourself using tools — never ask the user "
            "to run commands manually.\n"
            "For questions about what changed, what is new, what should be fixed first, "
            "top risks, or requests for a remediation plan, consult the local opportunities "
            "database before running fresh AWS scans.\n"
            "Use local opportunity tools freely for triage because they only mutate local "
            "metadata, not AWS resources.\n"
            "Before calling any tool, output a concise explanation of what you are about to "
            "do and why. This is shown to the user before they approve.\n"
            "Do not invent a schema_version argument. The only valid schema values are "
            "'v1' and 'v2', passed as the 'schema' argument when the user explicitly asks "
            "for v2 output; otherwise rely on tool defaults.\n"
            "When the user asks for an analysis or inventory of their AWS environment, "
            "first call tool_get_enabled_regions to discover all active regions, then run "
            "the relevant inventory and scan tools for each region to give complete coverage."
        )
    )
    config = _new_shell_config()
    first_turn = True
    graph: Any | None = None

    startup_runtime = check_ollama_runtime()
    if startup_runtime["ok"]:
        try:
            with c.status("[cyan]🤖  Initializing agent...[/cyan]", spinner="dots"):
                graph = create_agent_graph()
        except Exception as e:
            logger.exception("Failed to initialize agent", e)
    else:
        _render_ollama_alert(c, startup_runtime)

    c.print(Rule("[dim cyan]  ready  [/dim cyan]", style="dim cyan"))
    _render_shell_help(c)

    # ── REPL loop ────────────────────────────────────────────────────────────
    while True:
        try:
            c.print()
            user_input = Prompt.ask("[bold cyan]  you[/bold cyan]")
            normalized_input = user_input.strip().lower()
            if normalized_input in ("exit", "quit"):
                c.print("\n[dim]  👋 Goodbye.[/dim]\n")
                break
            if not normalized_input:
                continue

            action, translated_input = _translate_shell_command(user_input)
            if action == "exit":
                c.print("\n[dim]  👋 Goodbye.[/dim]\n")
                break
            if action == "help":
                _render_shell_help(c)
                continue
            if action == "status":
                _render_shell_status(c)
                continue
            if action == "opps":
                _render_shell_opportunities(c)
                continue
            if action == "plan":
                _render_shell_plan(c)
                continue
            if action == "logs":
                _render_shell_logs(c)
                continue
            if action == "analyze":
                _run_shell_analyze(c, translated_input or "analyze")
                continue
            if action == "clear":
                config = _new_shell_config()
                first_turn = True
                c.print("\n[dim]  Conversation memory cleared.[/dim]")
                continue

            runtime_status = check_ollama_runtime()
            if not runtime_status["ok"]:
                _render_ollama_alert(c, runtime_status)
                continue
            if graph is None:
                try:
                    with c.status(
                        "[cyan]🤖  Initializing agent...[/cyan]", spinner="dots"
                    ):
                        graph = create_agent_graph()
                except Exception as e:
                    logger.exception("Failed to initialize agent", e)
                    continue

            prompt_text = translated_input or user_input
            messages = (
                [system_prompt, HumanMessage(content=prompt_text)]
                if first_turn
                else [HumanMessage(content=prompt_text)]
            )
            first_turn = False

            # Stream agent events
            try:
                c.print("\n[dim]  phase: reasoning[/dim]")
                for event in graph.stream({"messages": messages}, config=config):
                    if "agent" in event:
                        msg = event["agent"]["messages"][-1]
                        if msg.content:
                            c.print()
                            c.print(
                                Panel(
                                    Markdown(msg.content),
                                    title="[bold cyan]Reasoning[/bold cyan]",
                                    border_style="cyan",
                                    padding=(0, 2),
                                )
                            )
                            if msg.tool_calls:
                                c.print("\n[dim]  phase: awaiting approval[/dim]")

                    elif "tools" in event:
                        msg = event["tools"]["messages"][-1]
                        content_preview = str(msg.content)[:120].replace("\n", " ")
                        c.print("\n[dim]  phase: running[/dim]")
                        c.print(
                            Panel(
                                f"[dim]{content_preview}{'...' if len(str(msg.content)) > 120 else ''}[/dim]",
                                title=f"[dim]Result — {msg.name if hasattr(msg, 'name') and msg.name else 'tool'}[/dim]",
                                border_style="dim",
                                padding=(0, 2),
                            )
                        )
                        c.print("\n[dim]  phase: reasoning[/dim]")
            except Exception as e:
                runtime_status = check_ollama_runtime()
                if not runtime_status["ok"]:
                    _render_ollama_alert(c, runtime_status)
                    continue
                logger.exception("Shell agent turn failed", e)
                c.print(
                    f"[dim]Use /logs to inspect the latest traceback in {logger.get_log_path()}[/dim]"
                )

        except KeyboardInterrupt:
            c.print("\n[dim]  👋 Goodbye.[/dim]\n")
            break
        except Exception as e:
            logger.exception("Shell loop failed", e)
            c.print(
                f"[dim]Use /logs to inspect the latest traceback in {logger.get_log_path()}[/dim]"
            )


if __name__ == "__main__":
    app()
