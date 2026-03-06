import io
import json
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Any, cast

import typer
from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from .auth import get_aws_session
from .db import db_manager
from .logger import logger
from .opportunities import SECTION_TO_SOURCE_KIND, sync_opportunities_from_scan
from .policy import PolicyConfigError, ScanPolicy, load_policy_config
from .scan_contract import error_result, merge_list_results
from .tools.cloudwatch_scan import detect_cloudwatch_gaps
from .tools.cost import get_monthly_cost_summary
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
from .tools.ri_sp_coverage import get_ri_sp_coverage
from .tools.security_scan import run_security_scan
from .tools.tagging import check_tagging_compliance
from .types import (
    CostFinding,
    OpportunitySourceKind,
    ScanError,
    ScanResult,
    SecurityFinding,
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


def _skipped_result(c: Console, title: str, data: Any) -> ScanResult:
    _render_skipped_panel(c, title)
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
) -> ScanResult:
    """Fetch costs, build trend, and render inventory + cost side-by-side."""
    with c.status(f"[cyan]💰  Fetching costs ({days}d)...[/cyan]", spinner="dots"):
        costs_result = get_monthly_cost_summary(days=days)
    costs = costs_result["data"]

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
                    title=f"[bold yellow]💰 Cost[/bold yellow]  [dim]{period_label}[/dim]{trend_suffix}",
                    border_style="yellow",
                    padding=(0, 1),
                ),
            ]
        )
    )
    c.print()
    return costs_result


def _section_cost_anomalies(c: Console, threshold_pct: float = 50.0) -> ScanResult:
    """Detect and render cost anomaly panel."""
    with c.status("[cyan]🚨  Detecting cost anomalies...[/cyan]", spinner="dots"):
        anomalies_result = detect_cost_anomalies(threshold_pct=threshold_pct)
    anomalies = anomalies_result["data"]

    if anomalies:
        anomaly_table = Table(
            box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1), show_edge=False
        )
        anomaly_table.add_column("Service", style="cyan")
        anomaly_table.add_column("Baseline 7d", justify="right", style="dim")
        anomaly_table.add_column("Recent 7d", justify="right")
        anomaly_table.add_column("Change", justify="right")
        for a in anomalies:
            anomaly_table.add_row(
                a["service"],
                f"${a['baseline_7d']:,.2f}",
                f"[bold yellow]${a['recent_7d']:,.2f}[/bold yellow]",
                f"[bold red]▲ {a['pct_change']:+.1f}%[/bold red]",
            )
        c.print(
            Panel(
                anomaly_table,
                title=f"[bold red]🚨 Cost Anomalies[/bold red]  [dim]{len(anomalies)} spike{'s' if len(anomalies) != 1 else ''} vs prior 7d[/dim]",
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
    return anomalies_result


def _section_ri_sp_coverage(c: Console, days: int) -> ScanResult:
    """Fetch and render RI / Savings Plan coverage panel."""
    with c.status(
        "[cyan]📊  Checking RI / Savings Plan coverage...[/cyan]", spinner="dots"
    ):
        ri_sp_result = get_ri_sp_coverage(days=days)
    ri_sp = ri_sp_result["data"]

    ri_cov = ri_sp.get("ri_coverage_pct")
    ri_util = ri_sp.get("ri_utilization_pct")
    sp_cov = ri_sp.get("sp_coverage_pct")
    sp_util = ri_sp.get("sp_utilization_pct")
    has_any = any(v and v > 0 for v in [ri_cov, ri_util, sp_cov, sp_util])

    ri_sp_table = Table(
        box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1), show_edge=False
    )
    ri_sp_table.add_column("Commitment", style="dim", no_wrap=True)
    ri_sp_table.add_column("Coverage", justify="right", no_wrap=True)
    ri_sp_table.add_column("Utilization", justify="right", no_wrap=True)
    ri_sp_table.add_column("Uncovered Spend", justify="right", no_wrap=True)
    ri_sp_table.add_column("Idle Cost", justify="right", no_wrap=True)

    ri_sp_table.add_row(
        "Reserved Instances",
        _pct_style(ri_cov),
        _pct_style(ri_util),
        _dollar(ri_sp.get("ri_on_demand_cost")),
        _dollar(ri_sp.get("ri_unused_cost")),
    )
    ri_sp_table.add_row(
        "Savings Plans",
        _pct_style(sp_cov),
        _pct_style(sp_util),
        _dollar(ri_sp.get("sp_on_demand_cost")),
        _dollar(ri_sp.get("sp_unused_commitment")),
    )

    if has_any:
        ri_sp_border = "yellow"
        ri_sp_title = "[bold yellow]📊 RI / Savings Plan Coverage[/bold yellow]"
    else:
        ri_sp_border = "dim"
        ri_sp_title = "[bold dim]📊 RI / Savings Plan Coverage[/bold dim]  [dim]no commitments detected[/dim]"

    c.print(
        Panel(
            ri_sp_table,
            title=f"{ri_sp_title}  [dim]{ri_sp.get('period', '')}[/dim]",
            border_style=ri_sp_border,
            padding=(0, 1),
        )
    )
    c.print()
    return ri_sp_result


def _section_security(
    c: Console,
    s3s: list,
    rdss: list,
    regions: list[str | None],
    multi_region: bool,
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
                if "region" not in f:
                    f["region"] = reg
        return _sec

    region_args = [(reg, i == 0) for i, reg in enumerate(regions)]
    with c.status("[cyan]🛡️   Running security checks...[/cyan]", spinner="dots"):
        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
            for result in pool.map(_sec_region, region_args):
                sec_results.append(result)
    sec_result = merge_list_results(sec_results)
    sec_findings: list[SecurityFinding] = sec_result["data"]

    sec_count = len(sec_findings)
    if sec_count:
        sec_table = Table(
            box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1), show_edge=False
        )
        sec_table.add_column("Severity", no_wrap=True)
        if multi_region:
            sec_table.add_column("Region", style="dim", no_wrap=True)
        sec_table.add_column("Resource", style="cyan", no_wrap=True)
        sec_table.add_column("Finding")
        for f in sec_findings:
            row: list[str | Text] = [_severity_text(f["severity"])]
            if multi_region:
                row.append(f.get("region", "global"))
            row += [f["resource"], f["finding"]]
            sec_table.add_row(*row)
        c.print(
            Panel(
                sec_table,
                title=(
                    f"[bold red]🛡️  Security[/bold red]  [dim]{sec_count} finding{'s' if sec_count != 1 else ''}[/dim]"
                    + ("  [yellow]degraded[/yellow]" if sec_result["errors"] else "")
                ),
                border_style="red",
                padding=(0, 1),
            )
        )
    elif sec_result["errors"]:
        c.print(
            Panel(
                "[yellow]⚠  Security scan is degraded due to API errors. Findings may be incomplete.[/yellow]",
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
    return sec_result


def _section_iam(c: Console) -> ScanResult:
    """Scan for over-permissive IAM policies and render findings panel."""
    with c.status("[cyan]🔑  Scanning IAM policies...[/cyan]", spinner="dots"):
        iam_result = cast(ScanResult, detect_overpermissive_iam())
    iam_findings = iam_result["data"]

    iam_count = len(iam_findings)
    if iam_count:
        iam_table = Table(
            box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1), show_edge=False
        )
        iam_table.add_column("Severity", no_wrap=True)
        iam_table.add_column("Principal", style="cyan", no_wrap=True)
        iam_table.add_column("Type", style="dim", no_wrap=True)
        iam_table.add_column("Policy", style="dim", no_wrap=True)
        iam_table.add_column("Reason")
        for f in iam_findings:
            principal = f"{f['principal_type']}/{f['principal_name']}"
            iam_table.add_row(
                _severity_text(f["severity"]),
                principal,
                f["policy_type"],
                f["policy_name"],
                f["reason"],
            )
        c.print(
            Panel(
                iam_table,
                title=f"[bold red]🔑 IAM Over-Permissive Policies[/bold red]  [dim]{iam_count} finding{'s' if iam_count != 1 else ''}[/dim]",
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
    return iam_result


def _section_cloudwatch(
    c: Console,
    regions: list[str | None],
    multi_region: bool,
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
    cw_findings = cw_result["data"]

    cw_count = len(cw_findings)
    if cw_count:
        cw_table = Table(
            box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1), show_edge=False
        )
        cw_table.add_column("Type", style="dim", no_wrap=True)
        if multi_region:
            cw_table.add_column("Region", style="dim", no_wrap=True)
        cw_table.add_column("Resource", style="cyan", no_wrap=True)
        cw_table.add_column("Missing Alarms")
        for f in cw_findings:
            row: list[str] = [f["resource_type"]]
            if multi_region:
                row.append(f.get("region", ""))
            row += [
                f["resource_name"],
                "[yellow]" + ", ".join(f["missing_alarms"]) + "[/yellow]",
            ]
            cw_table.add_row(*row)
        c.print(
            Panel(
                cw_table,
                title=f"[bold yellow]📡 CloudWatch Alarm Gaps[/bold yellow]  [dim]{cw_count} resource{'s' if cw_count != 1 else ''} unmonitored[/dim]",
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
    return cw_result


def _section_cost_waste(
    c: Console,
    regions: list[str | None],
    multi_region: bool,
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
    cost_findings: list[CostFinding] = cost_result["data"]

    waste_count = len(cost_findings)
    if waste_count:
        waste_table = Table(
            box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1), show_edge=False
        )
        if multi_region:
            waste_table.add_column("Region", style="dim", no_wrap=True)
        waste_table.add_column("Resource", style="cyan", no_wrap=True)
        waste_table.add_column("Finding")
        for f in cost_findings:
            row: list[str] = []
            if multi_region:
                row.append(f.get("region", ""))
            row += [f["resource"], f["finding"]]
            waste_table.add_row(*row)
        c.print(
            Panel(
                waste_table,
                title=f"[bold yellow]🗑️  Cost Waste[/bold yellow]  [dim]{waste_count} finding{'s' if waste_count != 1 else ''}[/dim]",
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
    return cost_result


def _section_tagging(
    c: Console,
    regions: list[str | None],
    multi_region: bool,
    required_tags: list[str] | None = None,
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
                if "region" not in f:
                    f["region"] = reg
        return cast(ScanResult, _tag)

    tag_args = [(reg, i == 0) for i, reg in enumerate(regions)]
    with c.status("[cyan]🏷️   Checking tag compliance...[/cyan]", spinner="dots"):
        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
            for result in pool.map(_tag_region, tag_args):
                tag_results.append(result)
    tag_result = merge_list_results(tag_results)
    tag_findings = tag_result["data"]

    tag_count = len(tag_findings)
    if tag_count:
        tag_table = Table(
            box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1), show_edge=False
        )
        tag_table.add_column("Type", style="dim", no_wrap=True)
        if multi_region:
            tag_table.add_column("Region", style="dim", no_wrap=True)
        tag_table.add_column("Resource", style="cyan", no_wrap=True)
        tag_table.add_column("Missing Tags")
        for f in tag_findings:
            row: list[str] = [f["resource_type"]]
            if multi_region:
                row.append(f.get("region", "global"))
            row += [
                f["resource_name"],
                "[yellow]" + ", ".join(f["missing_tags"]) + "[/yellow]",
            ]
            tag_table.add_row(*row)
        c.print(
            Panel(
                tag_table,
                title=f"[bold yellow]🏷️  Tagging Compliance[/bold yellow]  [dim]{tag_count} resource{'s' if tag_count != 1 else ''} untagged[/dim]",
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


def _section_remediation(
    c: Console,
    sec_findings: list[SecurityFinding],
    cost_findings: list[CostFinding],
) -> None:
    """Offer one-click remediation for actionable findings."""
    remediable = [f for f in sec_findings + cost_findings if f.get("remediation_type")]
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

    rem_table = Table(
        box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1), show_edge=False
    )
    rem_table.add_column("#", justify="right", style="dim", no_wrap=True)
    rem_table.add_column("Action", style="bold cyan", no_wrap=True)
    rem_table.add_column("Resource", no_wrap=True)
    for i, f in enumerate(remediable, 1):
        rem_table.add_row(str(i), f["remediation_label"], f["resource"])

    c.print(
        Panel(
            rem_table,
            title=(
                f"[bold cyan]🔧 One-Click Remediation[/bold cyan]  "
                f"[dim]{len(remediable)} fix{'es' if len(remediable) != 1 else ''} available[/dim]"
            ),
            border_style="cyan",
            padding=(0, 1),
        )
    )
    c.print()

    raw = Prompt.ask(
        "  [bold cyan]Apply fixes[/bold cyan] [dim](e.g. 1,3 — or Enter to skip)[/dim]",
        default="",
    )

    if raw.strip():
        indices = [int(x.strip()) - 1 for x in raw.split(",") if x.strip().isdigit()]
        for idx in indices:
            if 0 <= idx < len(remediable):
                f = remediable[idx]
                label = f["remediation_label"]
                resource = f["resource"]
                action = _ACTIONS.get(f["remediation_type"])
                if not action:
                    logger.error(f"Unknown remediation type: {f['remediation_type']}")
                    continue
                region = f.get("region")
                if f["remediation_type"] in _REGION_REQUIRED and not region:
                    logger.error(
                        f"Missing region for remediation {f['remediation_type']} on {resource}; skipping."
                    )
                    continue
                if typer.confirm(f"  Apply '{label}' on {resource}?", default=False):
                    with c.status(
                        f"[cyan]🔧  Applying {label}...[/cyan]", spinner="dots"
                    ):
                        ok = action(resource, region=region)
                    if ok:
                        logger.success(f"{label} applied to {resource}.")
                    else:
                        logger.error(f"Failed to apply {label} on {resource}.")
                else:
                    c.print(f"  [dim]Skipped {resource}.[/dim]")
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
# analyze command
# ─────────────────────────────────────────────────────────────────────────────
def _validate_output_options(output: str, json_schema: str) -> tuple[str, str]:
    output_mode = output.lower().strip()
    schema = json_schema.lower().strip()
    if output_mode not in {"text", "json"}:
        raise typer.BadParameter("--output must be either 'text' or 'json'")
    if schema not in {"v1", "v2"}:
        raise typer.BadParameter("--json-schema must be either 'v1' or 'v2'")
    return output_mode, schema


def _run_analyze_cycle(
    *,
    days: int,
    region: str | None,
    output_mode: str,
    interactive: bool,
    since_last: bool,
    policy: ScanPolicy | None = None,
    watch_cycle: int | None = None,
) -> dict[str, dict[str, Any]]:
    """Execute one analyze cycle and return both v1 and v2 machine payloads."""
    effective_policy = policy or ScanPolicy.default()
    json_mode = output_mode == "json"
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
        costs_result = _section_cost_columns(
            c, inv_table, days, account_id, regions, multi_region
        )
        anomalies_result = (
            _section_cost_anomalies(
                c, threshold_pct=effective_policy.cost_anomaly_threshold_pct
            )
            if effective_policy.scan_enabled("cost_anomalies")
            else _skipped_result(c, "[bold dim]🚨 Cost Anomalies[/bold dim]", [])
        )
        ri_sp_result = (
            _section_ri_sp_coverage(c, days)
            if effective_policy.scan_enabled("ri_sp_coverage")
            else _skipped_result(
                c, "[bold dim]📊 RI / Savings Plan Coverage[/bold dim]", {}
            )
        )
        sec_result = (
            _section_security(
                c, s3_result["data"], rds_result["data"], regions, multi_region
            )
            if effective_policy.scan_enabled("security")
            else _skipped_result(c, "[bold dim]🛡️ Security[/bold dim]", [])
        )
        iam_result = (
            _section_iam(c)
            if effective_policy.scan_enabled("iam")
            else _skipped_result(
                c, "[bold dim]🔑 IAM Over-Permissive Policies[/bold dim]", []
            )
        )
        cw_result = (
            _section_cloudwatch(c, regions, multi_region)
            if effective_policy.scan_enabled("cloudwatch")
            else _skipped_result(c, "[bold dim]📡 CloudWatch Alarm Gaps[/bold dim]", [])
        )
        cost_waste_result = (
            _section_cost_waste(c, regions, multi_region)
            if effective_policy.scan_enabled("cost_waste")
            else _skipped_result(c, "[bold dim]🗑️ Cost Waste[/bold dim]", [])
        )
        tag_result = (
            _section_tagging(
                c,
                regions,
                multi_region,
                required_tags=list(effective_policy.required_tags),
            )
            if effective_policy.scan_enabled("tagging")
            else _skipped_result(c, "[bold dim]🏷️ Tagging Compliance[/bold dim]", [])
        )
        sec_findings: list[SecurityFinding] = sec_result["data"]
        cost_findings: list[CostFinding] = cost_waste_result["data"]

        section_results: dict[str, ScanResult] = {
            "inventory": inventory_result,
            "costs": costs_result,
            "cost_anomalies": anomalies_result,
            "ri_sp_coverage": ri_sp_result,
            "security_findings": sec_result,
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
        help="Output format: text (default) or json",
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
) -> None:
    """Retrieve read-only state (inventory, cost, security) and render a dashboard."""
    output_mode, schema = _validate_output_options(output, json_schema)
    policy = _load_scan_policy(config)
    payloads = _run_analyze_cycle(
        days=days,
        region=region,
        output_mode=output_mode,
        interactive=interactive,
        since_last=since_last,
        policy=policy,
    )
    if output_mode == "json":
        print(json.dumps(payloads[schema], indent=2, default=str))


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
) -> None:
    """Continuously run non-interactive analyze cycles and emit deltas."""
    if interval_hours <= 0:
        raise typer.BadParameter("--interval-hours must be greater than zero")
    output_mode, schema = _validate_output_options(output, json_schema)
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
                )
                if output_mode == "json":
                    print(
                        json.dumps(payloads[schema], default=str, separators=(",", ":"))
                    )
                else:
                    logger.console.print(
                        f"[dim]Next scan in {interval_hours:g}h. Press Ctrl+C to stop.[/dim]"
                    )
            except Exception as e:
                if output_mode == "json":
                    print(
                        json.dumps(
                            {
                                "event": "error",
                                "cycle": cycle,
                                "scanned_at": datetime.now().isoformat(),
                                "message": str(e),
                            },
                            default=str,
                            separators=(",", ":"),
                        )
                    )
                else:
                    logger.error(f"Watch cycle {cycle} failed: {e}")
            time.sleep(interval_hours * 3600)
    except KeyboardInterrupt:
        if output_mode != "json":
            logger.console.print("\n[dim]Watch stopped.[/dim]")


# ─────────────────────────────────────────────────────────────────────────────
# shell command
# ─────────────────────────────────────────────────────────────────────────────
@app.command()
def shell() -> None:
    """Start the interactive AI agent shell."""
    from langchain_core.messages import HumanMessage, SystemMessage

    from .agent import create_agent_graph

    c = logger.console

    # ── Welcome banner ───────────────────────────────────────────────────────
    c.print()
    c.print(
        Align.center(
            Panel(
                "🔦  [bold cyan]AWS LIGHTHOUSE[/bold cyan]\n"
                "[dim]FinOps · Security · Infrastructure[/dim]\n"
                "[dim]Type a request or [bold]exit[/bold] to quit.[/dim]",
                border_style="cyan",
                padding=(0, 2),
                expand=False,
            )
        )
    )
    c.print()

    # ── Init agent ───────────────────────────────────────────────────────────
    try:
        with c.status("[cyan]🤖  Initializing agent...[/cyan]", spinner="dots"):
            graph = create_agent_graph()

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
                "When the user asks for an analysis or inventory of their AWS environment, "
                "first call tool_get_enabled_regions to discover all active regions, then run "
                "the relevant inventory and scan tools for each region to give complete coverage."
            )
        )
        config = {"configurable": {"thread_id": "main"}}
        first_turn = True
        c.print(Rule("[dim cyan]  ready  [/dim cyan]", style="dim cyan"))
    except Exception as e:
        logger.error(f"Failed to initialize agent: {e}")
        return

    # ── REPL loop ────────────────────────────────────────────────────────────
    while True:
        try:
            c.print()
            user_input = Prompt.ask("[bold cyan]  you[/bold cyan]")
            if user_input.strip().lower() in ("exit", "quit", ""):
                if user_input.strip().lower() in ("exit", "quit"):
                    c.print("\n[dim]  👋 Goodbye.[/dim]\n")
                    break
                continue

            messages = (
                [system_prompt, HumanMessage(content=user_input)]
                if first_turn
                else [HumanMessage(content=user_input)]
            )
            first_turn = False

            # Stream agent events
            c.print("\n[dim]  🤔 Thinking...[/dim]")
            for event in graph.stream({"messages": messages}, config=config):
                if "agent" in event:
                    msg = event["agent"]["messages"][-1]
                    if msg.content:
                        # Clear the "Thinking..." line with a blank then print response
                        c.print()
                        c.print(
                            Panel(
                                Markdown(msg.content),
                                title="[bold cyan]Lighthouse[/bold cyan]",
                                border_style="cyan",
                                padding=(0, 2),
                            )
                        )
                        # If there are tool calls coming next, show a follow-up indicator
                        if msg.tool_calls:
                            c.print("\n[dim]  ⚙️  Preparing tool...[/dim]")

                elif "tools" in event:
                    msg = event["tools"]["messages"][-1]
                    content_preview = str(msg.content)[:120].replace("\n", " ")
                    c.print(
                        Panel(
                            f"[dim]{content_preview}{'...' if len(str(msg.content)) > 120 else ''}[/dim]",
                            title=f"[dim]Tool result — {msg.name if hasattr(msg, 'name') and msg.name else 'tool'}[/dim]",
                            border_style="dim",
                            padding=(0, 2),
                        )
                    )
                    c.print("\n[dim]  🤔 Thinking...[/dim]")

        except KeyboardInterrupt:
            c.print("\n[dim]  👋 Goodbye.[/dim]\n")
            break
        except Exception as e:
            logger.error(f"Error: {e}")


if __name__ == "__main__":
    app()
