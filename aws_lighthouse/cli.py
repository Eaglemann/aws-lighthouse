import io
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

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
from .types import CostFinding, SecurityFinding

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
    """Return resource count, or '[red]Error[/red]' for explicit error payloads."""
    if lst and "error" in lst[0]:
        return "[red]Error[/red]"
    return str(len(lst))


def _pct_style(val: float | None, low: float = 60.0, high: float = 80.0) -> str:
    """Return a colored percentage string based on thresholds."""
    if val is None:
        return "[dim]N/A[/dim]"
    color = "green" if val >= high else ("yellow" if val >= low else "red")
    return f"[{color}]{val:.1f}%[/{color}]"


def _dollar(val: float | None) -> str:
    return f"${val:,.2f}" if val is not None else "[dim]N/A[/dim]"


# ─────────────────────────────────────────────────────────────────────────────
# Section functions
# ─────────────────────────────────────────────────────────────────────────────


def _section_inventory(
    c: Console,
    regions: list[str | None],
    multi_region: bool,
) -> tuple[Table, list, list, list, list, bool]:
    """Fetch inventory across all regions; return data for downstream sections."""
    s3s: list = []
    ec2s: list = []
    rdss: list = []
    lambdas: list = []

    def _inv_region(reg: str | None) -> tuple[list, list, list]:
        _ec2 = get_ec2_inventory(region=reg)
        _rds = get_rds_inventory(region=reg)
        _lmb = get_lambda_inventory(region=reg)
        if multi_region and reg is not None:
            for item in _ec2:
                item["region"] = reg
            for item in _rds:
                item["region"] = reg
            for item in _lmb:
                item["region"] = reg
        return _ec2, _rds, _lmb

    with c.status("[cyan]📦  Scanning inventory...[/cyan]", spinner="dots"):
        s3s = get_s3_inventory()
        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
            for _ec2, _rds, _lmb in pool.map(_inv_region, regions):
                ec2s.extend(_ec2)
                rdss.extend(_rds)
                lambdas.extend(_lmb)

    cur_bucket_exists = False
    if s3s and "error" not in s3s[0]:
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

    return inv_table, s3s, ec2s, rdss, lambdas, cur_bucket_exists


def _section_cost_columns(
    c: Console,
    inv_table: Table,
    days: int,
    account_id: str,
    regions: list[str | None],
    multi_region: bool,
) -> dict:
    """Fetch costs, build trend, and render inventory + cost side-by-side."""
    with c.status(f"[cyan]💰  Fetching costs ({days}d)...[/cyan]", spinner="dots"):
        costs = get_monthly_cost_summary(days=days)

    cost_table = Table(
        box=box.SIMPLE_HEAD, show_header=False, padding=(0, 1), show_edge=False
    )
    cost_table.add_column("Service", style="dim")
    cost_table.add_column("USD", justify="right")
    if "error" not in costs:
        cost_table.add_row(
            Text("Total", style="bold white"),
            Text(f"${costs['total_usd']:,.2f}", style="bold yellow"),
        )
        for svc, amt in list(costs.get("breakdown", {}).items())[:6]:
            cost_table.add_row(svc, f"${amt:,.2f}")
    else:
        cost_table.add_row("Error", costs["error"])

    prev_snapshot = db_manager.get_latest_cost_snapshot(account_id)
    if "error" not in costs:
        db_manager.record_cost_snapshot(
            account_id=account_id,
            start=costs["start"],
            end=costs["end"],
            total=costs["total_usd"],
            breakdown=costs["breakdown"],
        )

    trend_suffix = ""
    if prev_snapshot and "error" not in costs:
        prev_total = prev_snapshot["total_usd"]
        curr_total = costs["total_usd"]
        if prev_total > 0:
            pct = ((curr_total - prev_total) / prev_total) * 100
            arrow = "▲" if pct > 0 else "▼"
            color = "red" if pct > 0 else "green"
            trend_suffix = (
                f"  [{color}]{arrow} {pct:+.1f}%[/{color}] [dim]vs last scan[/dim]"
            )

    period_label = costs.get("period", "—") if "error" not in costs else "—"
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
    return costs


def _section_cost_anomalies(c: Console) -> list:
    """Detect and render cost anomaly panel."""
    with logger.capture_errors() as errors:
        with c.status("[cyan]🚨  Detecting cost anomalies...[/cyan]", spinner="dots"):
            anomalies = detect_cost_anomalies(threshold_pct=50.0)

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
    elif errors:
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
    return anomalies


def _section_ri_sp_coverage(c: Console, days: int) -> dict:
    """Fetch and render RI / Savings Plan coverage panel."""
    with c.status(
        "[cyan]📊  Checking RI / Savings Plan coverage...[/cyan]", spinner="dots"
    ):
        ri_sp = get_ri_sp_coverage(days=days)

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
    return ri_sp


def _section_security(
    c: Console,
    s3s: list,
    rdss: list,
    regions: list[str | None],
    multi_region: bool,
) -> list[SecurityFinding]:
    """Run security scan across all regions and render findings panel."""
    sec_findings: list[SecurityFinding] = []

    def _sec_region(args: tuple[str | None, bool]) -> list[SecurityFinding]:
        reg, include_global = args
        _rdss_r = [r for r in rdss if r.get("region") == reg] if multi_region else rdss
        _sec = run_security_scan(
            s3s=s3s, rdss=_rdss_r, region=reg, include_global=include_global
        )
        if multi_region and reg is not None:
            for f in _sec:
                if "region" not in f:
                    f["region"] = reg
        return _sec

    region_args = [(reg, i == 0) for i, reg in enumerate(regions)]
    with logger.capture_errors() as errors:
        with c.status("[cyan]🛡️   Running security checks...[/cyan]", spinner="dots"):
            with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
                for items in pool.map(_sec_region, region_args):
                    sec_findings.extend(items)

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
                    + ("  [yellow]degraded[/yellow]" if errors else "")
                ),
                border_style="red",
                padding=(0, 1),
            )
        )
    elif errors:
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
    return sec_findings


def _section_iam(c: Console) -> list:
    """Scan for over-permissive IAM policies and render findings panel."""
    with logger.capture_errors() as errors:
        with c.status("[cyan]🔑  Scanning IAM policies...[/cyan]", spinner="dots"):
            iam_findings = detect_overpermissive_iam()

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
    elif errors:
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
    return iam_findings


def _section_cloudwatch(
    c: Console,
    regions: list[str | None],
    multi_region: bool,
) -> list:
    """Check CloudWatch alarm coverage across all regions and render panel."""
    cw_findings: list = []

    def _cw_region(reg: str | None) -> list:
        _cw = detect_cloudwatch_gaps(region=reg)
        if multi_region and reg is not None:
            for f in _cw:
                f["region"] = reg
        return _cw

    with logger.capture_errors() as errors:
        with c.status(
            "[cyan]📡  Checking CloudWatch alarm coverage...[/cyan]", spinner="dots"
        ):
            with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
                for items in pool.map(_cw_region, regions):
                    cw_findings.extend(items)

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
    elif errors:
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
    return cw_findings


def _section_cost_waste(
    c: Console,
    regions: list[str | None],
    multi_region: bool,
) -> list[CostFinding]:
    """Scan for cost waste across all regions and render findings panel."""
    cost_findings: list[CostFinding] = []

    def _cost_region(reg: str | None) -> list[CostFinding]:
        _cost = run_cost_scan(region=reg)
        if multi_region and reg is not None:
            for f in _cost:
                f["region"] = reg
        return _cost

    with logger.capture_errors() as errors:
        with c.status("[cyan]🗑️   Scanning for cost waste...[/cyan]", spinner="dots"):
            with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
                for items in pool.map(_cost_region, regions):
                    cost_findings.extend(items)

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
    elif errors:
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
    return cost_findings


def _section_tagging(
    c: Console,
    regions: list[str | None],
    multi_region: bool,
) -> list:
    """Check tagging compliance across all regions and render panel."""
    tag_findings: list = []

    def _tag_region(args: tuple[str | None, bool]) -> list:
        reg, include_s3 = args
        _tag = check_tagging_compliance(region=reg, include_s3=include_s3)
        if multi_region and reg is not None:
            for f in _tag:
                if "region" not in f:
                    f["region"] = reg
        return _tag

    tag_args = [(reg, i == 0) for i, reg in enumerate(regions)]
    with logger.capture_errors() as errors:
        with c.status("[cyan]🏷️   Checking tag compliance...[/cyan]", spinner="dots"):
            with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
                for items in pool.map(_tag_region, tag_args):
                    tag_findings.extend(items)

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
    elif errors:
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
    return tag_findings


def _section_lambda_detail(c: Console, lambdas: list) -> None:
    """Render Lambda function detail panel if any valid functions exist."""
    valid_lambdas = [fn for fn in lambdas if "error" not in fn]
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
    interactive: bool = typer.Option(
        False,
        "--interactive/--no-interactive",
        help="Enable interactive remediation and CUR deployment prompts (default: disabled).",
    ),
) -> None:
    """Retrieve read-only state (inventory, cost, security) and render a dashboard."""
    json_mode = output == "json"
    # In JSON mode send all Rich output to a buffer so nothing leaks to stdout.
    c = Console(file=io.StringIO(), no_color=True) if json_mode else logger.console
    original_logger_console = logger.console
    if json_mode:
        logger.console = c

    try:
        # Header
        c.print()
        c.print(Rule(" 🔦  AWS LIGHTHOUSE ", style="bold cyan", align="center"))
        c.print()

        # Auth
        with c.status("[cyan]🔐  Authenticating...[/cyan]", spinner="dots"):
            session = get_aws_session()
            account_id = session.client("sts").get_caller_identity()["Account"]

        c.print(
            f"  [dim]🔐 Account[/dim]  [bold]{account_id}[/bold]  "
            f"[dim]·  📅 {datetime.now().strftime('%Y-%m-%d  %H:%M')}[/dim]"
        )
        c.print()

        # Regions
        if region:
            regions: list[str | None] = [region]
            c.print(f"  [dim]🌍 Region[/dim]  [bold]{region}[/bold]")
            c.print()
        else:
            with c.status(
                "[cyan]🌍  Detecting enabled regions...[/cyan]", spinner="dots"
            ):
                regions = list(get_enabled_regions())
            if not regions:
                regions = [None]

        multi_region = len(regions) > 1
        if multi_region:
            c.print(
                f"  [dim]🌍 Scanning [bold]{len(regions)}[/bold] regions:[/dim] "
                + ", ".join(r for r in regions if r)
            )
            c.print()

        # Sections — all section functions return their data; rendering is a side-effect
        # that goes to the devnull console when json_mode is True.
        inv_table, s3s, ec2s, rdss, lambdas, cur_bucket_exists = _section_inventory(
            c, regions, multi_region
        )
        costs = _section_cost_columns(
            c, inv_table, days, account_id, regions, multi_region
        )
        anomalies = _section_cost_anomalies(c)
        ri_sp = _section_ri_sp_coverage(c, days)
        sec_findings = _section_security(c, s3s, rdss, regions, multi_region)
        iam_findings = _section_iam(c)
        cw_findings = _section_cloudwatch(c, regions, multi_region)
        cost_findings = _section_cost_waste(c, regions, multi_region)
        tag_findings = _section_tagging(c, regions, multi_region)

        if json_mode:
            print(
                json.dumps(
                    {
                        "account_id": account_id,
                        "scanned_at": datetime.now().isoformat(),
                        "regions": [r for r in regions if r],
                        "inventory": {
                            "ec2": ec2s,
                            "rds": rdss,
                            "s3": s3s,
                            "lambda": lambdas,
                        },
                        "costs": costs,
                        "cost_anomalies": anomalies,
                        "ri_sp_coverage": ri_sp,
                        "security_findings": sec_findings,
                        "iam_findings": iam_findings,
                        "cloudwatch_findings": cw_findings,
                        "cost_waste": cost_findings,
                        "tagging_findings": tag_findings,
                    },
                    indent=2,
                    default=str,
                )
            )
            return

        _section_lambda_detail(c, lambdas)
        if interactive:
            _section_remediation(c, sec_findings, cost_findings)
            _section_cur_upsell(c, cur_bucket_exists, account_id)
    finally:
        if json_mode:
            logger.console = original_logger_console


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
