import typer
from datetime import datetime
from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from .logger import logger

app = typer.Typer(
    help="AWS Lighthouse: Terminal-first FinOps, Security, and Scaffolding Agent.",
    add_completion=False,
    invoke_without_command=True,
)


@app.callback()
def main(ctx: typer.Context):
    """AWS Lighthouse: Terminal-first FinOps, Security, and Scaffolding Agent."""
    if ctx.invoked_subcommand is None:
        shell()


# ── Severity colour map ──────────────────────────────────────────────────────
_SEV_STYLE = {"HIGH": "bold red", "MEDIUM": "bold yellow", "LOW": "bold blue"}


def _severity_text(sev: str) -> Text:
    return Text(sev, style=_SEV_STYLE.get(sev, "white"))


# ─────────────────────────────────────────────────────────────────────────────
# analyze command
# ─────────────────────────────────────────────────────────────────────────────
@app.command()
def analyze(
    days: int = typer.Option(14, "--days", "-d", help="Days of cost history to analyze"),
):
    """Retrieve read-only state (inventory, cost, security) and render a dashboard."""
    from .auth import get_aws_session
    from .db import db_manager
    from .tools.inventory import get_ec2_inventory, get_rds_inventory, get_s3_inventory
    from .tools.cost import get_monthly_cost_summary
    from .tools.security_scan import run_security_scan
    from .tools.cost_scan import run_cost_scan

    c = logger.console

    # ── Header ───────────────────────────────────────────────────────────────
    c.print()
    c.print(Rule("[bold cyan]AWS LIGHTHOUSE[/bold cyan]", style="cyan"))
    c.print()

    # ── 1. Auth ──────────────────────────────────────────────────────────────
    with c.status("[cyan]Authenticating...[/cyan]", spinner="dots"):
        session = get_aws_session()
        sts = session.client("sts")
        account_id = sts.get_caller_identity()["Account"]

    c.print(
        f"  [dim]Account[/dim]  [bold]{account_id}[/bold]  "
        f"[dim]·  Scanned[/dim]  {datetime.now().strftime('%Y-%m-%d  %H:%M')}"
    )
    c.print()

    # ── 2. Inventory ─────────────────────────────────────────────────────────
    with c.status("[cyan]Scanning resources...[/cyan]", spinner="dots"):
        ec2s = get_ec2_inventory()
        rdss = get_rds_inventory()
        s3s = get_s3_inventory()

    cur_bucket_exists = False
    if s3s and "error" not in s3s[0]:
        cur_bucket_exists = any(
            b.get("BucketName", "").startswith("cur-data-lighthouse-") for b in s3s
        )

    def _count(lst):
        return str(len(lst)) if lst and "error" not in lst[0] else "[red]Error[/red]"

    inv_table = Table(box=box.SIMPLE_HEAD, show_header=False, padding=(0, 1), show_edge=False)
    inv_table.add_column("Resource", style="dim")
    inv_table.add_column("Count", justify="right", style="bold white")
    inv_table.add_row("EC2 Instances", _count(ec2s))
    inv_table.add_row("RDS Databases", _count(rdss))
    inv_table.add_row("S3 Buckets",    _count(s3s))

    # ── 3. Costs ─────────────────────────────────────────────────────────────
    with c.status(f"[cyan]Fetching costs ({days}d)...[/cyan]", spinner="dots"):
        costs = get_monthly_cost_summary(days=days)

    cost_table = Table(box=box.SIMPLE_HEAD, show_header=False, padding=(0, 1), show_edge=False)
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

    # ── 4. Trend ─────────────────────────────────────────────────────────────
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
            trend_suffix = f"  [{color}]{arrow} {pct:+.1f}%[/{color}] [dim]vs last scan[/dim]"

    period_label = costs.get("period", "—") if "error" not in costs else "—"

    c.print(Columns([
        Panel(
            inv_table,
            title="[bold blue]Inventory[/bold blue]",
            border_style="blue",
            padding=(0, 1),
        ),
        Panel(
            cost_table,
            title=f"[bold yellow]Cost[/bold yellow]  [dim]{period_label}[/dim]{trend_suffix}",
            border_style="yellow",
            padding=(0, 1),
        ),
    ]))
    c.print()

    # ── 5. Security scan ─────────────────────────────────────────────────────
    with c.status("[cyan]Running security checks...[/cyan]", spinner="dots"):
        sec_findings = run_security_scan(s3s=s3s, rdss=rdss)

    sec_count = len(sec_findings)
    if sec_count:
        sec_table = Table(box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1), show_edge=False)
        sec_table.add_column("Severity",  no_wrap=True)
        sec_table.add_column("Resource",  style="cyan", no_wrap=True)
        sec_table.add_column("Finding")
        for f in sec_findings:
            sec_table.add_row(_severity_text(f["severity"]), f["resource"], f["finding"])
        c.print(Panel(
            sec_table,
            title=f"[bold red]Security[/bold red]  [dim]{sec_count} finding{'s' if sec_count != 1 else ''}[/dim]",
            border_style="red",
            padding=(0, 1),
        ))
    else:
        c.print(Panel(
            "[green]✓  All security checks passed.[/green]",
            title="[bold green]Security[/bold green]",
            border_style="green",
            padding=(0, 1),
        ))

    c.print()

    # ── 6. Cost waste scan ───────────────────────────────────────────────────
    with c.status("[cyan]Scanning for cost waste...[/cyan]", spinner="dots"):
        cost_findings = run_cost_scan()

    waste_count = len(cost_findings)
    if waste_count:
        waste_table = Table(box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1), show_edge=False)
        waste_table.add_column("Resource", style="cyan", no_wrap=True)
        waste_table.add_column("Finding")
        for f in cost_findings:
            waste_table.add_row(f["resource"], f["finding"])
        c.print(Panel(
            waste_table,
            title=f"[bold yellow]Cost Waste[/bold yellow]  [dim]{waste_count} finding{'s' if waste_count != 1 else ''}[/dim]",
            border_style="yellow",
            padding=(0, 1),
        ))
    else:
        c.print(Panel(
            "[green]✓  No cost waste detected.[/green]",
            title="[bold green]Cost Waste[/bold green]",
            border_style="green",
            padding=(0, 1),
        ))

    c.print()

    # ── 7. CUR upsell ────────────────────────────────────────────────────────
    if not cur_bucket_exists:
        c.print(Panel(
            "AWS Cost Explorer shows only daily service-level totals. "
            "Enable [bold]Cost & Usage Reports (CUR)[/bold] for per-resource attribution and long-term FinOps analysis.\n\n"
            "[bold cyan]Ask the agent:[/bold cyan]  [italic]'Deploy CUR Export'[/italic]",
            title="[bold yellow]⚡ Enable Deep FinOps[/bold yellow]",
            border_style="yellow",
            padding=(1, 2),
        ))

        if typer.confirm("\nDeploy the CUR CloudFormation stack now?"):
            import uuid
            cust_id  = typer.prompt("Customer resource ID (e.g. cust-abc123)")
            ext_id   = typer.prompt("External ID for trust relationship")
            s3_bucket = f"cur-data-lighthouse-{uuid.uuid4().hex[:8]}"

            from .tools.cfn_deploy import deploy_cur_template
            logger.action_start("Deploying CUR CloudFormation stack...")
            success = deploy_cur_template(
                account_id=account_id, cust_id=cust_id,
                ext_id=ext_id, s3_bucket=s3_bucket,
            )
            if success:
                logger.success("CUR deployment initiated successfully.")
            else:
                logger.error("CUR deployment failed.")


# ─────────────────────────────────────────────────────────────────────────────
# shell command
# ─────────────────────────────────────────────────────────────────────────────
@app.command()
def shell():
    """Start the interactive AI agent shell."""
    from .agent import create_agent_graph
    from langchain_core.messages import HumanMessage, SystemMessage

    c = logger.console

    # ── Welcome banner ───────────────────────────────────────────────────────
    c.print()
    c.print(Panel(
        Align.center(
            "[bold cyan]AWS LIGHTHOUSE[/bold cyan]\n"
            "[dim]FinOps  ·  Security  ·  Infrastructure[/dim]\n\n"
            "[dim]Type your request and press Enter.  [bold]exit[/bold] or Ctrl+C to quit.[/dim]"
        ),
        border_style="cyan",
        padding=(1, 4),
    ))
    c.print()

    # ── Init agent ───────────────────────────────────────────────────────────
    try:
        with c.status("[cyan]Initializing agent...[/cyan]", spinner="dots"):
            graph = create_agent_graph()

        system_prompt = SystemMessage(
            content=(
                "You are AWS Lighthouse, a secure Cloud Infrastructure Agent running locally "
                "on the user's machine with their full AWS credentials loaded.\n"
                "You MUST execute live AWS operations yourself using tools — never ask the user "
                "to run commands manually.\n"
                "Before calling any tool, output a concise explanation of what you are about to "
                "do and why. This is shown to the user before they approve."
            )
        )
        config = {"configurable": {"thread_id": "main"}}
        first_turn = True
        logger.success("Agent ready.")
    except Exception as e:
        logger.error(f"Failed to initialize agent: {e}")
        return

    # ── REPL loop ────────────────────────────────────────────────────────────
    while True:
        try:
            c.print()
            user_input = Prompt.ask("[bold cyan] ❯[/bold cyan]")
            if user_input.strip().lower() in ("exit", "quit", ""):
                if user_input.strip().lower() in ("exit", "quit"):
                    c.print("\n[dim]Goodbye.[/dim]\n")
                    break
                continue

            messages = (
                [system_prompt, HumanMessage(content=user_input)]
                if first_turn else
                [HumanMessage(content=user_input)]
            )
            first_turn = False

            # Stream agent events
            c.print("\n[dim]  ● Thinking...[/dim]")
            for event in graph.stream({"messages": messages}, config=config):

                if "agent" in event:
                    msg = event["agent"]["messages"][-1]
                    if msg.content:
                        # Clear the "Thinking..." line with a blank then print response
                        c.print()
                        c.print(Panel(
                            Markdown(msg.content),
                            title="[bold cyan]Lighthouse[/bold cyan]",
                            border_style="cyan",
                            padding=(0, 2),
                        ))
                        # If there are tool calls coming next, show a follow-up indicator
                        if msg.tool_calls:
                            c.print("\n[dim]  ● Preparing tool execution...[/dim]")

                elif "tools" in event:
                    msg = event["tools"]["messages"][-1]
                    content_preview = str(msg.content)[:120].replace("\n", " ")
                    c.print(Panel(
                        f"[dim]{content_preview}{'...' if len(str(msg.content)) > 120 else ''}[/dim]",
                        title=f"[dim]Tool result — {msg.name if hasattr(msg, 'name') and msg.name else 'tool'}[/dim]",
                        border_style="dim",
                        padding=(0, 2),
                    ))
                    c.print("\n[dim]  ● Thinking...[/dim]")

        except KeyboardInterrupt:
            c.print("\n[dim]Goodbye.[/dim]\n")
            break
        except Exception as e:
            logger.error(f"Error: {e}")


if __name__ == "__main__":
    app()
