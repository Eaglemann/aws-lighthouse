import typer
from .logger import logger

app = typer.Typer(
    help="AWS Lighthouse: Terminal-first FinOps, Security, and Scaffolding Agent.",
    add_completion=False,
)


@app.command()
def analyze(
    days: int = typer.Option(
        14, "--days", "-d", help="Days of cost history to analyze"
    ),
):
    """Retrieve Read-Only state (Drift & Cost) and render a dashboard."""
    from .auth import get_aws_session
    from .db import db_manager
    from .tools.inventory import get_ec2_inventory, get_rds_inventory, get_s3_inventory
    from .tools.cost import get_monthly_cost_summary
    from rich.table import Table
    from rich.columns import Columns
    from rich.panel import Panel

    logger.print_header("AWS Lighthouse - Environment Analysis")

    # 1. Authenticate
    with logger.console.status(
        "[cyan]Checking AWS Credentials...[/cyan]", spinner="dots"
    ):
        session = get_aws_session()
        sts = session.client("sts")
        account_id = sts.get_caller_identity()["Account"]

    # 2. Gather Inventory
    with logger.console.status(
        "[cyan]Scanning AWS Environment State...[/cyan]", spinner="dots"
    ):
        ec2s = get_ec2_inventory()
        rdss = get_rds_inventory()
        s3s = get_s3_inventory()

    cur_bucket_exists = False
    if s3s and "error" not in s3s[0]:
        cur_bucket_exists = any(b.get("BucketName", "").startswith("cur-data-lighthouse-") for b in s3s)

    # 3. Gather Cost
    with logger.console.status(
        f"[cyan]Aggregating Costs for the last {days} days...[/cyan]", spinner="dots"
    ):
        costs = get_monthly_cost_summary(days=days)

    # 4. Capture previous snapshot before saving the new one, then save
    prev_snapshot = db_manager.get_latest_cost_snapshot(account_id)
    if "error" not in costs:
        db_manager.record_cost_snapshot(
            account_id=account_id,
            start=costs["start"],
            end=costs["end"],
            total=costs["total_usd"],
            breakdown=costs["breakdown"],
        )

    # 5. Render Output
    logger.console.print(f"\n[bold]Account ID:[/bold] {account_id}")

    # Inventory Table
    inv_table = Table(title="Resource Inventory summary")
    inv_table.add_column("Resource Type", style="cyan")
    inv_table.add_column("Count", justify="right", style="green")
    inv_table.add_row(
        "EC2 Instances",
        str(len(ec2s) if "error" not in (ec2s[0] if ec2s else {}) else "Error"),
    )
    inv_table.add_row(
        "RDS Instances",
        str(len(rdss) if "error" not in (rdss[0] if rdss else {}) else "Error"),
    )
    inv_table.add_row(
        "S3 Buckets",
        str(len(s3s) if "error" not in (s3s[0] if s3s else {}) else "Error"),
    )

    # Cost Table
    cost_table = Table(title=f"Cost Summary ({costs.get('period', 'Error')})")
    cost_table.add_column("Service", style="magenta")
    cost_table.add_column("Cost (USD)", justify="right", style="yellow")
    if "error" not in costs:
        cost_table.add_row(
            "[bold]Total[/bold]", f"[bold]${costs['total_usd']:.2f}[/bold]"
        )
        for svc, amt in list(costs.get("breakdown", {}).items())[:5]:  # Top 5
            cost_table.add_row(svc, f"${amt:.2f}")
    else:
        cost_table.add_row("Error", costs["error"])

    # Trend Analysis
    trend_msg = "[dim]No previous scan found for comparison.[/dim]"
    if prev_snapshot and "error" not in costs:
        prev_total = prev_snapshot["total_usd"]
        curr_total = costs["total_usd"]
        if prev_total > 0:
            pct_change = ((curr_total - prev_total) / prev_total) * 100
            color = "red" if pct_change > 0 else "green"
            trend_msg = f"Cost changed by [{color}]{pct_change:+.1f}%[/{color}] since last scan on {prev_snapshot['recorded_at']}."

    # Security Findings
    public_rds = [
        db for db in rdss
        if "error" not in db and db.get("PubliclyAccessible")
    ]
    sec_table = Table(title="Security Findings")
    sec_table.add_column("Severity", style="red")
    sec_table.add_column("Resource", style="cyan")
    sec_table.add_column("Finding")
    for db in public_rds:
        sec_table.add_row(
            "HIGH",
            db["DBInstanceIdentifier"],
            f"RDS instance is publicly accessible (engine: {db['Engine']}, class: {db['Class']})",
        )
    if not public_rds:
        sec_table.add_row("[green]OK[/green]", "-", "No publicly accessible RDS instances found.")

    logger.console.print()
    logger.console.print(Columns([inv_table, cost_table]))
    logger.console.print(f"\n[bold]Trend:[/bold] {trend_msg}")
    logger.console.print()
    logger.console.print(sec_table)

    # CUR Upsell
    if not cur_bucket_exists:
        logger.console.print()
        cur_msg = (
            "AWS Cost Explorer is limited to high-level daily aggregations. "
            "For deep, long-term FinOps analysis (identifying exactly which resources cost the most), "
            "you must enable Cost & Usage Reports (CUR) delivery to an S3 bucket.\n\n"
            "[bold cyan]Run `aws-lighthouse shell` and type 'Deploy CUR Export' to set this up automatically.[/bold cyan]"
        )
        logger.console.print(
            Panel(
                cur_msg,
                title="[bold yellow]Enable Deep FinOps Parsing[/bold yellow]",
                border_style="yellow",
            )
        )

        if typer.confirm("\nWould you like the agent to deploy the CloudFormation template to activate CUR now?"):
            logger.action_start("Gathering deployment parameters...")
            
            import uuid
            # Pre-fill knowns or ask for inputs
            cust_id = typer.prompt("1. Lighthouse customer resource ID (e.g. cust-abc123)")
            ext_id = typer.prompt("2. External ID for trust relationship")
            
            # Hardcoded parameters required by user
            s3_bucket = f"cur-data-lighthouse-{uuid.uuid4().hex[:8]}"
            sub_url = "NONE (Not required for now)"
            
            logger.action_start("Initiating deterministic CloudFormation deployment...")
            from .tools.cfn_deploy import deploy_cur_template

            success = deploy_cur_template(
                account_id=account_id,
                cust_id=cust_id,
                ext_id=ext_id,
                s3_bucket=s3_bucket
            )
            
            if success:
                logger.success("CUR deployment sequence completed.")
            else:
                logger.error("CUR deployment encountered an error.")


@app.command()
def shell():
    """Start the interactive agent loop."""
    from .agent import create_agent_graph
    from langchain_core.messages import HumanMessage, SystemMessage

    logger.print_header("AWS Lighthouse - Agent Shell")
    logger.action_start("Initializing local brain context...")

    try:
        graph = create_agent_graph()
        system_prompt = SystemMessage(
            content="You are AWS Lighthouse, a secure Cloud Infrastructure Agent, running locally on the user's machine with their full AWS credentials loaded in the environment.\n"
                    "You MUST execute live AWS deployments yourself using the `tool_execute_bash` tool (e.g., calling `aws cloudformation ...`). Do not refuse or ask the user to run commands manually.\n"
                    "Before executing ANY tool (Bash, reading files, Remediation, Terraform, etc.), "
                    "you MUST output a clear, concise explanation of what you are about to do and why. "
                    "This explanation will be shown to the user before they approve your tool call."
        )
        state = {"messages": [system_prompt]}
        logger.success("Agent initialized. Ready to execute commands.")
    except Exception as e:
        logger.error(f"Failed to initialize agent graph: {str(e)}")
        return

    while True:
        try:
            user_input = typer.prompt("lighthouse> ")
            if user_input.lower() in ("exit", "quit"):
                break

            state["messages"].append(HumanMessage(content=user_input))

            # Run graph to completion (or approval pause)
            for event in graph.stream(state):
                if "agent" in event:
                    msg = event["agent"]["messages"][-1]
                    if msg.content:
                        logger.step(f"Agent: {msg.content}")
                elif "tools" in event:
                    msg = event["tools"]["messages"][-1]
                    logger.step(f"Tool execution returned: {msg.content[:100]}...")

            # The Langraph state mutates in place via messages
            # This is a simple interactive stream.

        except typer.Abort:
            break
        except Exception as e:
            logger.error(f"Execution Error: {str(e)}")

if __name__ == "__main__":
    app()
