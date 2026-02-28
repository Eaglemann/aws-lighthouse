# AWS Lighthouse

**AWS Lighthouse** is a terminal-first FinOps, Security, and Cloud Infrastructure Agent. It gives you a complete read-only picture of your AWS estate in one command, flags misconfigurations and cost waste across every enabled region, and lets you remediate findings or deploy infrastructure through a conversational AI agent — all from the CLI, with your credentials never leaving your machine.

Built on **LangGraph**, **LangChain**, **Ollama**, **Rich**, and **Typer**. Strictly enforces a **Human-in-the-Loop "Plan → Approve → Execute"** workflow so you remain in full control at every step.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Commands](#commands)
   - [analyze](#analyze--the-finops-dashboard)
   - [shell](#shell--the-interactive-agent)
5. [Dashboard Panels](#dashboard-panels)
6. [Agent Tools Reference](#agent-tools-reference)
7. [Human-in-the-Loop Approval](#human-in-the-loop-approval)
8. [AWS Authentication](#aws-authentication)
9. [Local State Database](#local-state-database)
10. [Architecture](#architecture)
11. [Project Structure](#project-structure)
12. [Development](#development)

---

## Prerequisites

| Requirement | Notes |
|---|---|
| **Python 3.12+** | Required for `str \| None` union syntax and modern typing |
| **[uv](https://github.com/astral-sh/uv)** | Fast dependency manager — replaces pip/poetry |
| **[Ollama](https://ollama.ai)** | Local LLM runtime, must be running before starting the shell |
| **`gpt-oss:120b-cloud` model** | The reasoning model used by the agent |
| **AWS Credentials** | Any standard method: `~/.aws/credentials`, `AWS_PROFILE`, env vars, IAM role, SSO |

Pull the model once:
```bash
ollama pull gpt-oss:120b-cloud
```

---

## Installation

```bash
git clone <repo-url>
cd aws-lighthouse
uv sync
```

---

## Quick Start

```bash
# Full multi-region dashboard (auto-detects all enabled regions)
uv run aws-lighthouse analyze

# Adjust cost look-back window
uv run aws-lighthouse analyze --days 30

# Interactive AI agent shell
uv run aws-lighthouse shell

# Running with no subcommand opens the shell directly
uv run aws-lighthouse
```

---

## Commands

### `analyze` — The FinOps Dashboard

Runs a comprehensive, **read-only** scan of your entire AWS estate and renders a Rich terminal dashboard. No changes are made to your account.

```bash
uv run aws-lighthouse analyze [--days N]
```

**Options:**

| Flag | Default | Description |
|---|---|---|
| `--days`, `-d` | `14` | Cost Explorer look-back window in days |

**What it does, step by step:**

1. **Authenticates** — validates credentials via STS `GetCallerIdentity`
2. **Detects regions** — calls `describe_regions` to find every opted-in region in your account; runs all subsequent regional scans across all of them automatically
3. **Scans inventory** — EC2, RDS, Lambda, S3 fetched in parallel per region with live `"Scanning us-east-1..."` spinner updates
4. **Fetches costs** — Cost Explorer `GetCostAndUsage` for the requested window; saves a snapshot to SQLite for trend tracking
5. **Detects cost anomalies** — compares last 7 days vs prior 7-day baseline per service; flags >50% spikes
6. **RI / Savings Plan coverage** — coverage % and utilization for both Reserved Instances and Savings Plans; highlights under-utilised commitments and uncovered on-demand spend
7. **Security scan** — six checks across all regions (see [Dashboard Panels](#dashboard-panels))
8. **IAM over-permissive scan** — inspects every user, role, and group for dangerous policies (global)
9. **CloudWatch alarm gaps** — finds EC2/RDS instances missing alarms on key metrics per region
10. **Cost waste scan** — unattached EBS, stopped EC2, stale snapshots, unassociated EIPs per region
11. **Tagging compliance** — EC2/RDS/S3 resources missing required tags
12. **Lambda inventory** — full function list with runtime, memory, code size, staleness flag
13. **One-click remediation** — numbered menu of auto-fixable findings; confirm each fix individually before it runs
14. **CUR upsell** — prompts to deploy the Cost & Usage Report CloudFormation stack if not already active

---

### `shell` — The Interactive Agent

Starts a persistent, conversational AI agent powered by LangGraph and your local Ollama model.

```bash
uv run aws-lighthouse shell
# or simply:
uv run aws-lighthouse
```

The shell maintains **conversation memory** across turns via LangGraph's `MemorySaver` checkpointer — the agent remembers what it found earlier in the session without you repeating context.

**Example prompts:**

```
❯ scan all my regions for security issues
❯ which EC2 instances are stopped and costing me money?
❯ apply Block Public Access to my-public-bucket
❯ check IAM for over-permissive policies
❯ show me Lambda functions that haven't been deployed in over 6 months
❯ what's my RI coverage and where am I wasting committed spend?
❯ deploy the CUR CloudFormation stack
❯ parse my ./infra Terraform files and tell me what resources exist
❯ terminate instance i-0abc1234def567890
```

The agent always explains its reasoning before calling any tool. Destructive operations require your explicit `y` approval before executing.

---

## Dashboard Panels

All panels follow a consistent colour scheme:
- **Blue** border — inventory / informational
- **Yellow** border — cost / warnings
- **Red** border — security / anomalies / high severity
- **Green** border — all-clear

### Inventory + Cost (side by side)

| Inventory | Cost |
|---|---|
| EC2 instance count | Total spend for the period |
| RDS database count | Per-service breakdown (top 6) |
| S3 bucket count | Trend arrow vs last scan (▲/▼) |
| Lambda function count | |

When multiple regions are detected the Inventory title shows `· N regions` and every finding table gains a **Region** column.

### Cost Anomalies

Compares each service's last 7-day spend against the prior 7-day baseline. Services with a >50% increase are flagged with the absolute amounts and percentage change.

### RI / Savings Plan Coverage

| Column | Description |
|---|---|
| Coverage | % of eligible hours/spend covered by commitments |
| Utilization | % of purchased commitment actually consumed |
| Uncovered Spend | On-demand dollars not protected by any commitment |
| Idle Cost | Money paid for unused RI/SP capacity |

Coverage and utilization are colour-coded: ≥80% green, 60–80% yellow, <60% red.

> **Note:** A deeper RI/SP analyser backed by 3-year CUR data is planned — see [fixplan.md](fixplan.md).

### Security

Six checks run across every enabled region:

| Check | Severity | Scope |
|---|---|---|
| Root account MFA | HIGH | Global |
| Open security groups (SSH/RDP from 0.0.0.0/0 or ::/0) | HIGH | Regional |
| IAM access keys older than 90 days | MEDIUM | Global |
| RDS instances with Public Accessibility enabled | HIGH | Regional |
| S3 buckets missing Block Public Access | HIGH | Global |
| CloudTrail not configured or not logging | HIGH | Regional |

### IAM Over-Permissive Policies

Scans all users, roles, and groups for dangerous policy statements:

| Severity | Condition |
|---|---|
| HIGH | `Action: *` on `Resource: *` (full administrator) |
| MEDIUM | `Action: <service>:*` on `Resource: *` (service-level wildcard) |

Checks inline policies, customer-managed policies (document fetched and cached), and known dangerous AWS-managed policies (`AdministratorAccess`, `PowerUserAccess`). AWS service-linked roles are skipped.

### CloudWatch Alarm Gaps

Finds resources with no alarm on key metrics:

| Resource | Required metrics |
|---|---|
| EC2 | CPUUtilization, StatusCheckFailed |
| RDS | CPUUtilization, FreeStorageSpace |

### Cost Waste

| Finding | Impact |
|---|---|
| Unattached EBS volumes | Paying for storage with no instance |
| Stopped EC2 instances | EBS volumes still billed |
| EBS snapshots older than 90 days | Accumulating snapshot storage cost |
| Unassociated Elastic IPs | ~$0.005/hr per idle address |

### Tagging Compliance

Checks every EC2 instance, RDS database, and S3 bucket for the required tags (`Environment`, `Owner` by default). Lists every missing tag per resource.

### Lambda Inventory

Lists all functions with runtime, memory (MB), code size (MB), last deploy date, and a **Stale** flag for functions not deployed in >180 days.

### One-Click Remediation

After all panels, Lighthouse presents a numbered list of findings that can be fixed automatically:

| Action | Triggered by |
|---|---|
| Enable S3 Block Public Access | S3 security finding |
| Delete EBS Volume | Unattached EBS finding |
| Release Elastic IP | Unassociated EIP finding |

Each fix requires individual confirmation before it calls the AWS API.

---

## Agent Tools Reference

All tools are available to the agent in the interactive shell. Read-only tools bypass the approval prompt automatically.

### Read-Only (no approval required)

| Tool | Description |
|---|---|
| `tool_get_enabled_regions` | List all opted-in AWS regions for this account |
| `tool_get_ec2_inventory(region)` | EC2 instances and state |
| `tool_get_rds_inventory(region)` | RDS instances and state |
| `tool_get_s3_inventory` | S3 buckets (global) |
| `tool_get_lambda_inventory(region)` | Lambda functions with staleness flag |
| `tool_get_ri_sp_coverage(days)` | RI and Savings Plan coverage + utilization |
| `tool_detect_cost_anomalies(threshold_pct)` | Per-service spend spikes vs prior 7d |
| `tool_check_tagging_compliance(required_tags, region)` | Missing tags on EC2/RDS/S3 |
| `tool_detect_overpermissive_iam` | IAM wildcard policy findings |
| `tool_detect_cloudwatch_gaps(region)` | EC2/RDS resources missing alarms |
| `tool_read_file(filepath)` | Read a local file |
| `parse_terraform_context` | Parse local `.tf` files |

### Mutative (require explicit approval)

| Tool | Description |
|---|---|
| `terminate_ec2(instance_id)` | Terminate an EC2 instance |
| `delete_ebs(volume_id)` | Delete an EBS volume |
| `s3_block_public_access(bucket_name)` | Enable Block Public Access on an S3 bucket |
| `tool_write_file(filepath, content)` | Write to a local file |
| `tool_execute_bash(command)` | Execute a shell command |

All regional tools accept an optional `region` parameter. When omitted, the session's default region is used. The agent is instructed to call `tool_get_enabled_regions` first when the user asks for a broad analysis, then fan out tool calls per region.

---

## Human-in-the-Loop Approval

The LangGraph state machine routes every tool call through one of two paths:

```
agent ──► should_require_approval?
              │
              ├─ read-only tool ──► tools (execute immediately)
              │
              ├─ destructive tool ──► approval node ──► [user types y] ──► tools
              │                                     └─ [user types n] ──► synthetic rejection sent to LLM
              │
              └─ no tool call ──► END
```

When an approval is requested you see:
- The agent's reasoning for the action
- Each tool name and the exact JSON arguments it generated
- A `y/n` prompt — **nothing runs until you type `y`**

If you deny, the agent receives a synthetic `ToolMessage` stating "User explicitly denied execution of this tool" and may propose an alternative approach.

---

## AWS Authentication

Authentication follows this priority order:

1. **Implicit credentials** — environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`), `~/.aws/credentials`, `AWS_PROFILE`, or an attached IAM role / instance profile
2. **Interactive fallback** — if no credentials are found, Lighthouse prompts for an AWS profile name, region, and optional role ARN to assume

A single `boto3.Session` is created once per process (singleton pattern via `AuthManager`) and reused for all service clients. Regional clients are derived from the same session via `get_aws_client_for_region(service, region)` — assumed-role credentials propagate automatically.

---

## Local State Database

Lighthouse maintains a SQLite database at `~/.aws-lighthouse/lighthouse.db`.

| Table | Purpose |
|---|---|
| `cost_snapshots` | One row per `analyze` run — account ID, date range, total spend, per-service breakdown. Used to compute the ▲/▼ cost trend shown in the dashboard. |

The database is created automatically on first run. No data leaves your machine.

---

## Architecture

### LangGraph State Machine

```
┌─────────────────────────────────────────────────────────────┐
│                      AgentState                             │
│  messages: Annotated[Sequence[BaseMessage], add_messages]   │
└─────────────────────────────────────────────────────────────┘
         │
    ┌────▼─────┐    should_require_approval()
    │  agent   ├──────────────────────────────────────────────────┐
    │  node    │                                                  │
    └────┬─────┘   read-only tool?          destructive tool?     │
         │              │                        │                │
         │         ┌────▼──────┐          ┌──────▼──────┐        │
         │         │   tools   │          │  approval   │        │
         │         │   node    │          │    node     │        │
         │         └────┬──────┘          └──────┬──────┘        │
         │              │                        │ (approved)    │
         └──────────────┴────────────────────────┘               │
                        │                                        │
                   (loop back)                             (no tool calls)
                                                               END
```

**Key components:**

- **`agent_node`** — invokes the LLM with the full message history; produces either a text response or tool calls
- **`approval_node`** — human-in-the-loop intercept; shows the proposed plan and waits for `y/n`
- **`tool_node`** — LangChain `ToolNode` that executes approved tool calls and returns `ToolMessage` results
- **`MemorySaver` checkpointer** — persists the full message graph in memory across turns; each `shell` session uses `thread_id = "main"`
- **`SAFE_TOOLS`** — set of read-only tool names that bypass the approval node entirely

### Tool Architecture

Each tool in `tools/` follows the pattern:

1. Pure Python function with typed inputs — testable in isolation, no LangChain dependency
2. `@tool`-decorated wrapper in `agent.py` — serialises inputs/outputs as JSON strings for the LLM
3. Regional variants accept `region: str = ""` — empty string coerces to `None` (session default)

---

## Project Structure

```
aws_lighthouse/
├── cli.py                  # Typer CLI — analyze dashboard + shell REPL
├── agent.py                # LangGraph state machine, tool bindings, approval node
├── auth.py                 # AWS credential management (singleton session)
├── db.py                   # SQLite cost snapshot store
├── logger.py               # Rich console logger wrapper
├── templates/              # CloudFormation templates
│   └── cur_stack.yaml      # Cost & Usage Report setup
└── tools/
    ├── bash.py             # File I/O and shell execution (read_file, write_file, execute_bash)
    ├── cfn_deploy.py       # CloudFormation deployment (CUR stack)
    ├── cloudwatch_scan.py  # CloudWatch alarm gap detection
    ├── cost.py             # Cost Explorer monthly summary
    ├── cost_anomaly.py     # Per-service spend spike detection
    ├── cost_scan.py        # Cost waste findings (EBS, EC2, snapshots, EIPs)
    ├── iam_scan.py         # IAM over-permissive policy detection
    ├── inventory.py        # EC2 / RDS / S3 / Lambda inventory (region-aware)
    ├── multi_region.py     # get_enabled_regions() helper
    ├── remediation.py      # Destructive tools: terminate_ec2, delete_ebs
    ├── remediation_actions.py  # One-click fixes: S3 BPA, delete EBS, release EIP
    ├── ri_sp_coverage.py   # RI and Savings Plan coverage + utilization
    ├── security.py         # s3_block_public_access (agent-facing mutative tool)
    ├── security_scan.py    # Six-check security posture scan
    ├── tagging.py          # Tagging compliance (EC2 / RDS / S3)
    └── terraform.py        # Terraform file parser
```

---

## Development

```bash
# Install all dependencies including dev extras
uv sync --all-extras --dev

# Lint
uv run ruff check .

# Auto-fix lint issues
uv run ruff check --fix .

# Format
uv run ruff format .

# Type checking
uv run mypy aws_lighthouse

# Run tests
uv run pytest
```

### Adding a New Tool

1. Add the core logic as a plain Python function in the appropriate `tools/*.py` file
2. If the tool is regional, accept `region: str | None = None` and use `get_aws_client_for_region(service, region) if region else get_aws_client(service)`
3. Write a `@tool`-decorated wrapper in `agent.py` that calls the plain function and returns `json.dumps(result)`
4. If the tool is read-only, add its name to the `SAFE_TOOLS` set in `agent.py`
5. Add it to the `tools` list in `agent.py`
6. If it produces findings displayed in the dashboard, add a panel in `cli.py`

### CI

GitHub Actions runs on every push to `main` and on pull requests:
- `ruff check` — linting
- `ruff format --check` — formatting
- `mypy` — type checking
- `pytest` — unit tests

See `.github/workflows/ci.yml` for the full pipeline definition.
