# AWS Lighthouse

**AWS Lighthouse** is a terminal-first FinOps, Security, and Cloud Infrastructure Agent. It acts as an interactive assistant to help you analyze your AWS environment, safely remediate security issues, cut costs, and generate Terraform infrastructure—all from the comfort of your CLI.

Built with **Typer**, **Rich**, and powered locally by **LangGraph** & **Ollama** (`gpt-oss:120b-cloud`), Lighthouse strictly enforces a Human-in-the-Loop "Plan -> Approve -> Execute" workflow so you remain in complete control of your AWS environment at all times.

---

## Prerequisites

Before running Lighthouse, ensure you have the following installed:

1. **Python 3.12+** & [uv](https://github.com/astral-sh/uv) (for lightning-fast dependency management)
2. **Node.js / npm** (required to run `npx` for spinning up the official AWS Model Context Protocol server in the background)
3. **Ollama** running locally.
4. The `gpt-oss:120b-cloud` model pulled in Ollama:
   ```bash
   ollama run gpt-oss:120b-cloud
   ```
5. Valid **AWS Credentials** configured locally (e.g., via `~/.aws/credentials`, `AWS_PROFILE`, or AWS SSO). *If credentials are not found in the environment, Lighthouse will interactively prompt you for them at runtime.*

---

## Installation

1. Clone or navigate to the repository:
   ```bash
   git clone <repo-url>
   cd aws-lighthouse
   ```

2. Sync dependencies and build the virtual environment using `uv`:
   ```bash
   uv sync
   ```

---

## Usage & Commands

Lighthouse exposes two primary CLI commands. You can run them gracefully using `uv run`.

### 1. `analyze` - The Read-Only FinOps Dashboard
This command runs a fast, parallel read-only scan of your active AWS account. It pulls inventory (EC2, RDS, S3) and the trailing 14-days of AWS Cost Explorer data. It saves snapshots to a local SQLite database (`~/.aws-lighthouse/lighthouse.db`) to show you cost trends over time.

```bash
uv run aws-lighthouse analyze
```
*Optional arguments:*
- `--days <int>`: Adjust the Cost Explorer lookback window (default is 14).

### 2. `shell` - The Interactive Agent Loop
This boots up the LangGraph reasoning engine and binds it to safe Bash tools, remote AWS MCP servers (like Terraform scaffolding), and destructive Boto3 remediation templates. 

```bash
uv run aws-lighthouse shell
```
Once inside the prompt (`lighthouse> `), you can ask the agent to perform complex operations like:
- *"Review my active EC2 instances and tell me if any are stopped."*
- *"Deploy the built-in CUR CloudFormation template."*
- *"Look at the `./infra` folder, parse my `.tf` files, and use the AWS MCP tool to scaffold a new S3 bucket for logs."*
- *"Check for any S3 buckets without Block Public Access, and secure them."*

#### 🛡️ The Approval Node
Any time the agent attempts to execute a destructive or mutative tool (e.g., terminating an EC2 instance, generating Terraform, applying Block Public Access), the shell process will **pause** and present a Rich-formatted execution plan.

You will see exactly which tools the agent intends to run and the JSON arguments it generated. You must type `y` to approve before any execution hits the AWS API or your local file system.

---

## Project Architecture & Roadmap

Refer to the internal AI-generated `task.md` and `implementation_plan.md` in the `.gemini/` workspace directory for the deep architectural overview of the Agent Nodes, State Graph, and Context Engine.
