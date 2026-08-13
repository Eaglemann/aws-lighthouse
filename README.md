# AWS Lighthouse

AWS Lighthouse is a terminal-first AWS FinOps and security scanner with a local
Ollama/LangGraph assistant. It inventories enabled regions, detects cost and
security opportunities, persists local history, emits JSON or SARIF, and can
apply a small set of remediations only after explicit confirmation.

> Status: alpha. Use a dedicated read-only role or sandbox first. Review every
> requested mutation and never treat a degraded scan as complete evidence.

## What it does

- Multi-region EC2, RDS, Lambda, and global S3 inventory.
- Cost summaries, anomaly detection, forecasts, waste checks, RI/SP analysis,
  Compute Optimizer recommendations, tag-cost coverage, and scenario planning.
- Security, IAM, CloudWatch, tagging, and security-group blast-radius checks.
- Fail-closed deltas: partial scans may add observed findings, but cannot resolve
  findings in failed sections or regions.
- Local opportunity lifecycle, audit history, policy-scoped baselines, webhook
  alerts, JSON v1/v2, and SARIF 2.1.0.
- Optional local AI shell using Ollama model `gpt-oss:120b-cloud`.

## Quick start

Requirements: Python 3.12+, [uv](https://docs.astral.sh/uv/), AWS credentials,
and Ollama only if using `shell`.

```bash
git clone https://github.com/Eaglemann/aws-lighthouse.git
cd aws-lighthouse
uv sync --dev

AWS_PROFILE=my-read-only-profile uv run aws-lighthouse analyze
```

Common commands:

```bash
# Single region, machine-readable v2 envelopes
uv run aws-lighthouse analyze --region eu-west-1 --output json --json-schema v2

# Compare with the last compatible scope and config
uv run aws-lighthouse analyze --since-last --config lighthouse-policy.example.toml

# Continuous compact monitoring; mutation prompts are disabled
uv run aws-lighthouse watch --interval-hours 4 --notify-webhook "$LIGHTHOUSE_NOTIFY_WEBHOOK"

# Local assistant; verifies Ollama before starting
OLLAMA_HOST=http://localhost:11434 uv run aws-lighthouse shell
```

`analyze` is non-interactive by default. `--interactive` enables CUR and
remediation prompts; selected remediations still require one confirmation per
resource. `watch` never enables mutation prompts.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [CLI and output contracts](docs/CLI_REFERENCE.md)
- [Agent tools and approval policy](docs/AGENT_TOOLS.md)
- [Local database schema](docs/DATABASE_SCHEMA.md)
- [Operations and live qualification](docs/OPERATIONS.md)
- [Security policy and threat model](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)
- [Example policy](lighthouse-policy.example.toml)

## Development gate

```bash
./scripts/ci-parity.sh
```

This runs lint, formatting, mypy, the complete test suite, the strict production
dependency audit, a package build, a clean-wheel install, and an entry-point
smoke test. Live AWS/Ollama qualification is separately and explicitly gated;
see [operations](docs/OPERATIONS.md).

## Safety summary

- AWS read tools may run without a prompt; mutations never do.
- Local Terraform reads, drift reads, file reads/writes, and opportunity-state
  updates require approval.
- Generic shell execution is not exposed to the model.
- Unknown tools fail closed to the approval route.
- The local database directory is mode `0700`; the database is mode `0600`.
- The repository ignores common credential, key, Terraform state, and local DB
  files and scans history with a checksum-verified Gitleaks binary in CI/release.

See [SECURITY.md](SECURITY.md) for limitations, IAM guidance, and reporting.

## License

[MIT](LICENSE)
