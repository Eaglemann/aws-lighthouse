# CLI and output contracts

Run `uv run aws-lighthouse COMMAND --help` for the generated option reference.
This document describes behavior that is easy to miss from option names.

## `analyze`

```text
aws-lighthouse analyze [--days N] [--region REGION]
  [--output text|json|sarif] [--json-schema v1|v2]
  [--since-last] [--config PATH] [--interactive]
  [--profiles a,b,c] [--terraform-dir PATH]
```

- Default scope: every enabled AWS region plus global services.
- `--region`: one region; cannot be combined with `--profiles`.
- `--profiles`: sequentially scans named AWS profiles and renders an account
  summary. It does not run profiles concurrently because authentication state is
  process-global.
- `--interactive`: permits CUR deployment and remediation prompts. Without it,
  `analyze` is read-only.
- `--terraform-dir`: classifies findings as Terraform-managed versus shadow
  infrastructure. Reading the directory is an explicit CLI request; the agent
  equivalent is approval-gated.
- `--since-last`: compares only against the same account and scope key.

## `watch`

```text
aws-lighthouse watch [--interval-hours HOURS] [--days N]
  [--region REGION] [--output text|json] [--json-schema v1|v2]
  [--config PATH] [--view compact|full] [--notify-webhook URL]
```

Each cycle is non-interactive and compares against the preceding compatible
snapshot. JSON mode emits one JSON object per line, including recoverable cycle
errors. Webhook alerts are sent only when new HIGH/CRITICAL findings satisfy the
alert policy; degraded sections do not create false resolved findings.

## Other commands

- `estimate RESOURCE_SPEC [--region REGION] [--output text|json]`: estimate
  monthly cost and produce a Terraform scaffold. Example resource spec:
  `ec2:m5.large:2,rds:db.t3.medium:1,lambda::3`.
- `audit [--limit N] [--since ISO_TIMESTAMP]`: local agent tool-decision log.
- `logs [--lines N]`: recent local application log entries.
- `shell`: interactive Ollama/LangGraph assistant. Bare `aws-lighthouse` also
  enters the shell.

## Scan envelope (`v2`)

Every scanner boundary uses:

```json
{
  "ok": false,
  "data": [{"resource": "observed-before-error"}],
  "errors": [
    {
      "code": "AccessDeniedException",
      "message": "not authorized",
      "service": "ec2",
      "operation": "DescribeInstances",
      "region": "eu-west-1",
      "retryable": false
    }
  ]
}
```

`ok=false` means incomplete, not necessarily empty. Consumers must inspect both
`data` and `errors`. `v1` returns compatibility payloads without per-section
envelopes. Prefer v2 for automation.

## Delta contract

For each tracked section:

```json
{
  "new": [],
  "resolved": [],
  "unchanged_count": 4,
  "trusted": false,
  "error_count": 1
}
```

When a section is degraded, observed positive evidence may appear in `new`, but
`resolved` is forced empty and `trusted=false`. The delta summary also lists
`degraded_sections`.

## SARIF

`--output sarif` emits SARIF 2.1.0. Security HIGH/CRITICAL maps to `error`,
MEDIUM to `warning`, LOW to `note`, and findings without an explicit severity to
`warning`. The driver version is read from the installed package metadata and
the information URI points to this repository.

## Policy file

Start from [`lighthouse-policy.example.toml`](../lighthouse-policy.example.toml).
Unknown keys are rejected.

```toml
required_tags = ["Owner", "Environment", "CostCenter"]
cost_anomaly_threshold_pct = 50

[regions]
include = ["eu-west-1", "us-east-1"]
exclude = []

[scans]
cost_anomalies = true
ri_sp_coverage = true
security = true
iam = true
cloudwatch = true
cost_waste = true
tagging = true
```

Region include/exclude overlap, unknown enabled regions, an empty result after
filtering, empty tag lists, negative thresholds, and extra fields are errors.
