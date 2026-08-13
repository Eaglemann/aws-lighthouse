# Operations and qualification

## Credential strategy

Use a dedicated AWS profile or role with the least permissions required for the
enabled scanners. Avoid running against production first. Authentication uses
the standard boto3 provider chain and may prompt for profile/region/role only
when implicit credentials fail.

All boto3 clients use adaptive retry mode and are cached by service/region. A
successful identity check does not prove scanner permissions; inspect degraded
services and v2 errors.

## Runtime files

- SQLite: `~/.aws-lighthouse/lighthouse.db`
- Logs: `~/.aws-lighthouse/logs/aws-lighthouse.log`
- Ollama host: `OLLAMA_HOST`, default `http://localhost:11434`
- Notification webhook: `LIGHTHOUSE_NOTIFY_WEBHOOK`
- Scanner tuning: `LIGHTHOUSE_ANOMALY_THRESHOLD_PCT`,
  `LIGHTHOUSE_SNAPSHOT_AGE_DAYS`, `LIGHTHOUSE_LAMBDA_STALE_DAYS`

Do not place webhook secrets or AWS credentials in committed policy files.

## Local quality gate

```bash
./scripts/ci-parity.sh
```

The gate performs Ruff lint/format, mypy, full pytest with coverage, strict
production `pip-audit`, package build, clean-wheel install, and entry-point
smoke test. CI additionally scans full git history for secrets. Release repeats
the security gates and verifies the tag equals the package version.

## Guarded live qualification

Live tests are never part of the default test run. AWS qualification requires an
explicit profile and exact expected account, and verifies STS identity before
scanner calls.

```bash
export AWS_LIGHTHOUSE_LIVE_AWS=1
export AWS_PROFILE=lighthouse-sandbox
export AWS_LIGHTHOUSE_EXPECTED_ACCOUNT_ID=123456789012
export AWS_LIGHTHOUSE_LIVE_REGIONS=eu-west-1,us-east-1  # optional; defaults to first two enabled

./scripts/run-live-qualification.sh
```

Default live AWS mode is strict: any scanner error fails qualification. Set
`AWS_LIGHTHOUSE_ALLOW_PARTIAL=1` only when intentionally qualifying a
least-privilege role with known denied services; envelopes are still validated.

For Ollama:

```bash
export AWS_LIGHTHOUSE_LIVE_OLLAMA=1
export OLLAMA_HOST=http://localhost:11434
./scripts/run-live-qualification.sh
```

The Ollama test verifies `/api/tags`, the required model, and LangGraph compile.
The AWS suite exercises multi-region inventory, global S3 inventory, a real
agent read tool, and proves an AWS mutation routes to approval without executing
it.

## Degraded scans

Treat `ok=false` or any displayed degraded service as an incomplete run. The
system preserves partial positive evidence and blocks false resolution, but an
operator should still investigate access denial, unsupported services, expired
credentials, throttling, or transient AWS errors.

Recommended monitoring rule: alert on repeated degraded sections separately
from finding alerts. A quiet finding webhook does not prove a complete scan.

## Release procedure

1. Update `CHANGELOG.md` and run `./scripts/ci-parity.sh`.
2. Bump with `uv version --bump patch|minor|major`.
3. Commit the version and lockfile.
4. Tag `v$(uv version --short)` and push the tag.
5. The release workflow validates tag/version, repeats security/quality gates,
   builds and smoke-tests distributions, publishes via PyPI OIDC, and creates a
   GitHub release.
