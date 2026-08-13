# Contributing

## Setup

```bash
uv sync --dev
uv run aws-lighthouse --help
```

Python 3.12 is the minimum. Keep runtime dependencies minimal; do not add a
package for functionality already available in the standard library or boto3.

## Development workflow

1. Create a focused branch such as `fix/fail-closed-delta` or
   `feat/new-scanner`.
2. For behavioral changes, write the failing test first and observe the expected
   failure. Implement the smallest change, then refactor while green.
3. Preserve the `ScanResult` contract at AWS boundaries. Partial data belongs in
   `data`; incompleteness belongs in `errors` with `ok=false`.
4. New agent tools must be classified. The default is approval-gated. Add a tool
   to `AUTO_APPROVED_TOOL_NAMES` only when it is demonstrably read-only and does
   not access arbitrary local paths.
5. Regional resources must carry region identity. Global checks must run once.
6. Update user-facing docs and `CHANGELOG.md` with behavior changes.
7. Run `./scripts/ci-parity.sh` before opening a pull request.

## Focused commands

```bash
uv run pytest tests/test_module.py -q --no-cov
uv run ruff check .
uv run ruff format --check .
uv run mypy aws_lighthouse
./scripts/dependency-audit.sh
```

Focused pytest uses `--no-cov`; the full gate enforces repository coverage.

## Scanner checklist

- Use `get_client(service, region)` so the shared retry/client policy applies.
- Use paginators for list/describe APIs that support them.
- Convert `ClientError`/`BotoCoreError` to `ScanError` with service, operation,
  region, and retryability.
- Preserve already observed data if a later sub-call fails.
- Add empty-account, multi-page, access-denied, throttling/partial, and regional
  identity tests.
- Do not catch programming exceptions as successful empty scans.

## Pull requests

Keep the title and description concise: outcome, risk, and verification. Do not
include credentials, account IDs, unredacted AWS payloads, internal discussion,
or generated local database/log files.
