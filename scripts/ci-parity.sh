#!/usr/bin/env bash
set -euo pipefail

uv run ruff check .
uv run ruff format --check .
uv run mypy aws_lighthouse
uv run pytest
./scripts/dependency-audit.sh

smoke_root="$(mktemp -d /tmp/aws-lighthouse-smoke.XXXXXX)"
trap 'rm -rf "${smoke_root}"' EXIT
uv build --out-dir "${smoke_root}/dist"
uv venv "${smoke_root}/venv"
uv pip install "${smoke_root}"/dist/*.whl --python "${smoke_root}/venv/bin/python"
"${smoke_root}/venv/bin/aws-lighthouse" --help >/dev/null
