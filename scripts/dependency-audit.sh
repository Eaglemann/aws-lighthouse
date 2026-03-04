#!/usr/bin/env bash
set -euo pipefail

tmp_reqs="$(mktemp /tmp/aws-lighthouse-reqs.XXXXXX.txt)"
trap 'rm -f "${tmp_reqs}"' EXIT

uv export --no-dev --format requirements-txt --no-hashes > "${tmp_reqs}"
uv run --with pip-audit pip-audit -r "${tmp_reqs}"
