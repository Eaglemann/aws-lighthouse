#!/usr/bin/env bash
set -euo pipefail

tmp_reqs="$(mktemp /tmp/aws-lighthouse-reqs.XXXXXX.txt)"
trap 'rm -f "${tmp_reqs}"' EXIT

if ! uv export --no-dev --format requirements-txt --no-hashes >"${tmp_reqs}"; then
  echo "dependency-audit: failed to export production dependencies with uv." >&2
  exit 1
fi

if [[ ! -s "${tmp_reqs}" ]]; then
  echo "dependency-audit: exported requirements file is empty: ${tmp_reqs}" >&2
  exit 1
fi

if ! uvx --with pip-audit pip-audit -r "${tmp_reqs}" --no-deps --disable-pip; then
  echo "dependency-audit: pip-audit failed or found vulnerabilities." >&2
  exit 1
fi
