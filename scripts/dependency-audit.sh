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

# CVE-2026-28277 currently has no published fix for langgraph and affects
# persisted checkpoint loading. aws-lighthouse uses MemorySaver, not a
# persistent checkpoint backend, so keep the audit strict but carve out this
# one advisory until upstream ships a fix.
if ! uvx --with pip-audit pip-audit -r "${tmp_reqs}" --no-deps --disable-pip --ignore-vuln CVE-2026-28277; then
  echo "dependency-audit: pip-audit failed or found vulnerabilities." >&2
  exit 1
fi
