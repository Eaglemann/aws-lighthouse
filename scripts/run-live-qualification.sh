#!/usr/bin/env bash
set -euo pipefail

if [[ "${AWS_LIGHTHOUSE_LIVE_AWS:-}" != "1" && "${AWS_LIGHTHOUSE_LIVE_OLLAMA:-}" != "1" ]]; then
  echo "Set AWS_LIGHTHOUSE_LIVE_AWS=1 and/or AWS_LIGHTHOUSE_LIVE_OLLAMA=1." >&2
  exit 2
fi

if [[ "${AWS_LIGHTHOUSE_LIVE_AWS:-}" == "1" ]]; then
  : "${AWS_PROFILE:?AWS_PROFILE must name the dedicated sandbox profile}"
  : "${AWS_LIGHTHOUSE_EXPECTED_ACCOUNT_ID:?Expected 12-digit sandbox account ID is required}"
fi

uv run pytest tests/live -m live -v --no-cov
