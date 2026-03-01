# ── Build stage ───────────────────────────────────────────────────────────────
# We use a single stage because the runtime needs the full Python toolchain
# (uv manages the venv) and Node.js (npx for the AWS MCP server).
# python:3.12-slim — pinned to digest for reproducible builds.
# To update: docker pull python:3.12-slim && docker inspect --format='{{index .RepoDigests 0}}' python:3.12-slim
FROM python:3.12-slim@sha256:42f1689d6d6b906c7e829f9d9ec38491550344ac9adc01e464ff9a08df1ffb48

# System packages
#   nodejs / npm  — required by mcp_client.py (npx -y @aws-mcp/server)
#   curl          — used by the compose healthcheck for Ollama
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nodejs \
        npm \
        curl \
    && rm -rf /var/lib/apt/lists/*

# ── uv ────────────────────────────────────────────────────────────────────────
# ghcr.io/astral-sh/uv:latest — pinned to digest for reproducible builds.
# To update: crane digest ghcr.io/astral-sh/uv:latest  (or check GitHub releases)
COPY --from=ghcr.io/astral-sh/uv:latest@sha256:edd1fd89f3e5b005814cc8f777610445d7b7e3ed05361f9ddfae67bebfe8456a /uv /uvx /bin/

# Copy-mode avoids hard-link issues across Docker layer filesystems
ENV UV_LINK_MODE=copy

# ── Non-root user ─────────────────────────────────────────────────────────────
RUN groupadd --gid 1001 lighthouse \
    && useradd --uid 1001 --gid lighthouse --shell /bin/bash \
       --create-home lighthouse

WORKDIR /app

# ── Dependency layer (cached unless pyproject.toml / uv.lock changes) ────────
# README.md is required by hatchling when building the project wheel
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project

# ── Application layer ─────────────────────────────────────────────────────────
COPY aws_lighthouse/ ./aws_lighthouse/
RUN uv sync --frozen --no-dev

# Persistent SQLite directory for cost-trend snapshots
RUN mkdir -p /home/lighthouse/.aws-lighthouse \
    && chown -R lighthouse:lighthouse /app /home/lighthouse/.aws-lighthouse

USER lighthouse

# ── Entrypoint ────────────────────────────────────────────────────────────────
# Default: run the read-only analysis dashboard.
# Override to "shell" to start the interactive agent:
#   docker compose run --rm lighthouse shell
ENTRYPOINT ["uv", "run", "aws-lighthouse"]
CMD ["analyze"]
