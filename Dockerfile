# ── Build stage ───────────────────────────────────────────────────────────────
# We use a single stage because the runtime needs the full Python toolchain
# (uv manages the venv) and Node.js (npx for the AWS MCP server).
FROM python:3.12-slim

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
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Copy-mode avoids hard-link issues across Docker layer filesystems
ENV UV_LINK_MODE=copy

WORKDIR /app

# ── Dependency layer (cached unless pyproject.toml / uv.lock changes) ────────
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# ── Application layer ─────────────────────────────────────────────────────────
COPY aws_lighthouse/ ./aws_lighthouse/
RUN uv sync --frozen --no-dev

# Persistent SQLite directory for cost-trend snapshots
RUN mkdir -p /root/.aws-lighthouse

# ── Entrypoint ────────────────────────────────────────────────────────────────
# Default: run the read-only analysis dashboard.
# Override to "shell" to start the interactive agent:
#   docker compose run --rm lighthouse shell
ENTRYPOINT ["uv", "run", "aws-lighthouse"]
CMD ["analyze"]
