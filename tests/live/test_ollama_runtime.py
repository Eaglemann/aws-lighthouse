"""Opt-in live check for the configured Ollama runtime and model."""

import os

import pytest

from aws_lighthouse.agent import check_ollama_runtime, create_agent_graph

pytestmark = [pytest.mark.integration, pytest.mark.live]


def test_configured_ollama_runtime_and_graph_compile():
    if os.environ.get("AWS_LIGHTHOUSE_LIVE_OLLAMA") != "1":
        pytest.skip("set AWS_LIGHTHOUSE_LIVE_OLLAMA=1 to opt in")

    runtime = check_ollama_runtime(timeout_seconds=5.0)
    assert runtime["ok"], runtime
    assert create_agent_graph() is not None
