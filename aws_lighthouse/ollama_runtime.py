"""Ollama endpoint and required-model health checks."""

import json
import os
from typing import Literal, TypedDict
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import urlopen

OLLAMA_DEFAULT_HOST = "http://localhost:11434"
OLLAMA_MODEL_NAME = "gpt-oss:120b-cloud"
OllamaRuntimeReason = Literal["ok", "unavailable", "invalid_response", "model_missing"]


class OllamaRuntimeStatus(TypedDict):
    ok: bool
    reason: OllamaRuntimeReason
    host: str
    model: str
    detail: str


def get_ollama_host() -> str:
    return os.getenv("OLLAMA_HOST", OLLAMA_DEFAULT_HOST).rstrip("/")


def check_ollama_runtime(timeout_seconds: float = 2.0) -> OllamaRuntimeStatus:
    """Probe the Ollama runtime and verify the configured model is present."""
    host = get_ollama_host()
    model = OLLAMA_MODEL_NAME
    parsed_host = urlsplit(host)
    if parsed_host.scheme not in {"http", "https"}:
        return {
            "ok": False,
            "reason": "unavailable",
            "host": host,
            "model": model,
            "detail": (
                "OLLAMA_HOST must use http or https; "
                f"received scheme '{parsed_host.scheme or 'none'}'."
            ),
        }
    try:
        with urlopen(  # noqa: S310 - URL scheme is restricted above
            f"{host}/api/tags", timeout=timeout_seconds
        ) as response:
            status = getattr(response, "status", response.getcode())
            payload_bytes = response.read()
    except HTTPError as exc:
        return {
            "ok": False,
            "reason": "unavailable",
            "host": host,
            "model": model,
            "detail": f"HTTP {exc.code}: {exc.reason}",
        }
    except URLError as exc:
        return {
            "ok": False,
            "reason": "unavailable",
            "host": host,
            "model": model,
            "detail": str(exc.reason),
        }
    except OSError as exc:
        return {
            "ok": False,
            "reason": "unavailable",
            "host": host,
            "model": model,
            "detail": str(exc),
        }

    if status != 200:
        return {
            "ok": False,
            "reason": "unavailable",
            "host": host,
            "model": model,
            "detail": f"Unexpected HTTP status: {status}",
        }

    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {
            "ok": False,
            "reason": "invalid_response",
            "host": host,
            "model": model,
            "detail": f"Invalid response from Ollama: {exc}",
        }

    raw_models = payload.get("models")
    if not isinstance(raw_models, list):
        return {
            "ok": False,
            "reason": "invalid_response",
            "host": host,
            "model": model,
            "detail": "The /api/tags response did not include a models list.",
        }

    installed_models = [
        model_name
        for entry in raw_models
        if isinstance(entry, dict)
        for model_name in [entry.get("name") or entry.get("model")]
        if isinstance(model_name, str)
    ]
    if model not in installed_models:
        detail = (
            "Installed models: " + ", ".join(installed_models[:5])
            if installed_models
            else "Ollama is reachable but reported no installed models."
        )
        return {
            "ok": False,
            "reason": "model_missing",
            "host": host,
            "model": model,
            "detail": detail,
        }

    return {
        "ok": True,
        "reason": "ok",
        "host": host,
        "model": model,
        "detail": "ready",
    }
