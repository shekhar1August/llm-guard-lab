from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable


@dataclass
class TargetResponse:
    reply: str = ""
    error: str = ""
    blocked: bool | None = None
    stage: str | None = None


@runtime_checkable
class TargetAdapter(Protocol):
    async def query(self, prompt: str) -> TargetResponse: ...

    async def query_turns(self, turns: list[str]) -> TargetResponse: ...


TARGET_TYPES = ("mock", "openai", "http_chat")


def make_target(config: dict[str, Any]) -> TargetAdapter:
    if not isinstance(config, dict):
        raise ValueError("target config must be a JSON object")
    t = config.get("type")
    if t == "mock":
        from .mock import MockTarget

        return MockTarget(config)
    if t == "openai":
        from .openai_compat import OpenAICompatTarget

        return OpenAICompatTarget(config)
    if t == "http_chat":
        from .http_chat import HttpChatTarget

        return HttpChatTarget(config)
    raise ValueError(
        f"unknown target type {t!r}; expected one of {', '.join(TARGET_TYPES)}"
    )


def redact_target_config(config: dict[str, Any]) -> dict[str, Any]:
    out = dict(config)
    if out.get("api_key"):
        out["api_key"] = "***redacted***"
    return out
