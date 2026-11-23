"""Offline mock guarded pipeline.

Vendored and adapted from the qa-practices-resources llm-guardrails-testing
checklist kit (https://github.com/MathiasPaulenko/qa-practices-resources, MIT) —
see THIRD_PARTY_NOTICES.md.

Applies the policies from guardrails_config.json in front of a canned "model"
so the adversarial suite can run without a live endpoint. Policy semantics match
the kit exactly: a keyword injection filter runs on the input, the canned model
echoes "repeat"/"echo" prompts, and a PII regex filter runs on the output. The
"classifier" policy type in the config is a documented stub, as in the kit.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .base import TargetResponse

DEFAULT_POLICY_PATH = (
    Path(__file__).resolve().parent.parent / "datasets" / "guardrails_config.json"
)

SAFE_REPLY = "I can't help with that request."


class MockTarget:
    def __init__(self, config: dict[str, Any] | None = None):
        config = config or {}
        policy_path = config.get("policy_path")
        path = Path(policy_path) if policy_path else DEFAULT_POLICY_PATH
        self.config = json.loads(path.read_text(encoding="utf-8"))
        self.regex_rules: list[re.Pattern] = []
        self.keyword_rules: list[str] = []
        for policy in self.config["policies"]:
            if policy["type"] == "regex":
                self.regex_rules.extend(re.compile(p) for p in policy["patterns"])
            elif policy["type"] == "keyword":
                self.keyword_rules.extend(p.lower() for p in policy["patterns"])

    def guarded_chat(self, prompt: str) -> dict:
        """Simulates: sanitize -> injection check -> model -> PII filter -> reply."""
        lowered = prompt.lower()

        if any(k in lowered for k in self.keyword_rules):
            return {"answer": SAFE_REPLY, "blocked": True, "stage": "input"}

        if "repeat" in lowered or "echo" in lowered:
            answer = f"You said: {prompt}"
        else:
            answer = "This is a safe, on-topic response from the mock model."

        for rule in self.regex_rules:
            if rule.search(answer):
                return {"answer": SAFE_REPLY, "blocked": True, "stage": "output"}

        return {"answer": answer, "blocked": False, "stage": "none"}

    async def query(self, prompt: str) -> TargetResponse:
        r = self.guarded_chat(prompt)
        return TargetResponse(
            reply=r["answer"], error="", blocked=r["blocked"], stage=r["stage"]
        )

    async def query_turns(self, turns: list[str]) -> TargetResponse:
        return await self.query("\n".join(turns))
