"""Custom HTTP chat-route target.

Blocked-detection mirrors the qa-practices-resources adversarial_test.py
(https://github.com/MathiasPaulenko/qa-practices-resources, MIT): a prompt counts
as blocked when the endpoint answers HTTP 400/401/403/422 or returns a refusal
phrase in the answer field. Improvements over the kit: HTTP 5xx and transport
errors are surfaced as errors instead of silently counting as "not blocked".
"""

from __future__ import annotations

import httpx

from ..engine.scoring import is_refusal
from .base import TargetResponse

BLOCKED_STATUSES = {400, 401, 403, 422}
DEFAULT_TIMEOUT_S = 30.0


class HttpChatTarget:
    def __init__(self, config: dict):
        self.url = (config.get("url") or "").strip()
        if not self.url:
            raise ValueError("http_chat target requires a 'url'")
        self.api_key = config.get("api_key") or ""
        self.timeout_s = float(config.get("timeout_s") or DEFAULT_TIMEOUT_S)
        self.prompt_field = config.get("prompt_field") or "prompt"
        self.answer_field = config.get("answer_field") or "answer"

    async def _post(self, payload_text: str) -> TargetResponse:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout_s) as client:
                resp = await client.post(
                    self.url,
                    json={self.prompt_field: payload_text},
                    headers=headers,
                )
        except httpx.ConnectError:
            return TargetResponse(error=f"target not reachable at {self.url}")
        except httpx.TimeoutException:
            return TargetResponse(error=f"request timed out after {self.timeout_s:g}s")
        except Exception as e:
            return TargetResponse(error=str(e))

        if resp.status_code in BLOCKED_STATUSES:
            return TargetResponse(reply="", blocked=True, stage="http")
        if resp.status_code >= 500:
            return TargetResponse(error=f"target returned HTTP {resp.status_code}")
        if resp.status_code != 200:
            return TargetResponse(error=f"unexpected HTTP {resp.status_code}")

        try:
            answer = str(resp.json().get(self.answer_field, ""))
        except ValueError:
            answer = resp.text
        return TargetResponse(
            reply=answer, blocked=is_refusal(answer), stage="none"
        )

    async def query(self, prompt: str) -> TargetResponse:
        return await self._post(prompt)

    async def query_turns(self, turns: list[str]) -> TargetResponse:
        return await self._post("\n".join(turns))
