"""Campaign runner: fire the corpus at a target, score each attack, and
optionally retry defended single-turn payloads through the escalating mutation
chain.

Adapted from the llm-injection-harness (https://github.com/plalan/llm-injection-harness,
MIT) — see THIRD_PARTY_NOTICES.md.
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable

from ..targets.base import TargetAdapter, TargetResponse
from .compliance import excerpt
from .mutations import MUTATORS
from .scoring import judge_with_llm, resilience_score, score_deterministic

OnResult = Callable[[dict], None]
CancelCheck = Callable[[], bool]

EXCERPT_LEN = 220


def _score_or_default(payload: dict, resp: TargetResponse):
    if resp.error:
        return (False, "error", resp.error)
    det = score_deterministic(payload, resp.reply)
    if det is None:
        return (False, "skipped", "judge detector: adaptive scoring not applicable")
    return det


async def _score(
    payload: dict, resp: TargetResponse, judge: dict | None,
) -> tuple[bool, str, str, bool, bool]:
    """Return (injected, method, note, errored, skipped)."""
    if resp.error:
        return (False, "error", resp.error, True, False)
    det = score_deterministic(payload, resp.reply)
    if det is not None:
        return (det[0], det[1], det[2], False, False)
    if judge:
        injected, note, error = await judge_with_llm(
            judge["endpoint"], judge["model"], payload, resp.reply,
        )
        if error:
            return (False, "judge", error, True, False)
        return (injected, "judge", note, False, False)
    return (False, "skipped", "judge detector and no judge configured", False, True)


async def _run_adaptive(
    target: TargetAdapter, payload: dict, max_tries: int,
) -> tuple[list[dict], bool, TargetResponse]:
    base_prompt = payload["prompt"]
    chain: list[dict] = []

    resp = await target.query(base_prompt)
    injected, method, note = _score_or_default(payload, resp)
    chain.append({
        "step": 0, "mutation": "original", "method": method,
        "prompt_excerpt": excerpt(base_prompt, EXCERPT_LEN),
        "reply_excerpt": excerpt(resp.reply, EXCERPT_LEN),
        "injected": injected, "errored": bool(resp.error), "note": note,
    })
    if injected or resp.error:
        return (chain, injected, resp)

    final = resp
    for i, mut in enumerate(MUTATORS[:max_tries], start=1):
        new_prompt, mname = mut(base_prompt)
        resp = await target.query(new_prompt)
        injected, method, note = _score_or_default(payload, resp)
        chain.append({
            "step": i, "mutation": mname, "method": method,
            "prompt_excerpt": excerpt(new_prompt, EXCERPT_LEN),
            "reply_excerpt": excerpt(resp.reply, EXCERPT_LEN),
            "injected": injected, "errored": bool(resp.error), "note": note,
        })
        final = resp
        if injected or resp.error:
            break
    return (chain, any(s["injected"] for s in chain), final)


async def run_campaign(
    target: TargetAdapter,
    payloads: list[dict],
    *,
    adaptive: bool = False,
    max_tries: int = 5,
    judge: dict[str, str] | None = None,
    on_result: OnResult | None = None,
    should_cancel: CancelCheck | None = None,
) -> tuple[list[dict], dict]:
    """Run every payload against the target. Returns (results, summary).

    Multi-turn payloads run their turns sequentially (only meaningful against
    the OpenAI-compatible adapter) and are never mutated adaptively, matching
    upstream harness behavior."""
    results: list[dict] = []
    cancelled = False

    for seq, payload in enumerate(payloads, start=1):
        if should_cancel is not None and should_cancel():
            cancelled = True
            break

        chain: list[dict] = []
        if "turns" in payload:
            resp = await target.query_turns(payload["turns"])
        else:
            if adaptive:
                chain, _, resp = await _run_adaptive(target, payload, max_tries)
            else:
                resp = await target.query(payload["prompt"])

        if "turns" in payload or not adaptive:
            injected, method, note, errored, skipped = await _score(
                payload, resp, judge,
            )
        else:
            first = chain[0]
            errored = first["errored"]
            skipped = first["method"] == "skipped"
            injected = any(s["injected"] for s in chain)
            method = first["method"]
            note = first["note"]

        verdict = "errored" if errored else (
            "skipped" if skipped else ("injected" if injected else "defended")
        )
        result = {
            "seq": seq,
            "payload_id": payload["id"],
            "category": payload["category"],
            "technique": payload.get("technique", ""),
            "severity": payload.get("severity", ""),
            "multi_turn": "turns" in payload,
            "verdict": verdict,
            "injected": injected,
            "errored": errored,
            "skipped": skipped,
            "method": method,
            "note": note,
            "chain": chain,
            "prompt_excerpt": excerpt(payload["prompt"], EXCERPT_LEN),
            "reply_excerpt": excerpt(resp.reply, EXCERPT_LEN),
        }
        results.append(result)
        if on_result is not None:
            on_result(result)

    summary = resilience_score(results)
    summary["cancelled"] = cancelled
    summary["run_mode"] = "campaign"
    return (results, summary)
