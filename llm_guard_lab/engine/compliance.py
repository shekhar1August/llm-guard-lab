"""Compliance suite runner: expected-verdict datasets against a target.

Modeled on the qa-practices-resources llm-guardrails-testing checklist kit
(https://github.com/MathiasPaulenko/qa-practices-resources, MIT) — see
THIRD_PARTY_NOTICES.md. Each case carries an expected `blocked` verdict; a run
passes when every case matches its expectation (refusals count as blocked for
targets that only return reply text).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from ..targets.base import TargetAdapter
from .scoring import is_refusal

DEFAULT_DATASET_PATH = (
    Path(__file__).resolve().parent.parent / "datasets" / "adversarial_prompts.json"
)

REQUIRED_CASE_FIELDS = ("id", "category", "prompt", "expect_blocked")

OnResult = Callable[[dict], None]


def excerpt(text: str, limit: int = 220) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def load_dataset(path: str | Path | None = None) -> list[dict]:
    p = Path(path) if path else DEFAULT_DATASET_PATH
    if not p.exists():
        raise FileNotFoundError(f"dataset not found: {p}")
    cases = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(cases, list) or not cases:
        raise ValueError(f"dataset {p} must be a non-empty JSON array of cases")
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError(f"dataset {p}: every case must be a JSON object")
        missing = [f for f in REQUIRED_CASE_FIELDS if f not in case]
        if missing:
            raise ValueError(
                f"dataset {p}: case {case.get('id', '?')} missing fields: "
                + ", ".join(missing)
            )
        if not isinstance(case["expect_blocked"], bool):
            raise ValueError(
                f"dataset {p}: case {case['id']} field 'expect_blocked' must be "
                "true or false"
            )
    return cases


async def run_suite(
    target: TargetAdapter,
    cases: list[dict],
    *,
    on_result: OnResult | None = None,
    should_cancel: Callable[[], bool] | None = None,
) -> tuple[list[dict], dict]:
    from .scoring import compliance_summary

    results: list[dict] = []
    cancelled = False

    for seq, case in enumerate(cases, start=1):
        if should_cancel is not None and should_cancel():
            cancelled = True
            break

        resp = await target.query(case["prompt"])
        if resp.error:
            blocked: bool | None = None
            ok: bool | None = False
            verdict = "errored"
        else:
            if resp.blocked is not None:
                blocked = resp.blocked
            else:
                blocked = is_refusal(resp.reply)
            ok = blocked == case["expect_blocked"]
            verdict = "pass" if ok else "fail"

        result = {
            "seq": seq,
            "payload_id": case["id"],
            "category": case["category"],
            "expected": case["expect_blocked"],
            "blocked": blocked,
            "ok": ok,
            "verdict": verdict,
            "stage": resp.stage,
            "injected": None,
            "errored": bool(resp.error),
            "note": resp.error,
            "prompt_excerpt": excerpt(case["prompt"]),
            "reply_excerpt": excerpt(resp.reply),
        }
        results.append(result)
        if on_result is not None:
            on_result(result)

    summary = compliance_summary(results)
    summary["cancelled"] = cancelled
    summary["run_mode"] = "compliance"
    return (results, summary)
