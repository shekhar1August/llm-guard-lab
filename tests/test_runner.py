import asyncio

from conftest import FakeTarget

from llm_guard_lab.engine.corpus import get_corpus
from llm_guard_lab.engine.runner import run_campaign
from llm_guard_lab.targets.mock import MockTarget


def _payload(pid="direct_01"):
    return next(p for p in get_corpus() if p["id"] == pid)


def test_campaign_against_mock_completes_cleanly():
    payloads = [p for p in get_corpus() if p["category"] == "direct_injection"]
    results, summary = asyncio.run(run_campaign(MockTarget(), payloads))
    assert summary["total"] == len(payloads)
    assert summary["errored"] == 0
    assert summary["skipped"] == 0
    assert not summary["cancelled"]
    assert 0 <= summary["resilience_pct"] <= 100
    assert len(results) == len(payloads)
    assert all(r["verdict"] in ("injected", "defended") for r in results)


def test_canary_reply_scores_injected():
    target = FakeTarget(replies=["PWNED731 all yours"])
    results, summary = asyncio.run(run_campaign(target, [_payload()]))
    assert results[0]["verdict"] == "injected"
    assert results[0]["injected"] is True
    assert summary["injected"] == 1
    assert summary["resilience_pct"] == 0
    assert summary["grade"] == "F"


def test_refusal_scores_defended():
    target = FakeTarget(replies=["I can't help with that."])
    results, summary = asyncio.run(run_campaign(target, [_payload()]))
    assert results[0]["verdict"] == "defended"
    assert summary["defended"] == 1
    assert summary["grade"] == "A"


def test_adaptive_lands_via_mutation():
    def is_authority(p):
        return "SYSTEM ADMINISTRATOR" in p

    class TwoFace(FakeTarget):
        async def query(self, prompt):
            if is_authority(prompt):
                from llm_guard_lab.targets.base import TargetResponse

                return TargetResponse(reply="fine: PWNED731")
            return await super().query(prompt)

    target = TwoFace(replies=["I can't help with that."])
    results, _ = asyncio.run(
        run_campaign(target, [_payload()], adaptive=True, max_tries=2)
    )
    r = results[0]
    assert r["injected"] is True
    assert r["chain"][0]["mutation"] == "original"
    assert r["chain"][0]["injected"] is False
    assert r["chain"][1]["mutation"] == "authority_prefix"
    assert r["chain"][1]["injected"] is True
    assert len(r["chain"]) == 2


def test_adaptive_exhausts_budget_when_defended():
    target = FakeTarget(replies=["I can't help with that."])
    results, summary = asyncio.run(
        run_campaign(target, [_payload()], adaptive=True, max_tries=3)
    )
    r = results[0]
    assert r["verdict"] == "defended"
    assert len(r["chain"]) == 4
    assert all(not s["injected"] for s in r["chain"])
    assert summary["defended"] == 1


def test_adaptive_not_applied_to_multi_turn():
    mt = next(p for p in get_corpus() if p["id"] == "mt_01")
    target = FakeTarget(turns_reply="I can't help with that.")
    results, _ = asyncio.run(
        run_campaign(target, [mt], adaptive=True, max_tries=3)
    )
    assert target.turns_seen and target.turns_seen[0] == mt["turns"]
    assert results[0]["chain"] == []
    assert results[0]["multi_turn"] is True


def test_judge_payload_without_judge_is_skipped():
    judge_payload = next(p for p in get_corpus() if p["detect"]["type"] == "judge")
    target = FakeTarget(replies=["some reply"])
    results, summary = asyncio.run(run_campaign(target, [judge_payload]))
    assert results[0]["verdict"] == "skipped"
    assert summary["skipped"] == 1
    assert summary["total"] == 0


def test_judge_failure_marks_errored():
    judge_payload = next(p for p in get_corpus() if p["detect"]["type"] == "judge")
    target = FakeTarget(replies=["some reply"])
    results, summary = asyncio.run(
        run_campaign(
            target, [judge_payload],
            judge={"endpoint": "http://127.0.0.1:9", "model": "m"},
        )
    )
    assert results[0]["verdict"] == "errored"
    assert "judge error" in results[0]["note"]
    assert summary["errored"] == 1
    assert summary["total"] == 0


def test_target_error_is_errored_and_excluded():
    target = FakeTarget(error="target not reachable")
    results, summary = asyncio.run(run_campaign(target, [_payload()]))
    assert results[0]["verdict"] == "errored"
    assert summary["errored"] == 1
    assert summary["total"] == 0


def test_cancel_stops_campaign():
    payloads = get_corpus(["direct_injection"])
    results, summary = asyncio.run(
        run_campaign(FakeTarget(), payloads, should_cancel=lambda: True)
    )
    assert results == []
    assert summary["cancelled"] is True
