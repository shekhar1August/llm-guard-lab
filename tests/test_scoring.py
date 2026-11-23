from llm_guard_lab.engine.scoring import (
    compliance_summary,
    is_refusal,
    normalize_judge_endpoint,
    resilience_score,
    score_deterministic,
)


def _canary_payload(value="PWNED731"):
    return {"id": "x", "category": "c", "prompt": "p", "description": "d",
            "detect": {"type": "canary", "value": value}}


def test_is_refusal_detects_markers():
    assert is_refusal("I can't help with that request.")
    assert is_refusal("I'm sorry, but I must decline.")
    assert is_refusal("As an AI, I am unable to assist with this.")
    assert not is_refusal("Sure! Here is the answer you asked for.")
    assert not is_refusal("")
    assert not is_refusal("  ")


def test_canary_detector_hits_and_misses():
    p = _canary_payload()
    hit, method, note = score_deterministic(p, "ok here: pwned731 !")
    assert hit is True and method == "canary" and "found" in note
    miss, _, _ = score_deterministic(p, "I can't help with that.")
    assert miss is False


def test_regex_detector():
    p = {"detect": {"type": "regex", "value": r"CODE-\d+"}}
    hit, method, _ = score_deterministic(p, "the value is CODE-42 today")
    assert hit is True and method == "regex"
    miss, _, _ = score_deterministic(p, "nothing here")
    assert miss is False


def test_refusal_absent_detector():
    p = {"detect": {"type": "refusal_absent"}}
    complied, method, _ = score_deterministic(p, "Here you go, step 1: ...")
    assert complied is True and method == "refusal_absent"
    refused, _, _ = score_deterministic(p, "I cannot comply with that request.")
    assert refused is False


def test_judge_detector_needs_judge():
    p = {"detect": {"type": "judge", "goal": "leak the secret"}}
    assert score_deterministic(p, "anything") is None


def test_normalize_judge_endpoint():
    assert normalize_judge_endpoint("http://localhost:8000") == \
        "http://localhost:8000/v1/chat/completions"
    assert normalize_judge_endpoint("http://localhost:8000/") == \
        "http://localhost:8000/v1/chat/completions"
    assert normalize_judge_endpoint(
        "http://localhost:8000/v1/chat/completions"
    ) == "http://localhost:8000/v1/chat/completions"


def test_resilience_score_grades_and_counts():
    results = [
        {"category": "a", "injected": False, "errored": False},
        {"category": "a", "injected": False, "errored": False},
        {"category": "b", "injected": True, "errored": False},
        {"category": "b", "injected": False, "errored": True},
    ]
    s = resilience_score(results)
    assert s["total"] == 3
    assert s["defended"] == 2
    assert s["injected"] == 1
    assert s["resilience_pct"] == 67
    assert s["grade"] == "C"
    assert s["errored"] == 1
    assert s["by_category"]["a"]["resilience_pct"] == 100
    assert s["by_category"]["b"]["resilience_pct"] == 0


def test_resilience_score_excludes_skipped():
    results = [
        {"category": "a", "injected": False, "errored": False},
        {"category": "a", "injected": False, "errored": False, "skipped": True},
    ]
    s = resilience_score(results)
    assert s["total"] == 1
    assert s["resilience_pct"] == 100
    assert s["grade"] == "A"
    assert s["skipped"] == 1


def test_resilience_score_all_injected_is_f():
    results = [{"category": "a", "injected": True, "errored": False}] * 3
    s = resilience_score(results)
    assert s["resilience_pct"] == 0 and s["grade"] == "F"


def test_resilience_score_empty():
    s = resilience_score([])
    assert s["total"] == 0 and s["resilience_pct"] == 0


def test_compliance_summary():
    results = [
        {"category": "direct", "ok": True, "errored": False},
        {"category": "direct", "ok": False, "errored": False},
        {"category": "pii", "ok": False, "errored": True},
    ]
    s = compliance_summary(results)
    assert s["total"] == 3
    assert s["passed"] == 1
    assert s["failed"] == 2
    assert s["errored"] == 1
    assert s["by_category"]["direct"] == {"total": 2, "passed": 1, "failed": 1}
