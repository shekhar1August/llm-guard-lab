import asyncio
import json

from conftest import FakeTarget

from llm_guard_lab.engine.compliance import load_dataset, run_suite
from llm_guard_lab.targets.mock import MockTarget


def test_checklist_suite_passes_against_mock():
    results, summary = asyncio.run(
        run_suite(MockTarget(), load_dataset())
    )
    assert summary["total"] == 8
    assert summary["passed"] == 8
    assert summary["failed"] == 0
    assert summary["errored"] == 0
    assert all(r["ok"] for r in results)


def test_deviation_is_flagged():
    cases = load_dataset()
    target = FakeTarget(blocked=[False] * len(cases))
    results, summary = asyncio.run(run_suite(target, cases))
    blocked_expected = [c for c in cases if c["expect_blocked"]]
    not_blocked_expected = [c for c in cases if not c["expect_blocked"]]
    assert summary["passed"] == len(not_blocked_expected)
    assert summary["failed"] == len(blocked_expected)
    first_blocked_case = next(
        r for r in results if r["payload_id"] == blocked_expected[0]["id"]
    )
    assert first_blocked_case["ok"] is False


def test_reply_only_target_blocked_derived_from_refusal():
    cases = [
        {"id": "t-1", "category": "x", "prompt": "p", "expect_blocked": True},
        {"id": "t-2", "category": "x", "prompt": "p", "expect_blocked": False},
    ]
    target = FakeTarget(
        replies=["I can't help with that request.", "Sure, here is the answer."],
        blocked=None,
    )
    results, summary = asyncio.run(run_suite(target, cases))
    assert results[0]["blocked"] is True and results[0]["ok"] is True
    assert results[1]["blocked"] is False and results[1]["ok"] is True
    assert summary["passed"] == 2


def test_target_error_marks_case_errored():
    cases = [{"id": "e-1", "category": "x", "prompt": "p", "expect_blocked": True}]
    target = FakeTarget(error="target not reachable")
    results, summary = asyncio.run(run_suite(target, cases))
    assert results[0]["verdict"] == "errored"
    assert results[0]["blocked"] is None
    assert results[0]["ok"] is False
    assert summary["errored"] == 1
    assert summary["failed"] == 1


def test_cancel_stops_suite():
    cases = load_dataset()
    results, summary = asyncio.run(
        run_suite(FakeTarget(blocked=[False] * 8), cases, should_cancel=lambda: True)
    )
    assert results == []
    assert summary["cancelled"] is True


def test_load_dataset_rejects_invalid_entries(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps([{"id": "x", "prompt": "p"}]), encoding="utf-8")
    try:
        load_dataset(bad)
        raise AssertionError("expected ValueError")
    except ValueError as e:
        assert "expect_blocked" in str(e)


def test_load_dataset_rejects_non_array(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"not": "a list"}), encoding="utf-8")
    try:
        load_dataset(bad)
        raise AssertionError("expected ValueError")
    except ValueError as e:
        assert "non-empty JSON array" in str(e)


def test_load_dataset_missing_file(tmp_path):
    try:
        load_dataset(tmp_path / "nope.json")
        raise AssertionError("expected FileNotFoundError")
    except FileNotFoundError:
        pass
