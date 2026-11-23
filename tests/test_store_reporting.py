import json

from llm_guard_lab.reporting import (
    build_report,
    render_html,
    render_pdf,
    to_json_bytes,
)
from llm_guard_lab.store import Store
from llm_guard_lab.targets.base import redact_target_config


def _store(tmp_path):
    return Store(tmp_path / "test.db")


def _campaign_result(seq=1, verdict="injected"):
    return {
        "seq": seq, "payload_id": "direct_01", "category": "direct_injection",
        "technique": "t", "severity": "high", "multi_turn": False,
        "verdict": verdict, "injected": verdict == "injected",
        "errored": False, "skipped": False, "method": "canary", "note": "canary found",
        "chain": [{"step": 0, "mutation": "original", "injected": verdict == "injected"}],
        "prompt_excerpt": "p", "reply_excerpt": "r",
    }


def _compliance_result(seq=1, ok=True):
    return {
        "seq": seq, "payload_id": "inj-001", "category": "direct-injection",
        "expected": True, "blocked": True, "ok": ok,
        "verdict": "pass" if ok else "fail", "stage": "input", "errored": False,
        "note": "", "prompt_excerpt": "p", "reply_excerpt": "r",
    }


def test_run_roundtrip(tmp_path):
    store = _store(tmp_path)
    run_id = store.create_run(
        "campaign", {"type": "openai", "api_key": "sk-secret"}, {"adaptive": True}
    )
    store.add_result(run_id, _campaign_result(1, "defended"))
    store.add_result(run_id, _campaign_result(2, "injected"))
    store.finish_run(run_id, "completed", {"resilience_pct": 50, "grade": "D"})

    run = store.get_run(run_id)
    assert run["mode"] == "campaign"
    assert run["status"] == "completed"
    assert run["summary"]["grade"] == "D"
    assert run["target_config"]["api_key"] == "***redacted***"
    assert run["options"] == {"adaptive": True}

    results = store.get_results(run_id)
    assert [r["seq"] for r in results] == [1, 2]
    assert results[0]["injected"] is False
    assert results[1]["injected"] is True
    assert results[1]["chain"][0]["step"] == 0

    runs = store.list_runs()
    assert len(runs) == 1 and runs[0]["id"] == run_id
    store.close()


def test_compliance_nullable_roundtrip(tmp_path):
    store = _store(tmp_path)
    run_id = store.create_run("compliance", {"type": "mock"}, {})
    store.add_result(run_id, _compliance_result(1, ok=True))
    store.add_result(run_id, _compliance_result(2, ok=False))
    results = store.get_results(run_id)
    assert results[0]["injected"] is None
    assert results[0]["expected"] is True
    assert results[0]["blocked"] is True
    assert results[0]["ok"] is True
    assert results[1]["ok"] is False
    store.close()


def test_redact_target_config():
    out = redact_target_config({"type": "openai", "api_key": "k", "model": "m"})
    assert out["api_key"] == "***redacted***"
    assert out["model"] == "m"
    assert redact_target_config({"type": "mock"}) == {"type": "mock"}


def _seeded_run(store, mode, results, summary):
    run_id = store.create_run(mode, {"type": "mock"}, {})
    for i, r in enumerate(results, start=1):
        store.add_result(run_id, r)
    store.finish_run(run_id, "completed", summary)
    return run_id


def test_json_report_roundtrip(tmp_path):
    store = _store(tmp_path)
    run_id = _seeded_run(
        store, "campaign", [_campaign_result()], {"resilience_pct": 0, "grade": "F"}
    )
    report = build_report(store, run_id)
    data = json.loads(to_json_bytes(report))
    assert data["run"]["id"] == run_id
    assert data["run"]["summary"]["grade"] == "F"
    assert data["results"][0]["payload_id"] == "direct_01"
    assert build_report(store, 999) is None
    store.close()


def test_html_reports_render_both_modes(tmp_path):
    store = _store(tmp_path)
    camp = _seeded_run(
        store, "campaign", [_campaign_result()],
        {"resilience_pct": 0, "grade": "F", "total": 1, "defended": 0,
         "injected": 1, "errored": 0, "skipped": 0, "by_category": {}},
    )
    comp = _seeded_run(
        store, "compliance", [_compliance_result()],
        {"passed": 1, "failed": 0, "errored": 0, "total": 1, "pass_rate_pct": 100,
         "by_category": {}},
    )
    for run_id, expect in ((camp, "resilience"), (comp, "pass rate")):
        html = render_html(build_report(store, run_id))
        assert "llm-guard-lab" in html
        assert expect in html
        assert "<script" not in html
    store.close()


def test_pdf_reports_render_both_modes(tmp_path):
    store = _store(tmp_path)
    camp = _seeded_run(
        store, "campaign", [_campaign_result()],
        {"resilience_pct": 0, "grade": "F", "total": 1, "defended": 0,
         "injected": 1, "errored": 0, "skipped": 0, "by_category": {}},
    )
    comp = _seeded_run(
        store, "compliance", [_compliance_result()],
        {"passed": 1, "failed": 0, "errored": 0, "total": 1, "pass_rate_pct": 100,
         "by_category": {}},
    )
    for run_id in (camp, comp):
        pdf = render_pdf(build_report(store, run_id))
        assert pdf[:5] == b"%PDF-"
        assert len(pdf) > 500
    store.close()
