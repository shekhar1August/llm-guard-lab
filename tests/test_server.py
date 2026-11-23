import importlib
import os
import time


def _load_app(tmp_path):
    os.environ["LLGL_DB_PATH"] = str(tmp_path / "server.db")
    from fastapi.testclient import TestClient

    from llm_guard_lab.server import app as app_module

    app_module = importlib.reload(app_module)
    return app_module, TestClient


def _wait_for_run(client, run_id, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        run = client.get(f"/api/runs/{run_id}").json()["run"]
        if run["status"] != "running":
            return run
        time.sleep(0.05)
    raise AssertionError(f"run {run_id} did not finish in {timeout}s")


def test_meta_lists_corpus_and_datasets(tmp_path):
    app_module, TestClient = _load_app(tmp_path)
    with TestClient(app_module.app) as client:
        meta = client.get("/api/meta").json()
        assert len(meta["categories"]) == 14
        assert meta["payload_count"] == 114
        assert meta["target_types"] == ["mock", "openai", "http_chat"]
        assert meta["datasets"][0]["cases"] == 8


def test_compliance_run_over_rest(tmp_path):
    app_module, TestClient = _load_app(tmp_path)
    with TestClient(app_module.app) as client:
        resp = client.post("/api/runs", json={
            "mode": "compliance",
            "target": {"type": "mock"},
            "options": {},
        })
        assert resp.status_code == 200
        run_id = resp.json()["run_id"]

        run = _wait_for_run(client, run_id)
        assert run["status"] == "completed"
        assert run["summary"]["passed"] == 8

        detail = client.get(f"/api/runs/{run_id}").json()
        assert len(detail["results"]) == 8
        assert detail["run"]["target_config"] == {"type": "mock"}


def test_unknown_target_type_is_rejected(tmp_path):
    app_module, TestClient = _load_app(tmp_path)
    with TestClient(app_module.app) as client:
        resp = client.post("/api/runs", json={
            "mode": "compliance", "target": {"type": "bogus"}, "options": {},
        })
        assert resp.status_code == 400


def test_reports_over_rest(tmp_path):
    app_module, TestClient = _load_app(tmp_path)
    with TestClient(app_module.app) as client:
        run_id = client.post("/api/runs", json={
            "mode": "compliance", "target": {"type": "mock"}, "options": {},
        }).json()["run_id"]
        _wait_for_run(client, run_id)

        html = client.get(f"/api/runs/{run_id}/report",
                          params={"format": "html"})
        assert html.status_code == 200
        assert html.headers["content-type"].startswith("text/html")
        assert "llm-guard-lab" in html.text

        pdf = client.get(f"/api/runs/{run_id}/report", params={"format": "pdf"})
        assert pdf.status_code == 200
        assert pdf.headers["content-type"] == "application/pdf"
        assert pdf.content[:5] == b"%PDF-"

        js = client.get(f"/api/runs/{run_id}/report", params={"format": "json"})
        assert js.status_code == 200
        assert js.json()["run"]["id"] == run_id

        bad = client.get(f"/api/runs/{run_id}/report", params={"format": "csv"})
        assert bad.status_code == 400


def test_websocket_streams_results_and_done(tmp_path):
    app_module, TestClient = _load_app(tmp_path)
    with TestClient(app_module.app) as client:
        run_id = client.post("/api/runs", json={
            "mode": "compliance", "target": {"type": "mock"}, "options": {},
        }).json()["run_id"]

        events = []
        with client.websocket_connect(f"/ws/runs/{run_id}") as ws:
            while True:
                m = ws.receive_json()
                events.append(m)
                if m["type"] == "done":
                    break
        assert sum(1 for e in events if e["type"] == "result") == 8
        assert events[-1]["status"] == "completed"
        assert events[-1]["summary"]["passed"] == 8
