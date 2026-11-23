from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ..engine import compliance as compliance_mod
from ..engine import runner as runner_mod
from ..engine.corpus import CATEGORIES, get_corpus
from ..store import Store, default_db_path
from ..targets.base import TARGET_TYPES, make_target

STATIC_DIR = Path(__file__).resolve().parent / "static"


class TargetSpec(BaseModel):
    type: str
    endpoint: str | None = None
    url: str | None = None
    model: str | None = None
    api_key: str | None = None
    timeout_s: float | None = None
    policy_path: str | None = None
    system_prompt: str | None = None
    prompt_field: str | None = None
    answer_field: str | None = None


class RunOptions(BaseModel):
    dataset: str | None = None
    categories: list[str] = Field(default_factory=list)
    adaptive: bool = False
    max_tries: int = 5
    judge: str | None = None
    judge_model: str = "gpt-4o-mini"


class RunSpec(BaseModel):
    mode: str
    target: TargetSpec
    options: RunOptions = RunOptions()


class RunManager:
    def __init__(self) -> None:
        self._runs: dict[int, dict] = {}

    def register(self, run_id: int) -> None:
        self._runs[run_id] = {"subscribers": [], "cancel": False}

    def subscribe(self, run_id: int) -> asyncio.Queue:
        entry = self._runs.setdefault(run_id, {"subscribers": [], "cancel": False})
        q: asyncio.Queue = asyncio.Queue()
        entry["subscribers"].append(q)
        return q

    def unsubscribe(self, run_id: int, q: asyncio.Queue) -> None:
        entry = self._runs.get(run_id)
        if entry and q in entry["subscribers"]:
            entry["subscribers"].remove(q)

    def publish(self, run_id: int, event: dict) -> None:
        entry = self._runs.get(run_id)
        if not entry:
            return
        for q in entry["subscribers"]:
            q.put_nowait(event)

    def set_cancel(self, run_id: int) -> bool:
        entry = self._runs.get(run_id)
        if entry is None:
            return False
        entry["cancel"] = True
        return True

    def is_cancelled(self, run_id: int) -> bool:
        entry = self._runs.get(run_id)
        return bool(entry and entry["cancel"])

    def cleanup(self, run_id: int) -> None:
        self._runs.pop(run_id, None)


app = FastAPI(title="llm-guard-lab", version="0.1.0")
store = Store(default_db_path())
manager = RunManager()


def _target_dict(t: TargetSpec) -> dict[str, Any]:
    d = t.model_dump(exclude_none=True)
    return {k: v for k, v in d.items() if v is not None}


async def _execute_run(run_id: int, spec: RunSpec) -> None:
    def on_result(r: dict) -> None:
        store.add_result(run_id, r)
        manager.publish(run_id, {"type": "result", "result": r})

    try:
        target = make_target(_target_dict(spec.target))
        if spec.mode == "compliance":
            cases = compliance_mod.load_dataset(spec.options.dataset)
            _, summary = await compliance_mod.run_suite(
                target, cases, on_result=on_result,
                should_cancel=lambda: manager.is_cancelled(run_id),
            )
        else:
            payloads = get_corpus(spec.options.categories or None)
            judge = (
                {"endpoint": spec.options.judge,
                 "model": spec.options.judge_model}
                if spec.options.judge else None
            )
            _, summary = await runner_mod.run_campaign(
                target, payloads,
                adaptive=spec.options.adaptive,
                max_tries=spec.options.max_tries,
                judge=judge,
                on_result=on_result,
                should_cancel=lambda: manager.is_cancelled(run_id),
            )
    except Exception as e:
        store.finish_run(run_id, "failed", None)
        manager.publish(run_id, {"type": "done", "status": "failed", "error": str(e)})
        manager.cleanup(run_id)
        return

    status = "cancelled" if summary.get("cancelled") else "completed"
    store.finish_run(run_id, status, summary)
    manager.publish(run_id, {"type": "done", "status": status, "summary": summary})
    manager.cleanup(run_id)


@app.post("/api/runs")
async def start_run(spec: RunSpec) -> dict:
    if spec.mode not in ("compliance", "campaign"):
        raise HTTPException(400, "mode must be 'compliance' or 'campaign'")
    if spec.target.type not in TARGET_TYPES:
        raise HTTPException(400, f"target type must be one of {TARGET_TYPES}")
    try:
        make_target(_target_dict(spec.target))
    except ValueError as e:
        raise HTTPException(400, str(e))

    target_config = _target_dict(spec.target)
    run_id = store.create_run(
        spec.mode, target_config, spec.options.model_dump(exclude_none=True)
    )
    manager.register(run_id)
    asyncio.create_task(_execute_run(run_id, spec))
    return {"run_id": run_id}


@app.get("/api/runs")
async def list_runs() -> dict:
    return {"runs": store.list_runs()}


@app.get("/api/runs/{run_id}")
async def get_run(run_id: int) -> dict:
    run = store.get_run(run_id)
    if run is None:
        raise HTTPException(404, f"run {run_id} not found")
    return {"run": run, "results": store.get_results(run_id)}


@app.post("/api/runs/{run_id}/cancel")
async def cancel_run(run_id: int) -> dict:
    run = store.get_run(run_id)
    if run is None:
        raise HTTPException(404, f"run {run_id} not found")
    if run["status"] != "running":
        return {"run_id": run_id, "cancelled": False, "reason": "not running"}
    ok = manager.set_cancel(run_id)
    return {"run_id": run_id, "cancelled": ok}


@app.get("/api/runs/{run_id}/report")
async def run_report(run_id: int, format: str = "json") -> Response:
    from ..reporting import build_report, render_html, render_pdf, to_json_bytes

    if format not in ("json", "html", "pdf"):
        raise HTTPException(400, "format must be json, html, or pdf")
    report = build_report(store, run_id)
    if report is None:
        raise HTTPException(404, f"run {run_id} not found")
    if format == "json":
        return Response(
            to_json_bytes(report), media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="run-{run_id}.json"'},
        )
    if format == "html":
        return Response(
            render_html(report), media_type="text/html",
        )
    return Response(
        render_pdf(report), media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="run-{run_id}-report.pdf"'},
    )


@app.get("/api/meta")
async def meta() -> dict:
    counts: dict[str, int] = {}
    for p in get_corpus():
        counts[p["category"]] = counts.get(p["category"], 0) + 1
    cases = compliance_mod.load_dataset()
    return {
        "target_types": list(TARGET_TYPES),
        "categories": [
            {"key": k, "label": label, "count": counts.get(k, 0)}
            for k, label in CATEGORIES.items()
        ],
        "payload_count": sum(counts.values()),
        "datasets": [
            {"id": "default", "label": "checklist kit (bundled)", "cases": len(cases)}
        ],
    }


@app.websocket("/ws/runs/{run_id}")
async def run_ws(ws: WebSocket, run_id: int) -> None:
    run = store.get_run(run_id)
    if run is None:
        await ws.accept()
        await ws.send_json({"type": "error", "error": f"run {run_id} not found"})
        await ws.close()
        return

    await ws.accept()
    q = manager.subscribe(run_id)
    max_seq = 0
    try:
        for r in store.get_results(run_id):
            max_seq = max(max_seq, r["seq"])
            await ws.send_json({"type": "result", "result": r})
        if run["status"] != "running":
            await ws.send_json(
                {"type": "done", "status": run["status"], "summary": run["summary"]}
            )
            return

        while True:
            event = await asyncio.wait_for(q.get(), timeout=30.0)
            if event["type"] == "result" and event["result"].get("seq", 0) <= max_seq:
                continue
            await ws.send_json(event)
            if event["type"] == "done":
                return
    except asyncio.TimeoutError:
        run = store.get_run(run_id)
        if run and run["status"] != "running":
            await ws.send_json(
                {"type": "done", "status": run["status"], "summary": run["summary"]}
            )
        return
    except WebSocketDisconnect:
        return
    finally:
        manager.unsubscribe(run_id, q)


app.mount(
    "/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static"
)
