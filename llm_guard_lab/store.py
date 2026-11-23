from __future__ import annotations

import json
import os
import sqlite3
import threading
from pathlib import Path
from typing import Any

from .targets.base import redact_target_config

DEFAULT_DB_DIR = "data"
DEFAULT_DB_NAME = "llm-guard-lab.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    mode TEXT NOT NULL,
    status TEXT NOT NULL,
    target_config TEXT NOT NULL,
    options TEXT NOT NULL,
    summary TEXT
);
CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id),
    seq INTEGER NOT NULL,
    payload_id TEXT NOT NULL,
    category TEXT NOT NULL,
    technique TEXT DEFAULT '',
    severity TEXT DEFAULT '',
    multi_turn INTEGER DEFAULT 0,
    verdict TEXT NOT NULL,
    injected INTEGER,
    errored INTEGER DEFAULT 0,
    skipped INTEGER DEFAULT 0,
    expected INTEGER,
    blocked INTEGER,
    ok INTEGER,
    method TEXT DEFAULT '',
    stage TEXT,
    note TEXT DEFAULT '',
    chain TEXT DEFAULT '[]',
    prompt_excerpt TEXT DEFAULT '',
    reply_excerpt TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_results_run ON results(run_id);
"""


def default_db_path() -> Path:
    env = os.environ.get("LLGL_DB_PATH")
    if env:
        return Path(env)
    return Path(DEFAULT_DB_DIR) / DEFAULT_DB_NAME


class Store:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else default_db_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock, self._conn:
            self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def create_run(self, mode: str, target_config: dict, options: dict) -> int:
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self._lock, self._conn:
            cur = self._conn.execute(
                "INSERT INTO runs (started_at, mode, status, target_config, options) "
                "VALUES (?, ?, 'running', ?, ?)",
                (
                    now,
                    mode,
                    json.dumps(redact_target_config(target_config)),
                    json.dumps(options, sort_keys=True),
                ),
            )
            return int(cur.lastrowid)

    def finish_run(self, run_id: int, status: str, summary: dict | None = None) -> None:
        from datetime import datetime, timezone

        finished = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE runs SET finished_at = ?, status = ?, summary = ? WHERE id = ?",
                (
                    finished,
                    status,
                    json.dumps(summary) if summary is not None else None,
                    run_id,
                ),
            )

    def add_result(self, run_id: int, result: dict) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO results (run_id, seq, payload_id, category, technique, "
                "severity, multi_turn, verdict, injected, errored, skipped, expected, "
                "blocked, ok, method, stage, note, chain, prompt_excerpt, reply_excerpt) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    run_id,
                    result.get("seq"),
                    result.get("payload_id"),
                    result.get("category"),
                    result.get("technique", ""),
                    result.get("severity", ""),
                    1 if result.get("multi_turn") else 0,
                    result.get("verdict"),
                    _opt_bool(result.get("injected")),
                    1 if result.get("errored") else 0,
                    1 if result.get("skipped") else 0,
                    _opt_bool(result.get("expected")),
                    _opt_bool(result.get("blocked")),
                    _opt_bool(result.get("ok")),
                    result.get("method", ""),
                    result.get("stage"),
                    result.get("note", ""),
                    json.dumps(result.get("chain") or []),
                    result.get("prompt_excerpt", ""),
                    result.get("reply_excerpt", ""),
                ),
            )

    def list_runs(self, limit: int = 50) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [_run_dict(r) for r in rows]

    def get_run(self, run_id: int) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM runs WHERE id = ?", (run_id,)
            ).fetchone()
        return _run_dict(row) if row else None

    def get_results(self, run_id: int) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM results WHERE run_id = ? ORDER BY seq", (run_id,)
            ).fetchall()
        return [_result_dict(r) for r in rows]


def _opt_bool(v: Any) -> int | None:
    return None if v is None else (1 if v else 0)


def _opt_bool_out(v: Any) -> bool | None:
    return None if v is None else bool(v)


def _run_dict(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "started_at": row["started_at"],
        "finished_at": row["finished_at"],
        "mode": row["mode"],
        "status": row["status"],
        "target_config": json.loads(row["target_config"]),
        "options": json.loads(row["options"]),
        "summary": json.loads(row["summary"]) if row["summary"] else None,
    }


def _result_dict(row: sqlite3.Row) -> dict:
    return {
        "seq": row["seq"],
        "payload_id": row["payload_id"],
        "category": row["category"],
        "technique": row["technique"],
        "severity": row["severity"],
        "multi_turn": bool(row["multi_turn"]),
        "verdict": row["verdict"],
        "injected": _opt_bool_out(row["injected"]),
        "errored": bool(row["errored"]),
        "skipped": bool(row["skipped"]),
        "expected": _opt_bool_out(row["expected"]),
        "blocked": _opt_bool_out(row["blocked"]),
        "ok": _opt_bool_out(row["ok"]),
        "method": row["method"],
        "stage": row["stage"],
        "note": row["note"],
        "chain": json.loads(row["chain"]),
        "prompt_excerpt": row["prompt_excerpt"],
        "reply_excerpt": row["reply_excerpt"],
    }
