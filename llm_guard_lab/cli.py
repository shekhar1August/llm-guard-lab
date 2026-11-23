from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from .engine import compliance as compliance_mod
from .engine import runner as runner_mod
from .engine.corpus import CATEGORIES, get_corpus
from .store import Store, default_db_path
from .targets.base import TARGET_TYPES, make_target


def parse_target(value: str) -> dict:
    if value == "mock":
        return {"type": "mock"}
    value = value.strip()
    if value.startswith("{"):
        try:
            return json.loads(value)
        except json.JSONDecodeError as e:
            raise SystemExit(f"--target is not valid JSON: {e}")
    path = Path(value)
    if not path.exists():
        raise SystemExit(
            f"--target must be 'mock', a JSON object, or a path to a JSON file; "
            f"got {value!r}"
        )
    return json.loads(path.read_text(encoding="utf-8"))


def add_target_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--target", default="mock",
        help="target to test: 'mock', an inline JSON object, or a path to a JSON "
             f"file. Types: {', '.join(TARGET_TYPES)}",
    )


def add_report_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--report", metavar="PATH", help="write a report file")
    p.add_argument(
        "--format", choices=("json", "html", "pdf"), dest="report_format",
        help="report format (default: inferred from --report extension, else json)",
    )


def add_db_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--db", default=str(default_db_path()),
        help=f"SQLite path (default: {default_db_path()}; env LLGL_DB_PATH)",
    )


def _print(line: str) -> None:
    print(line, file=sys.stderr, flush=True)


def _write_report(store: Store, run_id: int, path: str | None, fmt: str | None) -> None:
    from .reporting import build_report, render_html, render_pdf, to_json_bytes

    if not path and not fmt:
        return
    if fmt is None:
        ext = Path(path or "").suffix.lower().lstrip(".")
        fmt = ext if ext in ("json", "html", "pdf") else "json"
    if path is None:
        path = f"run-{run_id}-report.{fmt}"
    report = build_report(store, run_id)
    if report is None:
        raise SystemExit(f"run {run_id} not found")
    if fmt == "json":
        data = to_json_bytes(report)
    elif fmt == "html":
        data = render_html(report).encode("utf-8")
    else:
        data = render_pdf(report)
    Path(path).write_bytes(data)
    _print(f"report written: {path} ({fmt}, {len(data)} bytes)")


def _execute(mode: str, args: argparse.Namespace) -> int:
    store = Store(args.db)
    target_config = parse_target(args.target)
    run_id = store.create_run(mode, target_config, _options(args))
    _print(f"run #{run_id} started ({mode}) against target: "
           f"{json.dumps(target_config)}")

    def on_result(r: dict) -> None:
        store.add_result(run_id, r)
        print(_format_result_line(mode, r), flush=True)

    try:
        target = make_target(target_config)
        if mode == "compliance":
            cases = compliance_mod.load_dataset(getattr(args, "dataset", None))
            results, summary = asyncio.run(
                compliance_mod.run_suite(target, cases, on_result=on_result)
            )
        else:
            payloads = get_corpus(
                [c.strip() for c in args.categories.split(",") if c.strip()]
                if args.categories else None
            )
            judge = None
            if args.judge:
                judge = {
                    "endpoint": args.judge,
                    "model": args.judge_model or "gpt-4o-mini",
                }
            results, summary = asyncio.run(
                runner_mod.run_campaign(
                    target, payloads,
                    adaptive=args.adaptive,
                    max_tries=args.max_tries,
                    judge=judge,
                    on_result=on_result,
                )
            )
    except (ValueError, FileNotFoundError) as e:
        store.finish_run(run_id, "failed", None)
        raise SystemExit(str(e))

    status = "cancelled" if summary.get("cancelled") else "completed"
    store.finish_run(run_id, status, summary)
    _print(f"run #{run_id} {status}")

    _write_report(store, run_id, args.report, args.report_format)

    if mode == "compliance":
        _print(
            f"compliance: {summary['passed']}/{summary['total']} passed, "
            f"{summary['failed']} failed, {summary['errored']} errored"
        )
        return 1 if summary["failed"] else 0
    _print(
        f"resilience: {summary['resilience_pct']}% (grade {summary['grade']}) — "
        f"{summary['defended']}/{summary['total']} defended, "
        f"{summary['injected']} injected, {summary['errored']} errored, "
        f"{summary['skipped']} skipped"
    )
    if args.fail_below is not None and summary["resilience_pct"] < args.fail_below:
        _print(
            f"FAIL: resilience {summary['resilience_pct']}% is below the "
            f"--fail-below threshold of {args.fail_below}%"
        )
        return 1
    return 0


def _options(args: argparse.Namespace) -> dict:
    if getattr(args, "mode", None) == "compliance":
        return {"dataset": getattr(args, "dataset", None) or "default"}
    return {
        "categories": args.categories or "all",
        "adaptive": bool(args.adaptive),
        "max_tries": args.max_tries,
        "judge": bool(args.judge),
        "fail_below": args.fail_below,
    }


def _format_result_line(mode: str, r: dict) -> str:
    if mode == "compliance":
        mark = "OK" if r.get("ok") else "FAIL"
        return (
            f"[{mark}] {r['payload_id']} ({r['category']}): "
            f"expected blocked={r['expected']}, got {r['blocked']}"
            + (f" [error: {r['note']}]" if r.get("errored") else "")
        )
    mark = r["verdict"].upper()
    return (
        f"[{mark}] {r['payload_id']} ({r['category']}) via {r.get('method')}: "
        f"{r.get('note') or ''}"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="llm-guard-lab",
        description="Guardrail compliance suites and adaptive prompt-injection "
                    "campaigns for LLM applications.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_serve = sub.add_parser("serve", help="start the web UI")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8505)
    add_db_arg(p_serve)

    p_comp = sub.add_parser(
        "compliance", help="run an expected-verdict guardrail suite"
    )
    add_target_arg(p_comp)
    p_comp.add_argument(
        "--dataset", help="path to a dataset JSON (default: bundled checklist kit)"
    )
    add_report_args(p_comp)
    add_db_arg(p_comp)

    p_camp = sub.add_parser("campaign", help="run an injection campaign")
    add_target_arg(p_camp)
    p_camp.add_argument(
        "--categories",
        help=f"comma-separated subset of: {', '.join(CATEGORIES)} (default: all)",
    )
    p_camp.add_argument(
        "--adaptive", action="store_true",
        help="retry defended single-turn payloads through the mutation chain",
    )
    p_camp.add_argument("--max-tries", type=int, default=5)
    p_camp.add_argument(
        "--judge", metavar="URL",
        help="OpenAI-compatible endpoint for the LLM judge (optional)",
    )
    p_camp.add_argument("--judge-model", default="gpt-4o-mini")
    p_camp.add_argument(
        "--fail-below", type=int, metavar="PCT",
        help="exit non-zero when resilience falls below PCT",
    )
    add_report_args(p_camp)
    add_db_arg(p_camp)

    p_runs = sub.add_parser("runs", help="inspect persisted runs")
    runs_sub = p_runs.add_subparsers(dest="runs_command", required=True)
    p_runs_list = runs_sub.add_parser("list")
    add_db_arg(p_runs_list)
    p_runs_show = runs_sub.add_parser("show")
    p_runs_show.add_argument("run_id", type=int)
    add_db_arg(p_runs_show)

    p_report = sub.add_parser("report", help="export a persisted run")
    p_report.add_argument("run_id", type=int)
    p_report.add_argument(
        "--format", choices=("json", "html", "pdf"), default="json"
    )
    p_report.add_argument("-o", "--output", help="output path (json prints to "
                          "stdout when omitted)")
    add_db_arg(p_report)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "serve":
        import os

        import uvicorn

        os.environ["LLGL_DB_PATH"] = str(Path(args.db).resolve())
        _print(f"serving on http://{args.host}:{args.port} (db: {args.db})")
        uvicorn.run(
            "llm_guard_lab.server.app:app",
            host=args.host, port=args.port, log_level="info",
        )
        return 0

    if args.command == "runs":
        store = Store(args.db)
        if args.runs_command == "list":
            for run in store.list_runs():
                print(
                    f"#{run['id']:>4}  {run['started_at']}  {run['mode']:<11} "
                    f"{run['status']:<9} {json.dumps(run['target_config'])}"
                )
            return 0
        run = store.get_run(args.run_id)
        if run is None:
            raise SystemExit(f"run {args.run_id} not found")
        print(json.dumps(
            {"run": run, "results": store.get_results(args.run_id)},
            indent=2, default=str,
        ))
        return 0

    if args.command == "report":
        from .reporting import build_report, render_html, render_pdf, to_json_bytes

        store = Store(args.db)
        report = build_report(store, args.run_id)
        if report is None:
            raise SystemExit(f"run {args.run_id} not found")
        if args.format == "json":
            data = to_json_bytes(report)
        elif args.format == "html":
            data = render_html(report).encode("utf-8")
        else:
            data = render_pdf(report)
        if args.output:
            Path(args.output).write_bytes(data)
            _print(f"report written: {args.output} ({args.format})")
        elif args.format == "json":
            sys.stdout.buffer.write(data)
        else:
            raise SystemExit("--output is required for html/pdf formats")
        return 0

    mode = "compliance" if args.command == "compliance" else "campaign"
    args.mode = mode
    return _execute(mode, args)


if __name__ == "__main__":
    raise SystemExit(main())
