from __future__ import annotations

import json
from typing import Any

from jinja2 import Environment, StrictUndefined

from .store import Store

HTML_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>llm-guard-lab run {{ run.id }} report</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
         margin: 0 auto; max-width: 1100px; padding: 24px 16px 64px; line-height: 1.45; }
  h1 { font-size: 1.4rem; margin-bottom: 4px; }
  .meta { color: var(--muted, #888); font-size: 0.9rem; margin-bottom: 20px; }
  .summary { display: flex; gap: 24px; flex-wrap: wrap; align-items: center;
             border: 1px solid var(--border, #444); border-radius: 10px;
             padding: 16px 20px; margin-bottom: 24px; }
  .grade { font-size: 2.6rem; font-weight: 700; line-height: 1; }
  .stat b { font-size: 1.1rem; }
  .stat { color: var(--muted, #888); font-size: 0.85rem; }
  table { border-collapse: collapse; width: 100%; font-size: 0.85rem; margin-bottom: 28px; }
  th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--border, #444);
           vertical-align: top; }
  th { font-weight: 600; }
  .badge { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 0.75rem; }
  .injected, .fail, .errored { color: #fff; background: #c0392b; }
  .defended, .pass { color: #fff; background: #2e7d32; }
  .skipped { color: #fff; background: #95a5a6; }
  .muted { color: var(--muted, #888); }
  .note { max-width: 420px; overflow-wrap: anywhere; }
</style>
</head>
<body>
<h1>llm-guard-lab — run #{{ run.id }} ({{ run.mode }})</h1>
<div class="meta">
  {{ run.status }} · started {{ run.started_at }}{% if run.finished_at %} · finished {{ run.finished_at }}{% endif %}<br>
  target: <code>{{ run.target_config | tojson }}</code>
</div>

{% if run.mode == "campaign" and summary %}
<div class="summary">
  <div class="grade">{{ summary.grade }}</div>
  <div class="stat"><b>{{ summary.resilience_pct }}%</b> resilience<br>
    {{ summary.defended }}/{{ summary.total }} defended</div>
  <div class="stat"><b>{{ summary.injected }}</b> injected</div>
  <div class="stat"><b>{{ summary.errored }}</b> errored</div>
  <div class="stat"><b>{{ summary.skipped }}</b> skipped</div>
</div>

<h2>By category</h2>
<table>
  <tr><th>category</th><th>defended</th><th>injected</th><th>resilience</th></tr>
  {% for cat, v in summary.by_category.items() %}
  <tr><td>{{ cat }}</td><td>{{ v.defended }}/{{ v.total }}</td>
      <td>{{ v.injected }}</td><td>{{ v.resilience_pct }}%</td></tr>
  {% endfor %}
</table>
{% elif summary %}
<div class="summary">
  <div class="stat"><b>{{ summary.passed }}/{{ summary.total }}</b> cases passed<br>
    pass rate {{ summary.pass_rate_pct }}%</div>
  <div class="stat"><b>{{ summary.failed }}</b> failed</div>
  <div class="stat"><b>{{ summary.errored }}</b> errored</div>
</div>

<h2>By category</h2>
<table>
  <tr><th>category</th><th>passed</th><th>failed</th></tr>
  {% for cat, v in summary.by_category.items() %}
  <tr><td>{{ cat }}</td><td>{{ v.passed }}/{{ v.total }}</td><td>{{ v.failed }}</td></tr>
  {% endfor %}
</table>
{% endif %}

<h2>Results</h2>
<table>
  <tr>
    <th>#</th><th>id</th><th>category</th><th>verdict</th>
    {% if run.mode == "compliance" %}<th>expected</th><th>blocked</th>{% endif %}
    <th class="note">detail</th>
  </tr>
  {% for r in results %}
  <tr>
    <td class="muted">{{ r.seq }}</td>
    <td>{{ r.payload_id }}</td>
    <td>{{ r.category }}</td>
    <td><span class="badge {{ r.verdict }}">{{ r.verdict }}</span></td>
    {% if run.mode == "compliance" %}
    <td>{{ r.expected }}</td><td>{{ r.blocked }}</td>
    {% endif %}
    <td class="note muted">{{ result_detail(r) }}</td>
  </tr>
  {% endfor %}
</table>
</body>
</html>"""


def result_detail(r: dict) -> str:
    if r.get("note"):
        base = str(r["note"])
    elif r.get("chain"):
        base = chain_summary(r)
    else:
        base = r.get("method") or ""
    reply = r.get("reply_excerpt") or ""
    if reply and len(base) < 160:
        base = f"{base} — reply: {reply[:120]}"
    return base


def chain_summary(r: dict) -> str:
    chain = r.get("chain") or []
    if not chain:
        return ""
    landed = [c for c in chain if c.get("injected")]
    if landed:
        return f"landed via mutation '{landed[-1]['mutation']}'"
    return f"defended through {len(chain)} attempt(s)"


def landed_mutation(r: dict) -> str:
    chain = r.get("chain") or []
    landed = [c for c in chain if c.get("injected")]
    return landed[-1]["mutation"] if landed else ""


def build_report(store: Store, run_id: int) -> dict[str, Any] | None:
    run = store.get_run(run_id)
    if run is None:
        return None
    return {"run": run, "results": store.get_results(run_id)}


def to_json_bytes(report: dict[str, Any]) -> bytes:
    return (
        json.dumps(report, indent=2, sort_keys=False, default=str).encode("utf-8") + b"\n"
    )


def render_html(report: dict[str, Any]) -> str:
    env = Environment(autoescape=True, undefined=StrictUndefined)
    env.filters["tojson"] = lambda v: json.dumps(v)
    summary = report["run"].get("summary")
    tpl = env.from_string(HTML_TEMPLATE)
    return tpl.render(
        run=report["run"],
        results=report["results"],
        summary=summary,
        result_detail=result_detail,
    )


def render_pdf(report: dict[str, Any]) -> bytes:
    from io import BytesIO

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=letter,
        leftMargin=0.7 * inch, rightMargin=0.7 * inch,
        topMargin=0.7 * inch, bottomMargin=0.7 * inch,
        title=f"llm-guard-lab run {report['run']['id']} report",
    )
    styles = getSampleStyleSheet()
    small = ParagraphStyle(
        "small", parent=styles["BodyText"], fontSize=7.5, leading=9.5
    )
    cell = ParagraphStyle(
        "cell", parent=small, textColor=colors.black
    )
    story: list[Any] = []

    run = report["run"]
    summary = run.get("summary") or {}
    story.append(Paragraph(
        f"llm-guard-lab — run #{run['id']} ({run['mode']})",
        styles["Title"],
    ))
    story.append(Paragraph(
        f"status: {run['status']} · started: {run['started_at']} · "
        f"finished: {run.get('finished_at') or '—'}", small))
    story.append(Paragraph(
        f"target: {json.dumps(run['target_config'])}", small))
    story.append(Spacer(1, 14))

    if run["mode"] == "campaign" and summary:
        rows = [
            ["Resilience", "Grade", "Defended", "Injected", "Errored", "Skipped"],
            [f"{summary.get('resilience_pct', 0)}%", summary.get("grade", "—"),
             str(summary.get("defended", 0)), str(summary.get("injected", 0)),
             str(summary.get("errored", 0)), str(summary.get("skipped", 0))],
        ]
        t = Table(rows, hAlign="LEFT")
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#333333")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t)
        story.append(Spacer(1, 12))
        cat_rows = [["Category", "Defended", "Injected", "Resilience"]]
        for cat, v in (summary.get("by_category") or {}).items():
            cat_rows.append([
                cat, f"{v['defended']}/{v['total']}", str(v["injected"]),
                f"{v['resilience_pct']}%",
            ])
        t = Table(cat_rows, hAlign="LEFT")
        t.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dddddd")),
        ]))
        story.append(t)
    elif summary:
        rows = [
            ["Passed", "Failed", "Errored", "Pass rate"],
            [str(summary.get("passed", 0)), str(summary.get("failed", 0)),
             str(summary.get("errored", 0)), f"{summary.get('pass_rate_pct', 0)}%"],
        ]
        t = Table(rows, hAlign="LEFT")
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#333333")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ]))
        story.append(t)
    story.append(Spacer(1, 12))

    compliance = run["mode"] == "compliance"
    header = ["#", "ID", "Category", "Verdict"]
    if compliance:
        header += ["Expected", "Blocked"]
    else:
        header += ["Detail"]
    res_rows = [header]
    for r in report["results"]:
        row = [
            str(r["seq"]), r["payload_id"], r["category"],
            Paragraph(r["verdict"], cell),
        ]
        if compliance:
            row += [str(r["expected"]), str(r["blocked"])]
        else:
            row += [Paragraph(result_detail(r)[:200], cell)]
        res_rows.append(row)
    t = Table(res_rows, repeatRows=1, hAlign="LEFT",
              colWidths=[0.3 * inch, 0.9 * inch, 1.3 * inch, 0.8 * inch] +
                            ([0.7 * inch, 0.7 * inch] if compliance else [3.2 * inch]))
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dddddd")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(t)

    doc.build(story)
    return buf.getvalue()
