(() => {
"use strict";

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g,
  (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));

let META = null;
let activeSockets = {};

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" }, ...opts,
  });
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try { msg = (await res.json()).detail || msg; } catch {}
    throw new Error(msg);
  }
  return res.json();
}

function renderTargetConfig(root, prefix) {
  root.innerHTML = `
    <legend class="field-label">Target</legend>
    <div class="field inline">
      <label for="${prefix}-type">type</label>
      <select id="${prefix}-type">
        <option value="mock">mock guarded pipeline (offline)</option>
        <option value="openai">OpenAI-compatible /v1/chat/completions</option>
        <option value="http_chat">custom HTTP chat route</option>
      </select>
    </div>
    <div class="field ${prefix}-only ${prefix}-openai hidden">
      <label for="${prefix}-endpoint">endpoint</label>
      <input type="text" id="${prefix}-endpoint" placeholder="http://localhost:11434/v1/chat/completions">
    </div>
    <div class="field inline ${prefix}-only ${prefix}-openai hidden">
      <label for="${prefix}-model">model</label>
      <input type="text" id="${prefix}-model" placeholder="llama3.1">
    </div>
    <div class="field ${prefix}-only ${prefix}-openai hidden">
      <label for="${prefix}-api-key">API key (optional)</label>
      <input type="password" id="${prefix}-api-key" autocomplete="off">
    </div>
    <div class="field ${prefix}-only ${prefix}-http_chat hidden">
      <label for="${prefix}-url">URL</label>
      <input type="text" id="${prefix}-url" placeholder="http://localhost:8000/chat">
    </div>`;
  const typeSel = $(`#${prefix}-type`, root);
  typeSel.addEventListener("change", () => {
    const t = typeSel.value;
    $$(`.${prefix}-only`, root).forEach((el) => el.classList.add("hidden"));
    $$(`.${prefix}-${t}`, root).forEach((el) => el.classList.remove("hidden"));
  });
}

function targetPayload(prefix) {
  const type = $(`#${prefix}-type`).value;
  const cfg = { type };
  const val = (id) => $(`#${prefix}-${id}`) ? $(`#${prefix}-${id}`).value.trim() : "";
  if (type === "openai") {
    cfg.endpoint = val("endpoint");
    if (val("model")) cfg.model = val("model");
    if (val("api-key")) cfg.api_key = val("api-key");
  } else if (type === "http_chat") {
    cfg.url = val("url");
  }
  return cfg;
}

function setStatus(mode, text, err = false) {
  const el = $(`#${mode}-status`);
  el.textContent = text;
  el.classList.toggle("err", err);
}

function toggleRunButtons(mode, running, runId) {
  $(`#${mode}-run`).disabled = running;
  const cancel = $(`#${mode} .cancel`, document) ||
    $$("button.cancel").find((b) => b.dataset.run === mode);
  if (cancel) cancel.classList.toggle("hidden", !running);
  if (running && runId) cancel.onclick = async () => {
    try { await api(`/api/runs/${runId}/cancel`, { method: "POST" }); } catch {}
  };
}

function addResultRow(mode, r) {
  const table = $(`#${mode}-results`);
  table.hidden = false;
  const tbody = $("tbody", table);
  const row = document.createElement("tr");
  if (mode === "compliance") {
    row.innerHTML = `
      <td class="muted">${r.seq}</td>
      <td>${esc(r.payload_id)}</td>
      <td>${esc(r.category)}</td>
      <td>${esc(r.expected)}</td>
      <td>${r.blocked === null ? "—" : esc(r.blocked)}</td>
      <td><span class="badge ${esc(r.verdict)}">${esc(r.verdict)}</span>
          ${r.stage ? `<span class="muted"> @${esc(r.stage)}</span>` : ""}</td>
      <td class="excerpt">${esc(r.note ? "error: " + r.note : r.reply_excerpt)}</td>`;
  } else {
    const detail = r.chain && r.chain.length
      ? chainDetail(r)
      : esc(r.note || r.method || "");
    row.innerHTML = `
      <td class="muted">${r.seq}</td>
      <td>${esc(r.payload_id)}${r.multi_turn ? ' <span class="muted">multi-turn</span>' : ""}</td>
      <td>${esc(r.category)}</td>
      <td class="muted">${esc(r.severity)}</td>
      <td><span class="badge ${esc(r.verdict)}">${esc(r.verdict)}</span></td>
      <td class="excerpt">${detail}</td>`;
  }
  tbody.appendChild(row);
}

function chainDetail(r) {
  const landed = r.chain.filter((c) => c.injected);
  if (landed.length) return `landed via <code>${esc(landed[landed.length - 1].mutation)}</code> — ${esc(r.note)}`;
  return `defended through ${r.chain.length} attempt(s) — ${esc(r.note)}`;
}

function showSummary(mode, summary) {
  const el = $(`#${mode}-summary`);
  if (mode === "compliance") {
    el.innerHTML = `
      <div class="summary-grid">
        <div class="stat"><b>${summary.passed}/${summary.total}</b> cases passed<br>pass rate ${summary.pass_rate_pct}%</div>
        <div class="stat"><b>${summary.failed}</b> failed</div>
        <div class="stat"><b>${summary.errored}</b> errored</div>
      </div>`;
  } else {
    const cats = Object.entries(summary.by_category || {}).map(([c, v]) =>
      `<tr><td>${esc(c)}</td><td>${v.defended}/${v.total}</td><td>${v.injected}</td><td>${v.resilience_pct}%</td></tr>`
    ).join("");
    el.innerHTML = `
      <div class="summary-grid">
        <div class="grade">${esc(summary.grade)}</div>
        <div class="stat"><b>${summary.resilience_pct}%</b> resilience<br>${summary.defended}/${summary.total} defended</div>
        <div class="stat"><b>${summary.injected}</b> injected</div>
        <div class="stat"><b>${summary.errored}</b> errored</div>
        <div class="stat"><b>${summary.skipped}</b> skipped</div>
      </div>
      ${cats ? `<table class="results"><thead><tr><th>category</th><th>defended</th><th>injected</th><th>resilience</th></tr></thead><tbody>${cats}</tbody></table>` : ""}`;
  }
}

function openRunSocket(runId, mode) {
  if (activeSockets[mode]) activeSockets[mode].close();
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws/runs/${runId}`);
  activeSockets[mode] = ws;
  ws.onmessage = (ev) => {
    const m = JSON.parse(ev.data);
    if (m.type === "result") addResultRow(mode, m.result);
    if (m.type === "done") {
      setStatus(mode, `run #${runId} ${m.status}` + (m.error ? ` — ${m.error}` : ""));
      if (m.summary) showSummary(mode, m.summary);
      toggleRunButtons(mode, false, null);
      ws.close();
    }
  };
  ws.onerror = () => setStatus(mode, `run #${runId}: socket error`, true);
}

function startRun(mode) {
  const target = targetPayload(mode);
  const options = {};
  if (mode === "compliance") {
    options.dataset = $("#compliance-dataset").value === "default" ? null : $("#compliance-dataset").value;
  } else {
    options.categories = $$("#campaign-categories .chip.on input:checked").map((i) => i.value);
    options.adaptive = $("#campaign-adaptive").checked;
    options.max_tries = parseInt($("#campaign-max-tries").value, 10) || 5;
    const judge = $("#campaign-judge").value.trim();
    if (judge) { options.judge = judge; options.judge_model = $("#campaign-judge-model").value.trim() || "gpt-4o-mini"; }
  }
  $(`#${mode}-results tbody`).innerHTML = "";
  $(`#${mode}-results`).hidden = true;
  $(`#${mode}-summary`).innerHTML = "";
  setStatus(mode, "starting…");
  const body = { mode, target, options };
  api("/api/runs", { method: "POST", body: JSON.stringify(body) })
    .then(({ run_id }) => {
      setStatus(mode, `run #${run_id} running…`);
      toggleRunButtons(mode, true, run_id);
      openRunSocket(run_id, mode);
    })
    .catch((e) => setStatus(mode, `failed to start: ${e.message}`, true));
}

async function loadRuns() {
  const { runs } = await api("/api/runs");
  const tbody = $("#runs-table tbody");
  tbody.innerHTML = runs.map((r) => `
    <tr>
      <td>#${r.id}</td>
      <td class="muted">${esc(r.started_at)}</td>
      <td>${esc(r.mode)}</td>
      <td><span class="badge ${esc(r.status)}">${esc(r.status)}</span></td>
      <td class="excerpt"><code>${esc(JSON.stringify(r.target_config))}</code></td>
      <td><a href="/api/runs/${r.id}/report?format=json">json</a> ·
          <a href="/api/runs/${r.id}/report?format=html">html</a> ·
          <a href="/api/runs/${r.id}/report?format=pdf">pdf</a></td>
      <td><button class="primary" data-show="${r.id}">view</button></td>
    </tr>`).join("");
  $$("button[data-show]", tbody).forEach((b) => {
    b.onclick = () => showRunDetail(parseInt(b.dataset.show, 10));
  });
}

async function showRunDetail(runId) {
  const { run, results } = await api(`/api/runs/${runId}`);
  const rows = results.map((r) => `
    <tr><td class="muted">${r.seq}</td><td>${esc(r.payload_id)}</td>
    <td>${esc(r.category)}</td>
    <td><span class="badge ${esc(r.verdict)}">${esc(r.verdict)}</span></td>
    <td class="excerpt">${esc(r.note || r.method || "")}</td></tr>`).join("");
  $("#run-detail").innerHTML = `
    <div class="card">
      <h2>Run #${run.id} — ${esc(run.mode)} <span class="badge ${esc(run.status)}">${esc(run.status)}</span></h2>
      <div class="status">started ${esc(run.started_at)} · finished ${esc(run.finished_at || "—")}
        · target <code>${esc(JSON.stringify(run.target_config))}</code></div>
      ${run.summary ? `<pre class="status">${esc(JSON.stringify(run.summary, null, 2))}</pre>` : ""}
      <table class="results">
        <thead><tr><th>#</th><th>id</th><th>category</th><th>verdict</th><th>detail</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

async function loadMeta() {
  META = await api("/api/meta");
  $("#compliance-dataset").innerHTML = META.datasets.map((d) =>
    `<option value="${esc(d.id)}">${esc(d.label)} — ${d.cases} cases</option>`).join("");
  $("#campaign-categories").innerHTML = META.categories.map((c) => `
    <label class="chip"><input type="checkbox" value="${esc(c.key)}">
      ${esc(c.key)} <span class="muted">${c.count}</span></label>`).join("");
  $$("#campaign-categories .chip").forEach((chip) => {
    chip.addEventListener("change", () => chip.classList.toggle("on", $("input", chip).checked));
  });
}

$$(".tabbtn").forEach((btn) => {
  btn.addEventListener("click", () => {
    $$(".tabbtn").forEach((b) => b.classList.toggle("active", b === btn));
    $$(".tab").forEach((t) => t.classList.toggle("active", t.id === `tab-${btn.dataset.tab}`));
    if (btn.dataset.tab === "runs") loadRuns().catch((e) => console.error(e));
  });
});

renderTargetConfig($("#compliance-target"), "compliance");
renderTargetConfig($("#campaign-target"), "campaign");
$("#compliance-form").addEventListener("submit", (e) => { e.preventDefault(); startRun("compliance"); });
$("#campaign-form").addEventListener("submit", (e) => { e.preventDefault(); startRun("campaign"); });
$("#runs-refresh").addEventListener("click", () => loadRuns().catch((e) => console.error(e)));
loadMeta().catch((e) => setStatus("compliance", `meta load failed: ${e.message}`, true));
})();
