# llm-guard-lab

A testing tool for LLM applications that answers two questions about any target
you're about to ship:

1. **Compliance** — do my guardrails make the *expected* decision on a known
   adversarial dataset? (regression-style, expected verdicts, CI-friendly)
2. **Resilience** — when someone tries to hijack the model with prompt
   injection, how often do they *succeed*? (canary-scored campaign with adaptive
   mutation escalation and an A–F resilience grade)

It combines two proven open-source approaches on one engine:

- the corpus, mutation chain, deterministic scorer, LLM judge, and resilience
  grading of [plalan/llm-injection-harness](https://github.com/plalan/llm-injection-harness)
  (114 payloads, 14 OWASP LLM01 categories)
- the policy-config mock pipeline, expected-verdict dataset, and blocked-detection
  of the [qa-practices-resources llm-guardrails-testing-checklist](https://github.com/MathiasPaulenko/qa-practices-resources/tree/main/resources/checklists/ai-testing/llm-guardrails-testing-checklist)

> ⚠️ **Authorized testing only.** Point this at endpoints you own or are
> explicitly authorized to assess. Payloads carry harmless canary tokens and
> contain no working exploits. This is a defensive assessment tool.

## Quick start

```bash
cd llm-guard-lab
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# offline, zero setup: run the compliance suite against the mock pipeline
llm-guard-lab compliance --target mock

# full injection campaign against the mock (smoke) ...
llm-guard-lab campaign --target mock --categories direct_injection

# ... or against a real OpenAI-compatible endpoint (Ollama, hosted API, your agent)
llm-guard-lab campaign --target '{"type":"openai","endpoint":"http://localhost:11434/v1/chat/completions","model":"llama3.1"}' --adaptive

# web UI (Compliance / Campaign / Runs tabs, live WebSocket results)
llm-guard-lab serve            # http://127.0.0.1:8505
```

## Test modes

### Compliance suites

Expected-verdict regression testing of guardrail decisions. Each dataset case
declares `id`, `category`, `prompt`, and `expect_blocked`; a run passes only when
every case matches. `blocked` is determined per target type:

| Target | `blocked` means |
|---|---|
| `mock` | the mock pipeline's input/output guardrail fired (with a `stage`) |
| `http_chat` | HTTP 400/401/403/422, or a refusal phrase in the answer |
| `openai` | a refusal phrase in the reply |

The bundled dataset is the checklist kit's 8 cases (direct injection,
jailbreaks, PII echo, encoding, and a safe baseline). Point `--dataset` at your
own JSON to regression-test your real policy set; `pytest tests/test_mock_target.py`
mirrors the kit's offline suite.

### Injection campaigns

Fires the 114-payload corpus at the target. Detection is deterministic wherever
possible — each payload asks the target to emit a unique canary token (or a
secret is planted in the defensive system prompt and a leak = failure). The
optional **adaptive attacker** retries every defended single-turn payload
through an escalating mutation chain (authority framing → roleplay →
hypothetical → homoglyph → ChatML delimiter → zero-width → urgency → base64 →
translation relay) while preserving the canary, so the report shows *which
wrapper finally defeated the guardrail*.

Resilience = % of scorable attacks that were defended (errored and
judge-skipped attacks are counted separately, never silently scored). Exit
non-zero in CI with `--fail-below 90`.

Multi-turn payloads send their turns sequentially (carrying assistant replies)
against `openai` targets and are scored on the final reply; on `mock` and
`http_chat` targets turns are joined into one prompt.

## Targets

| `type` | Config | Notes |
|---|---|---|
| `mock` | `{"type":"mock","policy_path":"optional.json"}` | offline guarded pipeline; policy from `llm_guard_lab/datasets/guardrails_config.json` (keyword injection filter + PII regex output filter; the classifier entry is a documented stub, as in the kit) |
| `openai` | `{"type":"openai","endpoint":"…/v1/chat/completions","model":"…","api_key":"optional","system_prompt":"optional override"}` | attacks run under a deliberately ordinary defensive system prompt carrying the corpus's planted secret (`SYSTEM_CANARY`) |
| `http_chat` | `{"type":"http_chat","url":"…/chat","prompt_field":"prompt","answer_field":"answer"}` | any route taking `{prompt}` and returning `{answer}`; 5xx/transport failures count as errors, not "not blocked" |

API keys are redacted before anything is persisted or logged.

## CLI

```
llm-guard-lab serve [--host] [--port] [--db]
llm-guard-lab compliance [--target …] [--dataset PATH] [--report PATH] [--format json|html|pdf]
llm-guard-lab campaign  [--target …] [--categories c1,c2] [--adaptive] [--max-tries N]
                        [--judge URL] [--judge-model M] [--fail-below PCT] [--report PATH]
llm-guard-lab runs list|show ID
llm-guard-lab report ID --format json|html|pdf [-o PATH]
```

`--target` accepts `mock`, an inline JSON object, or a path to a JSON file.
`LLGL_DB_PATH` overrides the default SQLite location (`./data/llm-guard-lab.db`).

## Web API

- `POST /api/runs` `{mode, target, options}` → `{run_id}` (runs in background)
- `GET /api/runs`, `GET /api/runs/{id}`
- `WS /ws/runs/{id}` — live result events + final summary
- `POST /api/runs/{id}/cancel`
- `GET /api/runs/{id}/report?format=json|html|pdf`
- `GET /api/meta` — corpus categories, payload counts, datasets

## Extending

- **Corpus**: add payloads in `llm_guard_lab/engine/corpus.py` with the `_c`
  (canary), `_r` (refusal-absent), `_j` (judge), `_mt` (multi-turn) helpers.
- **Datasets**: add `{id, category, prompt, expect_blocked}` cases in a JSON
  file and pass `--dataset`.
- **Mock policies**: edit `datasets/guardrails_config.json` (or pass
  `policy_path`) to model the policy set you want to regression-test.

## Reports

Every run persists to SQLite; `llm-guard-lab report <run-id>` (or the Runs tab)
exports JSON (source of truth), HTML (readable summary with per-category
breakdown, pass/fail or resilience grade, and mutation-chain details), and PDF
(assessment deliverable).

## Testing

```bash
pip install -e ".[dev]"
pytest
```

## Docker

```bash
docker build -t llm-guard-lab .
docker run -p 8505:8505 -v "$PWD/data:/app/data" llm-guard-lab
```
