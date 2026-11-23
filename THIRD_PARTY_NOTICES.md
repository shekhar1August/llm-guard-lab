# Third-party notices

This project vendors and adapts MIT-licensed material from the following
projects. The full license texts are preserved in `THIRD_PARTY_LICENSES/`.

## plalan/llm-injection-harness

- Source: https://github.com/plalan/llm-injection-harness
- License: MIT — `THIRD_PARTY_LICENSES/llm-injection-harness-MIT.txt`
- Vendored/adapted components:
  - `llm_guard_lab/engine/corpus.py` (from `injection_corpus.py`) — the
    114-payload attack corpus, category taxonomy, authoring helpers, and
    `SYSTEM_CANARY`
  - `llm_guard_lab/engine/mutations.py` (from `injection_mutations.py`) — the
    9 delivery mutators used by the adaptive attacker
  - `llm_guard_lab/engine/scoring.py` (from `injection.py`) — refusal markers,
    deterministic detectors, the LLM-judge prompt, and resilience grading
  - `llm_guard_lab/engine/runner.py` (from `injection.py`) — the campaign runner
    and adaptive escalation loop
  - `llm_guard_lab/targets/openai_compat.py` (from `injection.py`) — the
    defensive system prompt and OpenAI-compatible target adapter

## MathiasPaulenko/qa-practices-resources

- Source: https://github.com/MathiasPaulenko/qa-practices-resources
  (`resources/checklists/ai-testing/llm-guardrails-testing-checklist`)
- License: MIT — `THIRD_PARTY_LICENSES/qa-practices-resources-MIT.txt`
- Vendored/adapted components:
  - `llm_guard_lab/targets/mock.py` (from `guarded_pipeline.py`) — the offline
    mock guarded pipeline
  - `llm_guard_lab/datasets/guardrails_config.json` — the policy config
  - `llm_guard_lab/datasets/adversarial_prompts.json` — the 8-case
    expected-verdict dataset
  - `llm_guard_lab/engine/compliance.py` (from `test_guardrails.py` /
    `adversarial_test.py`) — the compliance suite runner and blocked-detection
    semantics (HTTP 400/401/403/422 or refusal phrase)
