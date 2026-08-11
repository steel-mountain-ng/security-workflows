# Confidence-scoring benchmark report

Labeled TP/FP triage across OpenRouter models (same fixtures, prompt, and JSON schema).

## Setup

- Fixtures: `scripts/fixtures/confidence_benchmark.json`
- Findings: `alert:9` (TP — `js/clear-text-cookie`), `alert:3303` (noise/FP — npm image CVE under `usr/local/lib/node_modules/npm/...`)
- Soft-agree: for the FP fixture, `needs_human` counts as agreement (safe escalation); strict FP rate is reported separately
- Cost: OpenRouter `usage.cost` when present, else estimated from public $/MTok × token counts
- Caveat: **n=2 findings** — smoke test for routing policy, not a production calibration study

## Per-finding results

| Finding | Ground truth | Model | Classification | Conf | Latency (ms) | Est. USD | Agree |
| --- | --- | --- | --- | ---: | ---: | ---: | --- |
| `alert:9` | `likely_true_positive` | `deepseek/deepseek-v4-flash-0731` | `likely_true_positive` | 0.95 | 26876 | $0.00034 | yes |
| `alert:3303` | `likely_false_positive` | `deepseek/deepseek-v4-flash-0731` | `likely_false_positive` | 0.80 | 26876 | $0.00034 | yes |
| `alert:9` | `likely_true_positive` | `google/gemini-3.5-flash-lite` | `likely_true_positive` | 0.95 | 1522 | $0.00045 | yes |
| `alert:3303` | `likely_false_positive` | `google/gemini-3.5-flash-lite` | `needs_human` | 0.60 | 1522 | $0.00045 | yes |
| `alert:9` | `likely_true_positive` | `openai/gpt-4o-mini` | `likely_true_positive` | 0.90 | 3332 | $0.000092 | yes |
| `alert:3303` | `likely_false_positive` | `openai/gpt-4o-mini` | `likely_true_positive` | 0.90 | 3332 | $0.000092 | no |
| `alert:9` | `likely_true_positive` | `openai/gpt-4.1-mini` | `likely_true_positive` | 0.95 | 3809 | $0.00030 | yes |
| `alert:3303` | `likely_false_positive` | `openai/gpt-4.1-mini` | `likely_true_positive` | 0.90 | 3809 | $0.00030 | no |
| `alert:9` | `likely_true_positive` | `meta-llama/llama-3.1-8b-instruct` | `likely_true_positive` | 0.90 | 48854 | $0.000017 | yes |
| `alert:3303` | `likely_false_positive` | `meta-llama/llama-3.1-8b-instruct` | `likely_true_positive` | 0.95 | 48854 | $0.000017 | no |
| `alert:9` | `likely_true_positive` | `z-ai/glm-4.5-air` | `likely_true_positive` | 0.95 | 18377 | $0.00064 | yes |
| `alert:3303` | `likely_false_positive` | `z-ai/glm-4.5-air` | `likely_true_positive` | 0.90 | 18377 | $0.00064 | no |
| `alert:9` | `likely_true_positive` | `anthropic/claude-sonnet-4.5` | `likely_true_positive` | 0.92 | 13551 | $0.00458 | yes |
| `alert:3303` | `likely_false_positive` | `anthropic/claude-sonnet-4.5` | `needs_human` | 0.68 | 13551 | $0.00458 | yes |
| `alert:9` | `likely_true_positive` | `openai/gpt-4o` | `likely_true_positive` | 0.90 | 3237 | $0.00178 | yes |
| `alert:3303` | `likely_false_positive` | `openai/gpt-4o` | `likely_true_positive` | 0.95 | 3237 | $0.00178 | no |
| `alert:9` | `likely_true_positive` | `openai/gpt-4.1` | `likely_true_positive` | 0.98 | 2581 | $0.00156 | yes |
| `alert:3303` | `likely_false_positive` | `openai/gpt-4.1` | `likely_true_positive` | 0.95 | 2581 | $0.00156 | no |
| `alert:9` | `likely_true_positive` | `google/gemini-2.5-flash` | `likely_true_positive` | 0.90 | 2633 | $0.00055 | yes |
| `alert:3303` | `likely_false_positive` | `google/gemini-2.5-flash` | `likely_true_positive` | 0.95 | 2633 | $0.00055 | no |
| `alert:9` | `likely_true_positive` | `deepseek/deepseek-chat-v3.1` | `likely_true_positive` | 0.95 | 11514 | $0.00026 | yes |
| `alert:3303` | `likely_false_positive` | `deepseek/deepseek-chat-v3.1` | `likely_false_positive` | 0.85 | 11514 | $0.00026 | yes |
| `alert:9` | `likely_true_positive` | `meta-llama/llama-3.3-70b-instruct` | `likely_true_positive` | 0.90 | 6046 | $0.00014 | yes |
| `alert:3303` | `likely_false_positive` | `meta-llama/llama-3.3-70b-instruct` | `likely_true_positive` | 0.95 | 6046 | $0.00014 | no |
| `alert:9` | `likely_true_positive` | `qwen/qwen3-32b` | `likely_true_positive` | 0.90 | 8009 | $0.000092 | yes |
| `alert:3303` | `likely_false_positive` | `qwen/qwen3-32b` | `likely_true_positive` | 0.85 | 8009 | $0.000092 | no |
| `alert:9` | `likely_true_positive` | `z-ai/glm-4.5` | `likely_true_positive` | 1.00 | 101560 | $0.00602 | yes |
| `alert:3303` | `likely_false_positive` | `z-ai/glm-4.5` | `needs_human` | 0.80 | 101560 | $0.00602 | yes |
| `alert:9` | `likely_true_positive` | `anthropic/claude-opus-5` | `likely_true_positive` | 0.94 | 11291 | $0.0109 | yes |
| `alert:3303` | `likely_false_positive` | `anthropic/claude-opus-5` | `likely_false_positive` | 0.60 | 11291 | $0.0109 | yes |
| `alert:9` | `likely_true_positive` | `openai/o4-mini` | `likely_true_positive` | 0.90 | 4263 | $0.00122 | yes |
| `alert:3303` | `likely_false_positive` | `openai/o4-mini` | `likely_true_positive` | 0.90 | 4263 | $0.00122 | no |
| `alert:9` | `likely_true_positive` | `openai/o3-mini` | `likely_true_positive` | 0.95 | 5039 | $0.00227 | yes |
| `alert:3303` | `likely_false_positive` | `openai/o3-mini` | `likely_true_positive` | 0.95 | 5039 | $0.00227 | no |
| `alert:9` | `likely_true_positive` | `google/gemini-2.5-pro` | `likely_true_positive` | 0.95 | 18437 | $0.00917 | yes |
| `alert:3303` | `likely_false_positive` | `google/gemini-2.5-pro` | `needs_human` | 0.90 | 18437 | $0.00917 | yes |
| `alert:9` | `likely_true_positive` | `openrouter/auto@low` | `likely_true_positive` | 0.95 | 5683 | $0.00031 | yes |
| `alert:3303` | `likely_false_positive` | `openrouter/auto@low` | `likely_false_positive` | 0.80 | 5683 | $0.00031 | yes |
| `alert:9` | `likely_true_positive` | `openrouter/auto@medium` | `likely_true_positive` | 0.92 | 5158 | $0.00295 | yes |
| `alert:3303` | `likely_false_positive` | `openrouter/auto@medium` | `likely_false_positive` | 0.75 | 5158 | $0.00295 | yes |

## Per-model aggregate

| Model | Both correct | Acc | TP recall | FP noise OK | Strict FP | Avg conf | Latency (ms) | Tokens (in/out) | Total USD | $/correct |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `deepseek/deepseek-chat-v3.1` | yes | 100% | 100% | 100% | 100% | 0.90 | 11514 | 533/382 | $0.00053 | $0.00026 |
| `openrouter/auto@low` | yes | 100% | 100% | 100% | 100% | 0.88 | 5683 | 510/849 | $0.00062 | $0.00031 |
| `deepseek/deepseek-v4-flash-0731` | yes | 100% | 100% | 100% | 100% | 0.88 | 26876 | 510/1176 | $0.00068 | $0.00034 |
| `google/gemini-3.5-flash-lite` | yes | 100% | 100% | 100% | 0% | 0.77 | 1522 | 524/296 | $0.00090 | $0.00045 |
| `openrouter/auto@medium` | yes | 100% | 100% | 100% | 100% | 0.83 | 5158 | 488/739 | $0.00590 | $0.00295 |
| `anthropic/claude-sonnet-4.5` | yes | 100% | 100% | 100% | 0% | 0.80 | 13551 | 550/500 | $0.00915 | $0.00458 |
| `z-ai/glm-4.5` | yes | 100% | 100% | 100% | 0% | 0.90 | 101560 | 539/5328 | $0.0120 | $0.00602 |
| `google/gemini-2.5-pro` | yes | 100% | 100% | 100% | 0% | 0.93 | 18437 | 524/1768 | $0.0183 | $0.00917 |
| `anthropic/claude-opus-5` | yes | 100% | 100% | 100% | 100% | 0.77 | 11291 | 747/719 | $0.0217 | $0.0109 |
| `meta-llama/llama-3.1-8b-instruct` | no | 50% | 100% | 0% | 0% | 0.93 | 48854 | 487/583 | $0.000033 | $0.000033 |
| `openai/gpt-4o-mini` | no | 50% | 100% | 0% | 0% | 0.90 | 3332 | 487/184 | $0.00018 | $0.00018 |
| `qwen/qwen3-32b` | no | 50% | 100% | 0% | 0% | 0.88 | 8009 | 506/511 | $0.00018 | $0.00018 |
| `meta-llama/llama-3.3-70b-instruct` | no | 50% | 100% | 0% | 0% | 0.93 | 6046 | 507/216 | $0.00029 | $0.00029 |
| `openai/gpt-4.1-mini` | no | 50% | 100% | 0% | 0% | 0.93 | 3809 | 487/254 | $0.00060 | $0.00060 |
| `google/gemini-2.5-flash` | no | 50% | 100% | 0% | 0% | 0.93 | 2633 | 524/375 | $0.00109 | $0.00109 |
| `z-ai/glm-4.5-air` | no | 50% | 100% | 0% | 0% | 0.93 | 18377 | 540/1074 | $0.00128 | $0.00128 |
| `openai/o4-mini` | no | 50% | 100% | 0% | 0% | 0.90 | 4263 | 486/434 | $0.00244 | $0.00244 |
| `openai/gpt-4.1` | no | 50% | 100% | 0% | 0% | 0.96 | 2581 | 487/269 | $0.00313 | $0.00313 |
| `openai/gpt-4o` | no | 50% | 100% | 0% | 0% | 0.93 | 3237 | 487/234 | $0.00356 | $0.00356 |
| `openai/o3-mini` | no | 50% | 100% | 0% | 0% | 0.95 | 5039 | 486/912 | $0.00455 | $0.00455 |

### Cost-effectiveness — bulk triage

Ranked by: both findings correct → accuracy → lowest $/correct → latency.

1. **`deepseek/deepseek-chat-v3.1`** — acc 100%, $0.00026/correct, 11514ms, FP noise 100%
2. **`openrouter/auto@low`** (routed `deepseek/deepseek-v4-flash-0731`) — acc 100%, $0.00031/correct, 5683ms, FP noise 100%
3. **`deepseek/deepseek-v4-flash-0731`** — acc 100%, $0.00034/correct, 26876ms, FP noise 100%
4. **`google/gemini-3.5-flash-lite`** — acc 100%, $0.00045/correct, 1522ms, FP noise 100%
5. **`openrouter/auto@medium`** (routed `z-ai/glm-5.2`) — acc 100%, $0.00295/correct, 5158ms, FP noise 100%
6. **`anthropic/claude-sonnet-4.5`** — acc 100%, $0.00458/correct, 13551ms, FP noise 100%
7. **`z-ai/glm-4.5`** — acc 100%, $0.00602/correct, 101560ms, FP noise 100%
8. **`google/gemini-2.5-pro`** — acc 100%, $0.00917/correct, 18437ms, FP noise 100%

### Cost-effectiveness — FP confidence gate

Ranked by: both correct → TP recall → FP noise handling → strict FP rate → FP confidence.

1. **`deepseek/deepseek-chat-v3.1`** — TP 100%, FP noise 100%, strict FP 100%, FP conf 0.85, $0.00053/batch
2. **`deepseek/deepseek-v4-flash-0731`** — TP 100%, FP noise 100%, strict FP 100%, FP conf 0.80, $0.00068/batch
3. **`openrouter/auto@low`** — TP 100%, FP noise 100%, strict FP 100%, FP conf 0.80, $0.00062/batch
4. **`openrouter/auto@medium`** — TP 100%, FP noise 100%, strict FP 100%, FP conf 0.75, $0.00590/batch
5. **`anthropic/claude-opus-5`** — TP 100%, FP noise 100%, strict FP 100%, FP conf 0.60, $0.0217/batch
6. **`google/gemini-2.5-pro`** — TP 100%, FP noise 100%, strict FP 0%, FP conf 0.90, $0.0183/batch
7. **`z-ai/glm-4.5`** — TP 100%, FP noise 100%, strict FP 0%, FP conf 0.80, $0.0120/batch
8. **`anthropic/claude-sonnet-4.5`** — TP 100%, FP noise 100%, strict FP 0%, FP conf 0.68, $0.00915/batch

## Recommendation

**Top 3 bulk triage (cost-effective):** `deepseek/deepseek-chat-v3.1`, `openrouter/auto@low`, `deepseek/deepseek-v4-flash-0731`

**FP / confidence gate pick:** `anthropic/claude-opus-5`

_Gate rationale:_ prefer a model that marks noise as strict `likely_false_positive` (not only `needs_human`). Claude Opus is preferred when correct+strict because its lower FP confidence (~0.60 here) pairs safely with a high dismiss threshold (e.g. ≥0.7). Cheapest strict winners (DeepSeek / Auto@low) are excellent bulk routers but should not own auto-dismiss alone.

**Suggested two-tier routing:**
1. **Bulk triage / allowlisted fix suggestions** → `openrouter/auto@low` (cost leader among correct models: `deepseek/deepseek-chat-v3.1`).
2. **FP dismiss / confidence gate (MEDIUM+ candidates only)** → `anthropic/claude-opus-5` pinned; do not let bulk models auto-dismiss.
3. Escalate only `likely_false_positive` candidates from tier-1 to the gate model; keep secrets/malware never-dismissable.

## Skipped / failed models

- `qwen/qwen3-8b`: Expecting value: line 1 column 1 (char 0)

## Notes

- Rotate any API key that was pasted into chat or shell history.
- Re-run with `python scripts/benchmark_confidence.py --report docs/confidence-benchmark-report.md` after expanding fixtures.
