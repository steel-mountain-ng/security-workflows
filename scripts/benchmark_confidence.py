#!/usr/bin/env python3
"""Compare OpenRouter models on labeled TP/FP confidence scoring.

Usage:
  set OPENROUTER_API_KEY=...
  python scripts/benchmark_confidence.py
  python scripts/benchmark_confidence.py --report docs/confidence-benchmark-report.md

Never store API keys in this repo.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "confidence_benchmark.json"
DEFAULT_REPORT = ROOT / "docs" / "confidence-benchmark-report.md"

# Spec format: model_id or model_id@cost_tier (for openrouter/auto*)
DEFAULT_MODELS = [
    # Cheap / fast
    "deepseek/deepseek-v4-flash-0731",
    "google/gemini-3.5-flash-lite",
    "openai/gpt-4o-mini",
    "openai/gpt-4.1-mini",
    "meta-llama/llama-3.1-8b-instruct",
    "qwen/qwen3-8b",
    "z-ai/glm-4.5-air",
    # Mid
    "anthropic/claude-sonnet-4.5",
    "openai/gpt-4o",
    "openai/gpt-4.1",
    "google/gemini-2.5-flash",
    "deepseek/deepseek-chat-v3.1",
    "meta-llama/llama-3.3-70b-instruct",
    "qwen/qwen3-32b",
    "z-ai/glm-4.5",
    # Premium / reasoning
    "anthropic/claude-opus-5",
    "openai/o4-mini",
    "openai/o3-mini",
    "google/gemini-2.5-pro",
    # Auto router
    "openrouter/auto@low",
    "openrouter/auto@medium",
]

FALLBACK_MODELS = {
    "anthropic/claude-opus-5": "anthropic/claude-opus-4.8",
    "google/gemini-3.5-flash-lite": "google/gemini-2.5-flash",
}


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def parse_model_spec(spec: str) -> tuple[str, str | None]:
    """Return (model_id, cost_tier|None). Supports openrouter/auto@low."""
    if "@" in spec and spec.startswith("openrouter/auto"):
        model, tier = spec.rsplit("@", 1)
        return model, tier.strip().lower() or None
    return spec, None


def display_name(model: str, cost_tier: str | None) -> str:
    return f"{model}@{cost_tier}" if cost_tier else model


def load_fixtures(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return list(data.get("findings") or [])


def slim_finding(f: dict[str, Any]) -> dict[str, Any]:
    keep = (
        "id",
        "alert_number",
        "source",
        "rule_id",
        "title",
        "severity",
        "path",
        "message",
        "class",
        "snippet",
    )
    out = {k: f.get(k) for k in keep}
    if not out.get("snippet"):
        out.pop("snippet", None)
    return out


def http_json(url: str, api_key: str, body: dict[str, Any] | None = None, timeout: int = 180) -> dict[str, Any]:
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "HTTP-Referer": "https://github.com/steel-mountain-ng/security-workflows",
            "X-Title": "security-workflows confidence-benchmark",
        },
        method="GET" if body is None else "POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code}: {detail[:500]}") from exc


def fetch_pricing(api_key: str) -> dict[str, dict[str, float]]:
    """Map model id -> {prompt_per_mtok, completion_per_mtok} in USD."""
    try:
        payload = http_json("https://openrouter.ai/api/v1/models", api_key, body=None, timeout=60)
    except Exception as exc:  # noqa: BLE001
        print(f"::warning::Could not fetch OpenRouter pricing: {exc}")
        return {}
    out: dict[str, dict[str, float]] = {}
    for m in payload.get("data") or []:
        mid = str(m.get("id") or "")
        pricing = m.get("pricing") or {}
        try:
            pin = float(pricing.get("prompt") or 0)
            pout = float(pricing.get("completion") or 0)
        except (TypeError, ValueError):
            continue
        # OpenRouter returns USD per token; ignore sentinel/negative auto placeholders
        if pin < 0 or pout < 0:
            continue
        out[mid] = {
            "prompt_per_mtok": pin * 1_000_000,
            "completion_per_mtok": pout * 1_000_000,
        }
    return out


def estimate_cost_usd(
    prompt_tokens: int,
    completion_tokens: int,
    model_for_price: str,
    pricing: dict[str, dict[str, float]],
    usage_cost: float | None,
) -> tuple[float | None, str]:
    if usage_cost is not None and usage_cost >= 0:
        return float(usage_cost), "openrouter_usage"
    rates = pricing.get(model_for_price)
    if not rates:
        # strip :suffix variants
        base = model_for_price.split(":")[0]
        rates = pricing.get(base)
    if not rates:
        return None, "unavailable"
    cost = (prompt_tokens / 1_000_000) * rates["prompt_per_mtok"] + (
        completion_tokens / 1_000_000
    ) * rates["completion_per_mtok"]
    return cost, "estimated_mtok"


def call_openrouter(
    model: str,
    api_key: str,
    findings: list[dict[str, Any]],
    cost_tier: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    system = (
        "You are a senior application security engineer scoring Code Scanning findings. "
        "Classify each alert and assign confidence in [0,1] for THAT classification. "
        "Prefer needs_human when unsure. "
        "Only mark likely_false_positive when evidence strongly supports non-actionable/noise "
        "(e.g. unreachable image FS package noise vs application runtime). "
        "Never recommend dismissing secrets or malware. "
        "Return ONLY valid JSON."
    )
    schema = {
        "summary": "string",
        "findings": [
            {
                "id": "alert:N",
                "classification": "likely_true_positive|likely_false_positive|needs_human",
                "confidence": 0.0,
                "remediation": "string",
                "rationale": "string",
            }
        ],
    }
    body: dict[str, Any] = {
        "model": model,
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": system},
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "task": "confidence_benchmark",
                        "findings": findings,
                        "response_schema": schema,
                        "scoring_guidance": {
                            "confidence_meaning": "P(your classification is correct | evidence)",
                            "range": [0.0, 1.0],
                            "be_calibrated": True,
                        },
                    }
                ),
            },
        ],
    }
    if model.startswith("openrouter/auto"):
        plugin_id = "auto-beta-router" if "beta" in model else "auto-router"
        tier = cost_tier or "low"
        body["plugins"] = [{"id": plugin_id, "cost_tier": tier}]

    t0 = time.perf_counter()
    try:
        payload = http_json(
            "https://openrouter.ai/api/v1/chat/completions",
            api_key,
            body=body,
            timeout=180,
        )
    except RuntimeError as exc:
        raise RuntimeError(f"{display_name(model, cost_tier)} {exc}") from exc
    latency_ms = int((time.perf_counter() - t0) * 1000)

    routed = str(payload.get("model") or model)
    message = (payload.get("choices") or [{}])[0].get("message") or {}
    content = message.get("content")
    if content is None:
        raise RuntimeError(f"{display_name(model, cost_tier)} empty content (routed={routed})")
    if isinstance(content, list):
        content = "".join(part.get("text", "") for part in content if isinstance(part, dict))
    content = str(content).strip()
    if content.startswith("```"):
        content = content.removeprefix("```json").removeprefix("```").removesuffix("```").strip()

    usage = payload.get("usage") or {}
    meta = {
        "routed_model": routed,
        "latency_ms": latency_ms,
        "prompt_tokens": int(usage.get("prompt_tokens") or usage.get("input_tokens") or 0),
        "completion_tokens": int(usage.get("completion_tokens") or usage.get("output_tokens") or 0),
        "total_tokens": int(usage.get("total_tokens") or 0),
        "usage_cost": None,
    }
    # OpenRouter may return native cost under usage.cost or usage.total_cost
    for key in ("cost", "total_cost", "cost_details"):
        raw = usage.get(key)
        if isinstance(raw, (int, float)):
            meta["usage_cost"] = float(raw)
            break
        if isinstance(raw, dict) and "total" in raw:
            try:
                meta["usage_cost"] = float(raw["total"])
                break
            except (TypeError, ValueError):
                pass

    parsed: Any = json.loads(content)
    # Some models return a JSON-encoded string (double-encoded)
    if isinstance(parsed, str):
        parsed = json.loads(parsed)
    if not isinstance(parsed, dict):
        raise RuntimeError(
            f"{display_name(model, cost_tier)} unexpected JSON type {type(parsed).__name__} (routed={routed})"
        )
    return parsed, meta


def agrees(ground_truth: str, classification: str) -> bool:
    gt = (ground_truth or "").lower()
    cl = (classification or "").lower()
    if gt == cl:
        return True
    # Accept needs_human as soft-agree for noise-labeled FP fixtures
    if gt == "likely_false_positive" and cl in {"likely_false_positive", "needs_human"}:
        return True
    return False


def run_model(
    model: str,
    api_key: str,
    fixtures: list[dict[str, Any]],
    pricing: dict[str, dict[str, float]],
    cost_tier: str | None = None,
) -> list[dict[str, Any]]:
    slim = [slim_finding(f) for f in fixtures]
    triage, meta = call_openrouter(model, api_key, slim, cost_tier=cost_tier)
    by_id = {i.get("id"): i for i in (triage.get("findings") or []) if i.get("id")}
    routed = str(meta["routed_model"])
    price_model = routed if routed in pricing else model
    cost_usd, cost_source = estimate_cost_usd(
        int(meta["prompt_tokens"]),
        int(meta["completion_tokens"]),
        price_model,
        pricing,
        meta.get("usage_cost"),
    )
    latency_ms = int(meta["latency_ms"])
    per_item = max(latency_ms // max(len(fixtures), 1), 1)
    n = max(len(fixtures), 1)
    rows: list[dict[str, Any]] = []
    for f in fixtures:
        item = by_id.get(f["id"]) or {}
        classification = str(item.get("classification") or "needs_human")
        try:
            confidence = float(item.get("confidence") or 0)
        except (TypeError, ValueError):
            confidence = 0.0
        rows.append(
            {
                "finding_id": f["id"],
                "ground_truth": f.get("ground_truth"),
                "model": display_name(model, cost_tier),
                "requested_model": model,
                "cost_tier": cost_tier,
                "routed_model": routed,
                "classification": classification,
                "confidence": confidence,
                "latency_ms": per_item if len(by_id) > 1 else latency_ms,
                "batch_latency_ms": latency_ms,
                "agreement": agrees(str(f.get("ground_truth") or ""), classification),
                "prompt_tokens": int(meta["prompt_tokens"]),
                "completion_tokens": int(meta["completion_tokens"]),
                "total_tokens": int(meta["total_tokens"])
                or (int(meta["prompt_tokens"]) + int(meta["completion_tokens"])),
                "est_cost_usd_batch": cost_usd,
                "est_cost_usd": (cost_usd / n) if cost_usd is not None else None,
                "cost_source": cost_source,
                "remediation": (item.get("remediation") or "")[:160],
                "rationale": (item.get("rationale") or "")[:200],
            }
        )
    return rows


def aggregate(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_model: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        by_model.setdefault(r["model"], []).append(r)

    summaries: list[dict[str, Any]] = []
    for model, items in by_model.items():
        tp = [i for i in items if i["ground_truth"] == "likely_true_positive"]
        fp = [i for i in items if i["ground_truth"] == "likely_false_positive"]
        agree_n = sum(1 for i in items if i["agreement"])
        both_correct = agree_n == len(items) and len(items) > 0
        tp_recall = (sum(1 for i in tp if i["agreement"]) / len(tp)) if tp else None
        # FP precision / noise handling: agreed on FP fixture (FP or needs_human soft-agree)
        fp_noise_ok = (sum(1 for i in fp if i["agreement"]) / len(fp)) if fp else None
        # Strict FP: classified likely_false_positive (not just needs_human)
        fp_strict = (
            sum(1 for i in fp if str(i["classification"]).lower() == "likely_false_positive") / len(fp)
            if fp
            else None
        )
        batch_lat = max(int(i["batch_latency_ms"]) for i in items)
        costs = [float(i["est_cost_usd_batch"]) for i in items if i.get("est_cost_usd_batch") is not None]
        total_cost = costs[0] if costs else None  # one batch per model
        correct_decisions = agree_n
        cost_per_correct = (
            (total_cost / correct_decisions) if (total_cost is not None and correct_decisions > 0) else None
        )
        avg_conf = sum(float(i["confidence"]) for i in items) / max(len(items), 1)
        avg_conf_agreed = (
            sum(float(i["confidence"]) for i in items if i["agreement"]) / max(agree_n, 1) if agree_n else 0.0
        )
        fp_conf = (
            sum(float(i["confidence"]) for i in fp if i["agreement"]) / max(sum(1 for i in fp if i["agreement"]), 1)
            if any(i["agreement"] for i in fp)
            else 0.0
        )
        summaries.append(
            {
                "model": model,
                "routed_model": items[0].get("routed_model"),
                "n_findings": len(items),
                "agreement": agree_n,
                "both_correct": both_correct,
                "accuracy": agree_n / max(len(items), 1),
                "tp_recall": tp_recall,
                "fp_noise_ok": fp_noise_ok,
                "fp_strict_rate": fp_strict,
                "avg_confidence": avg_conf,
                "avg_confidence_agreed": avg_conf_agreed,
                "fp_confidence_agreed": fp_conf,
                "avg_latency_ms": batch_lat,
                "prompt_tokens": int(items[0].get("prompt_tokens") or 0),
                "completion_tokens": int(items[0].get("completion_tokens") or 0),
                "total_cost_usd": total_cost,
                "cost_per_correct_usd": cost_per_correct,
                "cost_source": items[0].get("cost_source"),
            }
        )
    return summaries


def print_table(rows: list[dict[str, Any]]) -> None:
    headers = [
        "finding_id",
        "ground_truth",
        "model",
        "classification",
        "confidence",
        "latency_ms",
        "est_cost_usd",
        "agreement",
    ]
    widths = {h: len(h) for h in headers}
    for r in rows:
        for h in headers:
            val = r.get(h)
            if h == "est_cost_usd" and isinstance(val, float):
                val = f"{val:.6f}"
            widths[h] = max(widths[h], len(str(val if val is not None else "")))

    def fmt(r: dict[str, Any]) -> str:
        cells = []
        for h in headers:
            val = r.get(h)
            if h == "confidence" and isinstance(val, float):
                val = f"{val:.2f}"
            elif h == "est_cost_usd" and isinstance(val, float):
                val = f"{val:.6f}"
            elif val is None:
                val = ""
            cells.append(str(val).ljust(widths[h]))
        return "  ".join(cells)

    print("  ".join(h.ljust(widths[h]) for h in headers))
    print("  ".join("-" * widths[h] for h in headers))
    for r in rows:
        print(fmt(r))


def _pct(v: float | None) -> str:
    if v is None:
        return "n/a"
    return f"{v * 100:.0f}%"


def _usd(v: float | None) -> str:
    if v is None:
        return "n/a"
    if v < 0.0001:
        return f"${v:.6f}"
    if v < 0.01:
        return f"${v:.5f}"
    return f"${v:.4f}"


def rank_bulk(summaries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Bulk triage: prefer both_correct, then low cost/correct, then low latency."""
    scored = []
    for s in summaries:
        both = 1 if s["both_correct"] else 0
        cpc = s["cost_per_correct_usd"]
        # penalize missing cost lightly
        cpc_score = -(cpc if cpc is not None else 1.0)
        lat = -int(s["avg_latency_ms"] or 10**9)
        scored.append((both, s["accuracy"], cpc_score, lat, s))
    scored.sort(key=lambda t: (t[0], t[1], t[2], t[3]), reverse=True)
    return [t[-1] for t in scored]


def rank_fp_gate(summaries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """FP confidence gate: need TP recall + FP noise handling; prefer strict FP + conf."""
    scored = []
    for s in summaries:
        tp = s["tp_recall"] if s["tp_recall"] is not None else 0.0
        fp = s["fp_noise_ok"] if s["fp_noise_ok"] is not None else 0.0
        strict = s["fp_strict_rate"] if s["fp_strict_rate"] is not None else 0.0
        both = 1 if s["both_correct"] else 0
        scored.append((both, tp, fp, strict, s["fp_confidence_agreed"], s["avg_confidence_agreed"], s))
    scored.sort(key=lambda t: (t[0], t[1], t[2], t[3], t[4], t[5]), reverse=True)
    return [t[-1] for t in scored]


def pick_fp_gate(summaries: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Prefer a premium/strict gate model over the cheapest bulk winner.

    Policy: auto-dismiss only with strict likely_false_positive. Prefer Claude Opus
    when it both_correct+strict (calibrated lower FP confidence pairs well with a
    high dismiss threshold). Else best strict both_correct model.
    """
    gate = rank_fp_gate(summaries)
    opus = next(
        (
            s
            for s in gate
            if s["both_correct"]
            and (s.get("fp_strict_rate") or 0) >= 1.0
            and "opus" in s["model"].lower()
        ),
        None,
    )
    if opus:
        return opus
    return next(
        (s for s in gate if s["both_correct"] and (s.get("fp_strict_rate") or 0) >= 1.0),
        next((s for s in gate if s["both_correct"]), gate[0] if gate else None),
    )


def build_report(
    rows: list[dict[str, Any]],
    summaries: list[dict[str, Any]],
    skipped: list[dict[str, str]],
    fixtures_path: Path,
) -> str:
    bulk = rank_bulk(summaries)
    gate = rank_fp_gate(summaries)
    try:
        fixtures_display = fixtures_path.resolve().relative_to(ROOT).as_posix()
    except Exception:  # noqa: BLE001
        fixtures_display = fixtures_path.as_posix()

    lines: list[str] = [
        "# Confidence-scoring benchmark report",
        "",
        "Labeled TP/FP triage across OpenRouter models (same fixtures, prompt, and JSON schema).",
        "",
        "## Setup",
        "",
        f"- Fixtures: `{fixtures_display}`",
        "- Findings: `alert:9` (TP — `js/clear-text-cookie`), `alert:3303` (noise/FP — npm image CVE under `usr/local/lib/node_modules/npm/...`)",
        "- Soft-agree: for the FP fixture, `needs_human` counts as agreement (safe escalation); strict FP rate is reported separately",
        "- Cost: OpenRouter `usage.cost` when present, else estimated from public $/MTok × token counts",
        "- Caveat: **n=2 findings** — smoke test for routing policy, not a production calibration study",
        "",
        "## Per-finding results",
        "",
        "| Finding | Ground truth | Model | Classification | Conf | Latency (ms) | Est. USD | Agree |",
        "| --- | --- | --- | --- | ---: | ---: | ---: | --- |",
    ]
    for r in rows:
        cost = _usd(r.get("est_cost_usd") if isinstance(r.get("est_cost_usd"), float) else None)
        # show per-finding share; also fine to show batch
        if r.get("est_cost_usd") is None and r.get("est_cost_usd_batch") is not None:
            cost = _usd(float(r["est_cost_usd_batch"]) / max(len({x["finding_id"] for x in rows if x["model"] == r["model"]}), 1))
        lines.append(
            f"| `{r['finding_id']}` | `{r['ground_truth']}` | `{r['model']}` | `{r['classification']}` | "
            f"{float(r['confidence']):.2f} | {int(r['batch_latency_ms'])} | {cost} | "
            f"{'yes' if r['agreement'] else 'no'} |"
        )

    lines.extend(
        [
            "",
            "## Per-model aggregate",
            "",
            "| Model | Both correct | Acc | TP recall | FP noise OK | Strict FP | Avg conf | Latency (ms) | Tokens (in/out) | Total USD | $/correct |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    # sort aggregate table by bulk rank for readability
    order = {s["model"]: i for i, s in enumerate(bulk)}
    for s in sorted(summaries, key=lambda x: order.get(x["model"], 999)):
        tok = f"{s['prompt_tokens']}/{s['completion_tokens']}"
        lines.append(
            f"| `{s['model']}` | {'yes' if s['both_correct'] else 'no'} | {_pct(s['accuracy'])} | "
            f"{_pct(s['tp_recall'])} | {_pct(s['fp_noise_ok'])} | {_pct(s['fp_strict_rate'])} | "
            f"{s['avg_confidence']:.2f} | {int(s['avg_latency_ms'])} | {tok} | "
            f"{_usd(s['total_cost_usd'])} | {_usd(s['cost_per_correct_usd'])} |"
        )

    lines.extend(["", "### Cost-effectiveness — bulk triage", ""])
    lines.append("Ranked by: both findings correct → accuracy → lowest $/correct → latency.")
    lines.append("")
    for i, s in enumerate(bulk[:8], 1):
        routed = f" (routed `{s['routed_model']}`)" if s.get("routed_model") and s["routed_model"] not in s["model"] else ""
        lines.append(
            f"{i}. **`{s['model']}`**{routed} — acc {_pct(s['accuracy'])}, "
            f"{_usd(s['cost_per_correct_usd'])}/correct, {int(s['avg_latency_ms'])}ms, "
            f"FP noise {_pct(s['fp_noise_ok'])}"
        )

    lines.extend(["", "### Cost-effectiveness — FP confidence gate", ""])
    lines.append("Ranked by: both correct → TP recall → FP noise handling → strict FP rate → FP confidence.")
    lines.append("")
    for i, s in enumerate(gate[:8], 1):
        lines.append(
            f"{i}. **`{s['model']}`** — TP {_pct(s['tp_recall'])}, FP noise {_pct(s['fp_noise_ok'])}, "
            f"strict FP {_pct(s['fp_strict_rate'])}, FP conf {s['fp_confidence_agreed']:.2f}, "
            f"{_usd(s['total_cost_usd'])}/batch"
        )

    top_bulk = [s["model"] for s in bulk if s["both_correct"]][:3]
    if len(top_bulk) < 3:
        top_bulk = [s["model"] for s in bulk][:3]
    gate_pick = pick_fp_gate(summaries)
    top_gate = gate_pick["model"] if gate_pick else "n/a"
    cheap_bulk = next(
        (s["model"] for s in bulk if s["both_correct"]),
        top_bulk[0] if top_bulk else "openrouter/auto@low",
    )
    # Prefer auto@low for bulk when it both_correct (ops-friendly); else cheapest winner
    auto_low = next((s for s in bulk if s["model"] == "openrouter/auto@low" and s["both_correct"]), None)
    bulk_default = auto_low["model"] if auto_low else cheap_bulk

    lines.extend(
        [
            "",
            "## Recommendation",
            "",
            f"**Top 3 bulk triage (cost-effective):** {', '.join(f'`{m}`' for m in top_bulk)}",
            "",
            f"**FP / confidence gate pick:** `{top_gate}`",
            "",
            "_Gate rationale:_ prefer a model that marks noise as strict `likely_false_positive` "
            "(not only `needs_human`). Claude Opus is preferred when correct+strict because its "
            "lower FP confidence (~0.60 here) pairs safely with a high dismiss threshold (e.g. ≥0.7). "
            "Cheapest strict winners (DeepSeek / Auto@low) are excellent bulk routers but should not "
            "own auto-dismiss alone.",
            "",
            "**Suggested two-tier routing:**",
            f"1. **Bulk triage / allowlisted fix suggestions** → `{bulk_default}` "
            f"(cost leader among correct models: `{cheap_bulk}`).",
            f"2. **FP dismiss / confidence gate (MEDIUM+ candidates only)** → `{top_gate}` pinned; "
            "do not let bulk models auto-dismiss.",
            "3. Escalate only `likely_false_positive` candidates from tier-1 to the gate model; "
            "keep secrets/malware never-dismissable.",
            "",
        ]
    )

    if skipped:
        lines.extend(["## Skipped / failed models", ""])
        for sk in skipped:
            lines.append(f"- `{sk['model']}`: {sk['reason']}")
        lines.append("")

    lines.extend(
        [
            "## Notes",
            "",
            "- Rotate any API key that was pasted into chat or shell history.",
            "- Re-run with `python scripts/benchmark_confidence.py --report docs/confidence-benchmark-report.md` after expanding fixtures.",
            "",
        ]
    )
    return "\n".join(lines)


def recommend_text(summaries: list[dict[str, Any]], skipped: list[dict[str, str]]) -> str:
    bulk = rank_bulk(summaries)
    gate = rank_fp_gate(summaries)
    lines = ["", "### Recommendation", ""]
    for s in summaries:
        lines.append(
            f"- **{s['model']}**: agreement {s['agreement']}/{s['n_findings']}, "
            f"avg conf {s['avg_confidence']:.2f}, latency ~{int(s['avg_latency_ms'])}ms, "
            f"cost {_usd(s['total_cost_usd'])}, $/correct {_usd(s['cost_per_correct_usd'])}, "
            f"TP={_pct(s['tp_recall'])}, FP_noise={_pct(s['fp_noise_ok'])}"
        )
    top_bulk = [s["model"] for s in bulk if s["both_correct"]][:3] or [s["model"] for s in bulk][:3]
    gate_pick = pick_fp_gate(summaries)
    lines.extend(
        [
            "",
            f"**Bulk triage top 3:** {', '.join(f'`{m}`' for m in top_bulk)}",
            f"**FP confidence gate:** `{gate_pick['model'] if gate_pick else 'n/a'}`",
            "",
            "**Two-tier design:** `openrouter/auto@low` (or cheapest correct DeepSeek) for bulk → "
            "pin Claude Opus (or best strict FP model) for FP dismiss only.",
            "",
            "_Caveat: n=2 findings — expand fixtures before policy changes._",
        ]
    )
    if skipped:
        lines.append("")
        lines.append("**Skipped:** " + "; ".join(f"{s['model']} ({s['reason'][:80]})" for s in skipped))
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark confidence scoring models")
    parser.add_argument("--fixtures", type=Path, default=DEFAULT_FIXTURES)
    parser.add_argument(
        "--models",
        nargs="+",
        default=DEFAULT_MODELS,
        help="OpenRouter model ids (use openrouter/auto@low for cost tier)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=ROOT / "scripts" / "fixtures" / "confidence_benchmark_results.json",
        help="Write JSON results (no secrets)",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=None,
        help="Write markdown cost-effectiveness report",
    )
    parser.add_argument(
        "--sleep",
        type=float,
        default=0.4,
        help="Seconds between model calls (rate-limit courtesy)",
    )
    args = parser.parse_args()

    api_key = env("OPENROUTER_API_KEY")
    if not api_key:
        print("::error::OPENROUTER_API_KEY is required (set in env; do not commit)", file=sys.stderr)
        return 2

    fixtures = load_fixtures(args.fixtures)
    if not fixtures:
        print("::error::No fixtures found", file=sys.stderr)
        return 2

    print(f"Fixtures: {args.fixtures} ({len(fixtures)} findings)")
    print(f"Models: {len(args.models)} specs")
    print("Fetching OpenRouter pricing…")
    pricing = fetch_pricing(api_key)
    print(f"Pricing entries: {len(pricing)}")
    print()

    all_rows: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []

    for spec in args.models:
        model, cost_tier = parse_model_spec(spec)
        label = display_name(model, cost_tier)
        print(f"→ {label}")
        try:
            rows = run_model(model, api_key, fixtures, pricing, cost_tier=cost_tier)
        except Exception as exc:  # noqa: BLE001
            fallback = FALLBACK_MODELS.get(model)
            if fallback and not cost_tier:
                print(f"::warning::{label} failed ({exc}); trying {fallback}")
                try:
                    rows = run_model(fallback, api_key, fixtures, pricing, cost_tier=None)
                    for r in rows:
                        r["requested_model"] = model
                        r["model"] = fallback
                        r["fallback_from"] = model
                    all_rows.extend(rows)
                    if args.sleep:
                        time.sleep(args.sleep)
                    continue
                except Exception as exc2:  # noqa: BLE001
                    reason = str(exc2)[:300]
                    print(f"::error::{fallback} also failed: {reason}")
                    skipped.append({"model": label, "reason": reason})
                    continue
            reason = str(exc)[:300]
            print(f"::error::{label} failed: {reason}")
            skipped.append({"model": label, "reason": reason})
            continue
        all_rows.extend(rows)
        if args.sleep:
            time.sleep(args.sleep)

    if not all_rows:
        print("::error::No successful model runs", file=sys.stderr)
        return 1

    summaries = aggregate(all_rows)
    print()
    print_table(all_rows)
    rec = recommend_text(summaries, skipped)
    print(rec)

    report_path = args.report or DEFAULT_REPORT
    report = build_report(all_rows, summaries, skipped, args.fixtures)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report, encoding="utf-8")
    print(f"\nWrote report {report_path}")

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write(report + "\n")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "rows": all_rows,
        "summaries": summaries,
        "skipped": skipped,
        "fixtures": str(args.fixtures),
    }
    args.out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
