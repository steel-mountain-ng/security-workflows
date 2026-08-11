#!/usr/bin/env python3
"""Compare OpenRouter models on labeled TP/FP confidence scoring.

Usage:
  set OPENROUTER_API_KEY=...
  python scripts/benchmark_confidence.py

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

DEFAULT_MODELS = [
    "anthropic/claude-opus-5",
    "deepseek/deepseek-v4-flash-0731",
]

FALLBACK_MODELS = {
    "anthropic/claude-opus-5": "anthropic/claude-opus-4.8",
}


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


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


def call_openrouter(model: str, api_key: str, findings: list[dict[str, Any]]) -> tuple[dict[str, Any], str, int]:
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
    body = {
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
    req = urllib.request.Request(
        "https://openrouter.ai/api/v1/chat/completions",
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/steel-mountain-ng/security-workflows",
            "X-Title": "security-workflows confidence-benchmark",
        },
        method="POST",
    )
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{model} HTTP {exc.code}: {detail[:500]}") from exc
    latency_ms = int((time.perf_counter() - t0) * 1000)
    routed = str(payload.get("model") or model)
    message = (payload.get("choices") or [{}])[0].get("message") or {}
    content = message.get("content")
    if content is None:
        raise RuntimeError(f"{model} empty content (routed={routed})")
    if isinstance(content, list):
        content = "".join(part.get("text", "") for part in content if isinstance(part, dict))
    content = str(content).strip()
    if content.startswith("```"):
        content = content.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    return json.loads(content), routed, latency_ms


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
) -> list[dict[str, Any]]:
    slim = [slim_finding(f) for f in fixtures]
    triage, routed, latency_ms = call_openrouter(model, api_key, slim)
    by_id = {i.get("id"): i for i in (triage.get("findings") or []) if i.get("id")}
    rows: list[dict[str, Any]] = []
    per_item = max(latency_ms // max(len(fixtures), 1), 1)
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
                "model": model,
                "routed_model": routed,
                "classification": classification,
                "confidence": confidence,
                "latency_ms": per_item if len(by_id) > 1 else latency_ms,
                "batch_latency_ms": latency_ms,
                "agreement": agrees(str(f.get("ground_truth") or ""), classification),
                "remediation": (item.get("remediation") or "")[:160],
                "rationale": (item.get("rationale") or "")[:200],
            }
        )
    return rows


def print_table(rows: list[dict[str, Any]]) -> None:
    headers = [
        "finding_id",
        "ground_truth",
        "model",
        "classification",
        "confidence",
        "latency_ms",
        "agreement",
    ]
    widths = {h: len(h) for h in headers}
    for r in rows:
        for h in headers:
            widths[h] = max(widths[h], len(str(r.get(h, ""))))

    def fmt(r: dict[str, Any]) -> str:
        cells = []
        for h in headers:
            val = r.get(h)
            if h == "confidence" and isinstance(val, float):
                val = f"{val:.2f}"
            cells.append(str(val).ljust(widths[h]))
        return "  ".join(cells)

    print("  ".join(h.ljust(widths[h]) for h in headers))
    print("  ".join("-" * widths[h] for h in headers))
    for r in rows:
        print(fmt(r))


def recommend(rows: list[dict[str, Any]]) -> str:
    by_model: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        by_model.setdefault(r["model"], []).append(r)

    lines = ["", "### Recommendation", ""]
    for model, items in by_model.items():
        agree_n = sum(1 for i in items if i["agreement"])
        avg_conf = sum(float(i["confidence"]) for i in items) / max(len(items), 1)
        avg_lat = sum(int(i["batch_latency_ms"]) for i in items) / max(len(items), 1)
        # Prefer confidence on correct TP high and FP high when agreed
        tp = [i for i in items if i["ground_truth"] == "likely_true_positive"]
        fp = [i for i in items if i["ground_truth"] == "likely_false_positive"]
        tp_ok = all(i["agreement"] for i in tp) if tp else False
        fp_ok = all(i["agreement"] for i in fp) if fp else False
        lines.append(
            f"- **{model}**: agreement {agree_n}/{len(items)}, "
            f"avg confidence {avg_conf:.2f}, batch latency ~{avg_lat:.0f}ms, "
            f"TP_ok={tp_ok}, FP/noise_ok={fp_ok}"
        )

    # Heuristic pick: maximize agreement, then prefer higher confidence on agreed rows, then lower latency
    scored = []
    for model, items in by_model.items():
        agree_n = sum(1 for i in items if i["agreement"])
        avg_conf_agreed = (
            sum(float(i["confidence"]) for i in items if i["agreement"]) / max(agree_n, 1)
            if agree_n
            else 0
        )
        avg_lat = sum(int(i["batch_latency_ms"]) for i in items) / max(len(items), 1)
        scored.append((agree_n, avg_conf_agreed, -avg_lat, model))
    scored.sort(reverse=True)
    best = scored[0][3] if scored else "n/a"
    lines.extend(
        [
            "",
            f"**Confidence-scoring delegate:** `{best}` (best agreement / calibration proxy on this tiny set).",
            "",
            "**Suggested two-tier design:**",
            "- Bulk triage / allowlisted fix suggestions -> `openrouter/auto` or DeepSeek Flash (cheap/parallel).",
            "- FP dismiss / confidence gate (MEDIUM only) -> pin Claude Opus (or the winner above) on FP candidates only.",
            "- Do not let bulk models auto-dismiss; escalate only `likely_false_positive` candidates to the scorer.",
            "",
            "_Caveat: n=2 findings - treat as a smoke test, expand fixtures before policy changes._",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark confidence scoring models")
    parser.add_argument("--fixtures", type=Path, default=DEFAULT_FIXTURES)
    parser.add_argument(
        "--models",
        nargs="+",
        default=DEFAULT_MODELS,
        help="OpenRouter model ids",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=ROOT / "scripts" / "fixtures" / "confidence_benchmark_results.json",
        help="Write JSON results (no secrets)",
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
    print(f"Models: {', '.join(args.models)}")
    print()

    all_rows: list[dict[str, Any]] = []
    for model in args.models:
        try:
            rows = run_model(model, api_key, fixtures)
        except Exception as exc:  # noqa: BLE001
            fallback = FALLBACK_MODELS.get(model)
            if fallback:
                print(f"::warning::{model} failed ({exc}); trying {fallback}")
                try:
                    rows = run_model(fallback, api_key, fixtures)
                    for r in rows:
                        r["requested_model"] = model
                    all_rows.extend(rows)
                    continue
                except Exception as exc2:  # noqa: BLE001
                    print(f"::error::{fallback} also failed: {exc2}")
                    continue
            print(f"::error::{model} failed: {exc}")
            continue
        all_rows.extend(rows)

    if not all_rows:
        return 1

    print_table(all_rows)
    rec = recommend(all_rows)
    print(rec)

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write("### Confidence benchmark\n\n")
            fh.write("```\n")
            # re-print compact table
            for r in all_rows:
                fh.write(
                    f"{r['finding_id']} | gt={r['ground_truth']} | {r['model']} | "
                    f"{r['classification']} | conf={float(r['confidence']):.2f} | "
                    f"{r['latency_ms']}ms | agree={r['agreement']}\n"
                )
            fh.write("```\n")
            fh.write(rec + "\n")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({"rows": all_rows}, indent=2) + "\n", encoding="utf-8")
    print(f"\nWrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
