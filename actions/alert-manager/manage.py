#!/usr/bin/env python3
"""Manage open Code Scanning alerts: dismiss LOWs, AI FP dismiss, draft fix PRs."""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from fix_helpers import (
    AUTO_FIX_ALLOWLIST,
    NEVER_AUTO_FIX_SOURCES,
    open_draft_fix_prs,
)

LOW_SEVERITIES = {"low", "note", "none", "unknown"}
HIGH_SEVERITIES = {"critical", "high", "error"}
SECRET_HINTS = ("secret", "private-key", "password", "credential", "aws-access", "token")


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def write_output(name: str, value: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(f"{name}={value}\n")


def append_summary(text: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(text + "\n")


def gh_api(method: str, path: str, body: dict[str, Any] | None = None) -> Any:
    token = env("GITHUB_TOKEN")
    repo = env("GITHUB_REPOSITORY")
    if not token or not repo:
        raise RuntimeError("GITHUB_TOKEN and GITHUB_REPOSITORY are required")
    url = path if path.startswith("http") else f"https://api.github.com{path}"
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"GitHub API {method} {path} -> {exc.code}: {detail}") from exc


def list_open_alerts() -> list[dict[str, Any]]:
    repo = env("GITHUB_REPOSITORY")
    owner, name = repo.split("/", 1)
    alerts: list[dict[str, Any]] = []
    page = 1
    while True:
        qs = urllib.parse.urlencode({"state": "open", "per_page": 100, "page": page})
        batch = gh_api("GET", f"/repos/{owner}/{name}/code-scanning/alerts?{qs}")
        if not batch:
            break
        alerts.extend(batch)
        if len(batch) < 100:
            break
        page += 1
        if page > 50:
            break
    return alerts


def alert_severity(alert: dict[str, Any]) -> str:
    rule = alert.get("rule") or {}
    sev = (
        rule.get("security_severity_level")
        or rule.get("severity")
        or alert.get("security_severity_level")
        or "unknown"
    )
    return str(sev).lower()


def is_low(alert: dict[str, Any]) -> bool:
    return alert_severity(alert) in LOW_SEVERITIES


def is_secretish(alert: dict[str, Any]) -> bool:
    rule = alert.get("rule") or {}
    tool = ((alert.get("tool") or {}).get("name") or "").lower()
    blob = " ".join(
        [
            str(rule.get("id") or ""),
            str(rule.get("name") or ""),
            str(rule.get("description") or ""),
            tool,
            str(alert.get("most_recent_instance", {}).get("category") or ""),
        ]
    ).lower()
    return any(h in blob for h in SECRET_HINTS) or "secret" in tool


def dismiss_alert(number: int, reason: str, comment: str) -> None:
    repo = env("GITHUB_REPOSITORY")
    owner, name = repo.split("/", 1)
    gh_api(
        "PATCH",
        f"/repos/{owner}/{name}/code-scanning/alerts/{number}",
        {
            "state": "dismissed",
            "dismissed_reason": reason,
            "dismissed_comment": comment[:280],
        },
    )


def mask_secrets(text: str) -> str:
    patterns = [
        (r"(?i)(aws_secret_access_key\s*[=:]\s*)(\S+)", r"\1***REDACTED***"),
        (r"(?i)(aws_access_key_id\s*[=:]\s*)(AKIA[0-9A-Z]{16})", r"\1AKIA****************"),
        (r"(ghp_[A-Za-z0-9]{20,})", "***REDACTED_GITHUB_TOKEN***"),
        (
            r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)(.*?)(-----END [A-Z ]*PRIVATE KEY-----)",
            r"\1\n***REDACTED PRIVATE KEY***\n\3",
        ),
    ]
    out = text
    for pattern, repl in patterns:
        out = re.sub(pattern, repl, out, flags=re.DOTALL)
    return out


def read_snippet(repo_root: Path, path: str, start: int | None, end: int | None, pad: int = 12) -> str:
    if not path:
        return ""
    file_path = repo_root / path
    if not file_path.is_file():
        return ""
    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    if not lines:
        return ""
    s = max((start or 1) - pad, 1)
    e = min((end or start or 1) + pad, len(lines))
    chunk = "\n".join(f"{i}:{lines[i - 1]}" for i in range(s, e + 1))
    return mask_secrets(chunk)[:2000]


def normalize_alert(alert: dict[str, Any], repo_root: Path, *, include_snippet: bool = False) -> dict[str, Any]:
    rule = alert.get("rule") or {}
    inst = alert.get("most_recent_instance") or {}
    loc = (inst.get("location") or {}) if isinstance(inst, dict) else {}
    path = loc.get("path") or ""
    start = loc.get("start_line")
    end = loc.get("end_line") or start
    tool = ((alert.get("tool") or {}).get("name") or "code-scanning").lower()
    sev = alert_severity(alert).upper()
    if sev in {"NOTE", "NONE"}:
        sev = "LOW"
    if sev == "ERROR":
        sev = "HIGH"
    class_ = "secret" if is_secretish(alert) else "code-scanning"
    source = "trivy-secrets" if class_ == "secret" else tool.replace(" ", "-")
    message = (
        (inst.get("message") or {}).get("text")
        if isinstance(inst.get("message"), dict)
        else str(inst.get("message") or "")
    )
    path_l = path.lower()
    want_snippet = include_snippet or path_l == "dockerfile" or path_l.endswith("/dockerfile")
    return {
        "id": f"alert:{alert.get('number')}",
        "alert_number": alert.get("number"),
        "source": source,
        "rule_id": rule.get("id") or rule.get("name") or "unknown",
        "title": rule.get("description") or rule.get("name") or rule.get("id") or "alert",
        "severity": sev,
        "path": path,
        "start_line": start,
        "end_line": end,
        "message": (message or "")[:500],
        "fixed_version": None,
        "package": None,
        "auto_fix_type": None,
        "class": class_,
        "snippet": read_snippet(repo_root, path, start, end) if want_snippet else "",
        "html_url": alert.get("html_url"),
    }


def slim_for_model(finding: dict[str, Any]) -> dict[str, Any]:
    """Drop bulky fields for OpenRouter payloads."""
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
    out = {k: finding.get(k) for k in keep}
    if not out.get("snippet"):
        out.pop("snippet", None)
    return out


def chunked(items: list[Any], size: int) -> list[list[Any]]:
    if size <= 0:
        return [items]
    return [items[i : i + size] for i in range(0, len(items), size)]


def _normalize_batch_items(
    batch: list[dict[str, Any]], items: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    by_id = {i.get("id"): i for i in items if i.get("id")}
    out: list[dict[str, Any]] = []
    for f in batch:
        if f["id"] in by_id:
            out.append(by_id[f["id"]])
        else:
            out.append(
                {
                    "id": f["id"],
                    "classification": "needs_human",
                    "confidence": 0.4,
                    "remediation": "Model omitted this alert; left for human review.",
                    "auto_fix_eligible": False,
                    "auto_fix_type": None,
                    "dismiss_as_fp": False,
                }
            )
    return out


def _review_one_batch(
    idx: int,
    total: int,
    batch: list[dict[str, Any]],
    *,
    model: str,
    api_key: str,
    cost_tier: str | None,
    purpose: str,
    label_prefix: str,
) -> tuple[int, list[dict[str, Any]], str, bool, str]:
    """Worker: review one batch. Returns (idx, items, summary, fallback, routed_model)."""
    label = (
        f"{label_prefix} {idx}/{total}: "
        + ", ".join(f"#{f.get('alert_number')}:{f.get('rule_id')}" for f in batch[:6])
        + (" ..." if len(batch) > 6 else "")
    )
    print(label, flush=True)
    try:
        triage, routed = call_openrouter(
            model,
            api_key,
            [slim_for_model(f) for f in batch],
            cost_tier=cost_tier,
            purpose=purpose,
        )
        items = _normalize_batch_items(batch, triage.get("findings") or [])
        summary = str(triage.get("summary") or f"Batch {idx} ok ({routed})")
        print(f"{label_prefix} {idx}/{total} done via {routed}", flush=True)
        return idx, items, summary, False, routed
    except Exception as exc:  # noqa: BLE001
        print(f"::warning::{label_prefix} {idx}/{total} failed: {exc}", flush=True)
        if purpose == "fp_gate":
            # Do not invent FPs on gate failure — force needs_human
            items = [
                {
                    "id": f["id"],
                    "classification": "needs_human",
                    "confidence": 0.3,
                    "remediation": "FP gate failed; left for human review.",
                    "auto_fix_eligible": False,
                    "auto_fix_type": None,
                    "dismiss_as_fp": False,
                }
                for f in batch
            ]
            return idx, items, f"FP gate batch {idx} failed.", True, "fp-gate-error"
        fallback = heuristic_review(batch)
        return idx, fallback.get("findings") or [], f"Batch {idx} heuristic fallback.", True, "heuristic"


def review_findings_batched(
    findings: list[dict[str, Any]],
    *,
    model: str,
    api_key: str,
    batch_size: int,
    concurrency: int,
    cost_tier: str | None = None,
    purpose: str = "bulk",
    label_prefix: str = "AI bulk agent",
) -> dict[str, Any]:
    """Send findings to OpenRouter in parallel agent batches; merge classifications."""
    if not findings:
        return {"summary": "No findings to review.", "findings": [], "fallback": False}

    if not api_key:
        print("::warning::OPENROUTER_API_KEY missing; heuristic review only")
        return heuristic_review(findings)

    batches = chunked(findings, batch_size)
    workers = max(1, min(concurrency, len(batches)))
    print(
        f"{label_prefix}: {len(findings)} alert(s), {len(batches)} batch(es) "
        f"x up to {batch_size}, concurrency={workers}, model={model}, purpose={purpose}"
    )

    results: dict[int, tuple[list[dict[str, Any]], str, bool, str]] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(
                _review_one_batch,
                idx,
                len(batches),
                batch,
                model=model,
                api_key=api_key,
                cost_tier=cost_tier,
                purpose=purpose,
                label_prefix=label_prefix,
            ): idx
            for idx, batch in enumerate(batches, start=1)
        }
        for fut in as_completed(futures):
            idx, items, summary, fallback, routed = fut.result()
            results[idx] = (items, summary, fallback, routed)

    merged: list[dict[str, Any]] = []
    summaries: list[str] = []
    routed_models: list[str] = []
    any_fallback = False
    for idx in sorted(results):
        items, summary, fallback, routed = results[idx]
        merged.extend(items)
        summaries.append(summary)
        routed_models.append(routed)
        any_fallback = any_fallback or fallback

    unique_routes = sorted({m for m in routed_models if m and m not in {"heuristic", "fp-gate-error"}})
    if unique_routes:
        print(f"{label_prefix} routed models: {', '.join(unique_routes)}")

    return {
        "summary": " | ".join(summaries)[:2000] or f"Reviewed {len(merged)} alert(s).",
        "findings": merged,
        "fallback": any_fallback,
        "routed_models": unique_routes,
    }


def rescore_fp_candidates(
    triage_items: list[dict[str, Any]],
    findings_by_id: dict[str, dict[str, Any]],
    *,
    fp_model: str,
    api_key: str,
    batch_size: int,
    concurrency: int,
    repo_root: Path,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Second-tier Opus (or pinned) gate: overwrite bulk FP guesses with gate scores."""
    candidate_ids: list[str] = []
    for item in triage_items:
        if item.get("dismiss_as_fp") or item.get("classification") == "likely_false_positive":
            fid = item.get("id")
            if fid:
                candidate_ids.append(str(fid))

    if not candidate_ids:
        print("FP gate: no likely_false_positive candidates from bulk tier")
        return triage_items, []

    # Enrich with snippets for better FP judgment
    gate_findings: list[dict[str, Any]] = []
    for fid in candidate_ids:
        base = findings_by_id.get(fid)
        if not base:
            continue
        enriched = dict(base)
        if not enriched.get("snippet"):
            enriched["snippet"] = read_snippet(
                repo_root,
                str(enriched.get("path") or ""),
                enriched.get("start_line"),
                enriched.get("end_line"),
            )
        # Carry bulk opinion for the gate model
        bulk = next((i for i in triage_items if i.get("id") == fid), {})
        enriched["bulk_classification"] = bulk.get("classification")
        enriched["bulk_confidence"] = bulk.get("confidence")
        gate_findings.append(enriched)

    print(f"FP gate: re-scoring {len(gate_findings)} candidate(s) with {fp_model}")
    gate = review_findings_batched(
        gate_findings,
        model=fp_model,
        api_key=api_key,
        batch_size=max(min(batch_size, 15), 1),
        concurrency=max(min(concurrency, 4), 1),
        cost_tier=None,
        purpose="fp_gate",
        label_prefix="AI FP gate",
    )
    by_id = {i.get("id"): i for i in (gate.get("findings") or []) if i.get("id")}
    merged: list[dict[str, Any]] = []
    for item in triage_items:
        fid = item.get("id")
        if fid in by_id:
            gated = dict(item)
            g = by_id[fid]
            for key in (
                "classification",
                "confidence",
                "dismiss_as_fp",
                "remediation",
                "exploitability",
                "reachability",
                "business_impact",
                "patch_sketch",
                "auto_fix_eligible",
                "auto_fix_type",
            ):
                if key in g:
                    gated[key] = g[key]
            gated["fp_gate_model"] = fp_model
            gated["bulk_classification"] = item.get("classification")
            gated["bulk_confidence"] = item.get("confidence")
            merged.append(gated)
        else:
            merged.append(item)
    return merged, gate.get("routed_models") or [fp_model]


def call_openrouter(
    model: str,
    api_key: str,
    findings: list[dict[str, Any]],
    *,
    cost_tier: str | None = None,
    purpose: str = "bulk",
) -> tuple[dict[str, Any], str]:
    """Call OpenRouter chat completions. Returns (triage_json, routed_model)."""
    if purpose == "fp_gate":
        system = (
            "You are a senior application security engineer acting as a FALSE-POSITIVE gate. "
            "These alerts were flagged as possible false positives by a cheaper bulk model. "
            "Re-score carefully. Prefer needs_human when unsure. "
            "Only mark likely_false_positive when evidence strongly supports non-actionable noise. "
            "Never recommend dismissing secrets, malware, or clearly exploitable app bugs. "
            "Never approve auto-dismiss for CRITICAL/HIGH. "
            "Return ONLY valid JSON."
        )
    else:
        system = (
            "You are a senior application security engineer managing a Code Scanning backlog. "
            "Classify each alert. Prefer needs_human when unsure. "
            "Only mark likely_false_positive when evidence strongly supports it. "
            "Never recommend dismissing secrets or malware. "
            "Never auto-dismiss CRITICAL/HIGH. "
            "Return ONLY valid JSON."
        )
    schema = {
        "summary": "string",
        "findings": [
            {
                "id": "alert:N",
                "classification": "likely_true_positive|likely_false_positive|needs_human",
                "confidence": 0.0,
                "exploitability": "string",
                "reachability": "string",
                "business_impact": "string",
                "remediation": "string",
                "patch_sketch": "string",
                "auto_fix_eligible": False,
                "auto_fix_type": "dockerfile_user_root|dependency_fixed_version|base_image_update|null",
                "dismiss_as_fp": False,
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
                        "repository": env("GITHUB_REPOSITORY"),
                        "findings": findings,
                        "response_schema": schema,
                        "rules": {
                            "never_auto_fix_sources": sorted(NEVER_AUTO_FIX_SOURCES),
                            "auto_fix_allowlist": sorted(AUTO_FIX_ALLOWLIST),
                            "never_dismiss_critical_high": True,
                            "never_dismiss_secrets": True,
                        },
                    }
                ),
            },
        ],
    }
    # Prefer OpenRouter Auto Router when using openrouter/auto*
    if model.startswith("openrouter/auto"):
        plugin_id = "auto-beta-router" if "beta" in model else "auto-router"
        tier = (cost_tier or env("AI_COST_TIER", "medium") or "medium").strip()
        body["plugins"] = [{"id": plugin_id, "cost_tier": tier}]

    req = urllib.request.Request(
        "https://openrouter.ai/api/v1/chat/completions",
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": env("GITHUB_SERVER_URL", "https://github.com"),
            "X-Title": "steel-mountain-ng security-workflows alert-manager",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=180) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    routed = str(payload.get("model") or model)
    choices = payload.get("choices") or []
    if not choices:
        raise RuntimeError(f"OpenRouter returned no choices (model={routed}): {json.dumps(payload)[:500]}")
    message = (choices[0] or {}).get("message") or {}
    content = message.get("content")
    if isinstance(content, list):
        content = "".join(part.get("text", "") for part in content if isinstance(part, dict))
    if content is None:
        # Some routed models return tool/refusal payloads without text content
        raise RuntimeError(
            f"OpenRouter empty content (model={routed}): {json.dumps(message)[:500]}"
        )
    content = str(content).strip()
    if not content:
        raise RuntimeError(f"OpenRouter blank content (model={routed})")
    if content.startswith("```"):
        content = re.sub(r"^```(?:json)?\s*", "", content)
        content = re.sub(r"\s*```$", "", content)
    return json.loads(content), routed


def heuristic_review(findings: list[dict[str, Any]]) -> dict[str, Any]:
    items = []
    for f in findings:
        fix_type = None
        eligible = False
        title = (f.get("title") or "").lower()
        path = (f.get("path") or "").lower()
        rule = (f.get("rule_id") or "").lower()
        blob = f"{title} {rule}"
        if ("dockerfile" in path or path.endswith("dockerfile")) and "user" in blob and "root" in blob:
            fix_type = "dockerfile_user_root"
            eligible = True
        elif path.endswith("dockerfile") or path == "dockerfile" or path.endswith("/dockerfile"):
            if any(k in blob for k in ("from", "base", "image", "vuln", "cve")):
                fix_type = "base_image_update"
                eligible = True
        # Allowlisted mechanical matches get threshold-passing confidence; never FP-dismiss without AI
        confidence = 0.8 if eligible else 0.55
        items.append(
            {
                "id": f["id"],
                "classification": "needs_human" if f.get("severity") in {"CRITICAL", "HIGH"} else "likely_true_positive",
                "confidence": confidence,
                "exploitability": "Heuristic only — model unavailable.",
                "reachability": "Not analyzed (fallback).",
                "business_impact": f.get("severity"),
                "remediation": f.get("message") or f.get("title") or "",
                "patch_sketch": "FROM node:20-bookworm-slim" if fix_type == "base_image_update" else "",
                "auto_fix_eligible": eligible,
                "auto_fix_type": fix_type,
                "dismiss_as_fp": False,
            }
        )
    return {"summary": f"Heuristic review of {len(findings)} alert(s).", "findings": items, "fallback": True}


def main() -> int:
    dismiss_lows = env("DISMISS_LOWS", "true").lower() == "true"
    ai_review = env("AI_REVIEW", "true").lower() == "true"
    open_fix_prs = env("AI_OPEN_FIX_PRS", "false").lower() == "true"
    # 0 / negative => review all open non-LOW alerts
    max_alerts = int(env("AI_MAX_ALERTS", "0") or 0)
    batch_size = int(env("AI_BATCH_SIZE", "40") or 40)
    concurrency = int(env("AI_CONCURRENCY", "8") or 8)
    fp_confidence = float(env("AI_FP_CONFIDENCE", "0.85") or 0.85)
    fix_confidence = float(env("AI_FIX_CONFIDENCE", "0.7") or 0.7)
    model = env("AI_MODEL", "openrouter/auto") or "openrouter/auto"
    cost_tier = env("AI_COST_TIER", "medium") or "medium"
    fp_model = env("AI_FP_MODEL", "anthropic/claude-opus-5") or "anthropic/claude-opus-5"
    api_key = env("OPENROUTER_API_KEY")
    repo_root = Path(env("AI_REPO_ROOT", ".")).resolve()

    print("Listing open Code Scanning alerts...")
    try:
        alerts = list_open_alerts()
    except Exception as exc:  # noqa: BLE001
        print(f"::error::Failed to list alerts: {exc}")
        write_output("dismissed-lows", "0")
        write_output("dismissed-fps", "0")
        write_output("fix-pr-urls", "")
        return 1

    print(f"Open alerts: {len(alerts)}")
    lows = [a for a in alerts if is_low(a)]
    others = [a for a in alerts if not is_low(a)]

    dismissed_lows = 0
    if dismiss_lows:
        for alert in lows:
            number = alert.get("number")
            if number is None:
                continue
            try:
                dismiss_alert(
                    int(number),
                    "won't fix",
                    "Org policy: LOW severity auto-dismissed by security-workflows alert manager",
                )
                dismissed_lows += 1
                print(f"Dismissed LOW alert #{number}")
            except Exception as exc:  # noqa: BLE001
                print(f"::warning::Failed to dismiss LOW alert #{number}: {exc}")

    write_output("dismissed-lows", str(dismissed_lows))
    append_summary("### Alert manager")
    append_summary("")
    append_summary(f"- Open alerts seen: **{len(alerts)}**")
    append_summary(f"- LOW dismissed (policy): **{dismissed_lows}**")

    dismissed_fps = 0
    fix_urls: list[str] = []
    triage: dict[str, Any] = {"summary": "No AI review", "findings": []}

    if ai_review and others:
        # Prefer allowlisted fix targets first, then MEDIUM, then HIGH/CRITICAL
        def _batch_rank(alert: dict[str, Any]) -> tuple[int, int, str]:
            path = str(((alert.get("most_recent_instance") or {}).get("location") or {}).get("path") or "").lower()
            rule = str((alert.get("rule") or {}).get("id") or "").lower()
            sev = alert_severity(alert)
            is_dockerfile = path == "dockerfile" or path.endswith("/dockerfile")
            is_app_manifest = path in {"package.json", "package-lock.json"} or (
                path.endswith("package.json")
                and "/node_modules/" not in path
                and not path.startswith("usr/")
            )
            fixable = int(is_dockerfile or is_app_manifest)
            sev_rank = 0 if sev == "medium" else 1 if sev in {"high", "critical", "error"} else 2
            return (0 if fixable else 1, sev_rank, rule)

        others_sorted = sorted(others, key=_batch_rank)
        if max_alerts > 0:
            others_sorted = others_sorted[:max_alerts]
            print(f"Capping AI review at {max_alerts} alert(s)")
        else:
            print(f"AI review scope: ALL {len(others_sorted)} non-LOW open alert(s)")

        findings = [normalize_alert(a, repo_root, include_snippet=False) for a in others_sorted]
        findings_by_id = {f["id"]: f for f in findings}

        # Tier 1: bulk classify (OpenRouter Auto @ medium by default)
        triage = review_findings_batched(
            findings,
            model=model,
            api_key=api_key,
            batch_size=max(batch_size, 1),
            concurrency=max(concurrency, 1),
            cost_tier=cost_tier,
            purpose="bulk",
            label_prefix="AI bulk agent",
        )

        bulk_fp_candidates = sum(
            1
            for i in (triage.get("findings") or [])
            if i.get("dismiss_as_fp") or i.get("classification") == "likely_false_positive"
        )
        print(
            f"Bulk findings={len(triage.get('findings') or [])} "
            f"fp_candidates={bulk_fp_candidates} fallback={bool(triage.get('fallback'))}"
        )

        # Tier 2: Claude Opus FP gate — only gate may authorize dismiss
        fp_routed: list[str] = []
        if api_key and fp_model:
            gated_items, fp_routed = rescore_fp_candidates(
                triage.get("findings") or [],
                findings_by_id,
                fp_model=fp_model,
                api_key=api_key,
                batch_size=max(batch_size, 1),
                concurrency=max(concurrency, 1),
                repo_root=repo_root,
            )
            triage["findings"] = gated_items
            triage["fp_gate_model"] = fp_model
            triage["fp_gate_routed_models"] = fp_routed

        eligible_pre = sum(1 for i in (triage.get("findings") or []) if i.get("auto_fix_eligible"))
        fp_after_gate = sum(
            1
            for i in (triage.get("findings") or [])
            if i.get("dismiss_as_fp") or i.get("classification") == "likely_false_positive"
        )
        print(
            f"After FP gate: fp_candidates={fp_after_gate} eligible_fixes={eligible_pre} "
            f"gate_model={fp_model}"
        )

        for item in triage.get("findings") or []:
            base = findings_by_id.get(item.get("id") or "", {})
            sev = (base.get("severity") or "").upper()
            secretish = base.get("class") == "secret" or is_secretish(
                {"rule": {"id": base.get("rule_id"), "description": base.get("title")}, "tool": {"name": base.get("source")}}
            )

            # Dismiss only after Opus/fp-gate confirmation (MEDIUM + non-secret + high conf)
            gate_ok = (not fp_model) or bool(item.get("fp_gate_model"))
            want_fp = bool(item.get("dismiss_as_fp")) or item.get("classification") == "likely_false_positive"
            conf = float(item.get("confidence") or 0)
            can_dismiss_fp = (
                gate_ok
                and want_fp
                and conf >= fp_confidence
                and sev == "MEDIUM"
                and not secretish
            )
            if can_dismiss_fp:
                number = base.get("alert_number")
                if number is not None:
                    try:
                        dismiss_alert(
                            int(number),
                            "false positive",
                            (
                                f"AI alert-manager FP gate ({fp_model}): likely_false_positive "
                                f"(confidence={conf:.2f}; bulk={item.get('bulk_classification')}/"
                                f"{item.get('bulk_confidence')}). {item.get('remediation') or ''}"
                            ),
                        )
                        dismissed_fps += 1
                        print(f"Dismissed FP alert #{number} via {fp_model}")
                    except Exception as exc:  # noqa: BLE001
                        print(f"::warning::Failed to dismiss FP alert #{number}: {exc}")

            # Enforce fix policy (bulk allowlist still applies; gate does not unlock secrets)
            if secretish or (base.get("source") or "") in NEVER_AUTO_FIX_SOURCES:
                item["auto_fix_eligible"] = False
                item["auto_fix_type"] = None
            if item.get("auto_fix_type") not in AUTO_FIX_ALLOWLIST:
                item["auto_fix_eligible"] = False

        if open_fix_prs:
            fix_urls = open_draft_fix_prs(
                triage,
                findings_by_id,
                repo_root,
                fix_confidence,
                actor_name="security-alert-manager",
                branch_prefix="alert-manager",
            )

    write_output("dismissed-fps", str(dismissed_fps))
    write_output("fix-pr-urls", ",".join(fix_urls))
    reviewed = len(triage.get("findings") or [])
    append_summary(
        f"- Tier 1 bulk: `{model}` (cost-tier={cost_tier}, concurrency={concurrency})"
    )
    routed = triage.get("routed_models") or []
    if routed:
        append_summary(f"- Bulk routed models: `{', '.join(routed)}`")
    append_summary(f"- Tier 2 FP gate: `{fp_model}`")
    fp_routed_summary = triage.get("fp_gate_routed_models") or []
    if fp_routed_summary:
        append_summary(f"- FP gate models: `{', '.join(fp_routed_summary)}`")
    append_summary(f"- AI-reviewed alerts: **{reviewed}**")
    append_summary(f"- AI false positives dismissed: **{dismissed_fps}**")
    append_summary(f"- Draft fix PRs: **{len(fix_urls)}**")
    if fix_urls:
        append_summary("")
        append_summary("#### Draft fix PRs")
        for url in fix_urls:
            append_summary(f"- {url}")
    append_summary("")
    append_summary(triage.get("summary") or "")
    append_summary("")
    append_summary(
        "_Alert manager is backlog hygiene. Security Gate remains the merge authority._"
    )

    Path("alert-manager-result.json").write_text(
        json.dumps(
            {
                "dismissed_lows": dismissed_lows,
                "dismissed_fps": dismissed_fps,
                "fix_pr_urls": fix_urls,
                "triage": triage,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
