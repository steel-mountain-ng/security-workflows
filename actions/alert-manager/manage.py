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


def normalize_alert(alert: dict[str, Any], repo_root: Path) -> dict[str, Any]:
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
        "message": (inst.get("message") or {}).get("text") if isinstance(inst.get("message"), dict) else str(inst.get("message") or ""),
        "fixed_version": None,
        "package": None,
        "auto_fix_type": None,
        "class": class_,
        "snippet": read_snippet(repo_root, path, start, end),
        "html_url": alert.get("html_url"),
    }


def call_openrouter(model: str, api_key: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
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
    with urllib.request.urlopen(req, timeout=120) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    content = payload["choices"][0]["message"]["content"]
    if isinstance(content, list):
        content = "".join(part.get("text", "") for part in content if isinstance(part, dict))
    content = content.strip()
    if content.startswith("```"):
        content = re.sub(r"^```(?:json)?\s*", "", content)
        content = re.sub(r"\s*```$", "", content)
    return json.loads(content)


def heuristic_review(findings: list[dict[str, Any]]) -> dict[str, Any]:
    items = []
    for f in findings:
        fix_type = None
        eligible = False
        title = (f.get("title") or "").lower()
        path = (f.get("path") or "").lower()
        if "dockerfile" in path and "user" in title and "root" in title:
            fix_type = "dockerfile_user_root"
            eligible = True
        elif path.endswith("dockerfile") or path == "dockerfile":
            if "from" in title or "base" in title or "image" in title:
                fix_type = "base_image_update"
                eligible = True
        items.append(
            {
                "id": f["id"],
                "classification": "needs_human" if f.get("severity") in {"CRITICAL", "HIGH"} else "likely_true_positive",
                "confidence": 0.55,
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
    max_alerts = int(env("AI_MAX_ALERTS", "40") or 40)
    fp_confidence = float(env("AI_FP_CONFIDENCE", "0.85") or 0.85)
    fix_confidence = float(env("AI_FIX_CONFIDENCE", "0.7") or 0.7)
    model = env("AI_MODEL", "openai/gpt-4o-mini")
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
        findings = [normalize_alert(a, repo_root) for a in others]
        # Prefer MEDIUM for AI dismiss consideration; keep CRITICAL/HIGH for fix suggestions
        findings.sort(
            key=lambda f: (
                0 if f["severity"] == "MEDIUM" else 1 if f["severity"] in {"HIGH", "CRITICAL"} else 2,
                f.get("rule_id") or "",
            )
        )
        findings = findings[:max_alerts]
        findings_by_id = {f["id"]: f for f in findings}

        if api_key:
            try:
                slim = [{k: v for k, v in f.items() if k != "snippet" or v} for f in findings]
                triage = call_openrouter(model, api_key, slim)
            except Exception as exc:  # noqa: BLE001
                print(f"::warning::OpenRouter review failed: {exc}")
                triage = heuristic_review(findings)
        else:
            print("::warning::OPENROUTER_API_KEY missing; heuristic review only")
            triage = heuristic_review(findings)

        for item in triage.get("findings") or []:
            base = findings_by_id.get(item.get("id") or "", {})
            sev = (base.get("severity") or "").upper()
            secretish = base.get("class") == "secret" or is_secretish(
                {"rule": {"id": base.get("rule_id"), "description": base.get("title")}, "tool": {"name": base.get("source")}}
            )

            # Enforce dismiss policy
            want_fp = bool(item.get("dismiss_as_fp")) or item.get("classification") == "likely_false_positive"
            conf = float(item.get("confidence") or 0)
            can_dismiss_fp = (
                want_fp
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
                            f"AI alert-manager: likely_false_positive (confidence={conf:.2f}). {item.get('remediation') or ''}",
                        )
                        dismissed_fps += 1
                        print(f"Dismissed FP alert #{number}")
                    except Exception as exc:  # noqa: BLE001
                        print(f"::warning::Failed to dismiss FP alert #{number}: {exc}")

            # Enforce fix policy
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
