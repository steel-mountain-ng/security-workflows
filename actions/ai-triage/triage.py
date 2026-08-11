#!/usr/bin/env python3
"""AI security triage: normalize findings, call OpenRouter, comment on PR, optional draft fixes."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from fix_helpers import (
    AUTO_FIX_ALLOWLIST,
    NEVER_AUTO_FIX_SOURCES,
    open_draft_fix_prs,
)

SEVERITY_RANK = {
    "CRITICAL": 0,
    "HIGH": 1,
    "ERROR": 1,
    "MEDIUM": 2,
    "WARNING": 2,
    "LOW": 3,
    "NOTE": 4,
    "UNKNOWN": 5,
    "INFO": 5,
}


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def write_output(name: str, value: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        if "\n" in value:
            fh.write(f"{name}<<EOF\n{value}\nEOF\n")
        else:
            fh.write(f"{name}={value}\n")


def mask_secrets(text: str) -> str:
    patterns = [
        (r"(?i)(aws_secret_access_key\s*[=:]\s*)(\S+)", r"\1***REDACTED***"),
        (r"(?i)(aws_access_key_id\s*[=:]\s*)(AKIA[0-9A-Z]{16})", r"\1AKIA****************"),
        (r"(ghp_[A-Za-z0-9]{20,})", "***REDACTED_GITHUB_TOKEN***"),
        (r"(sk_live_[A-Za-z0-9]+)", "***REDACTED_STRIPE_KEY***"),
        (r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)(.*?)(-----END [A-Z ]*PRIVATE KEY-----)",
         r"\1\n***REDACTED PRIVATE KEY***\n\3"),
    ]
    out = text
    for pattern, repl in patterns:
        out = re.sub(pattern, repl, out, flags=re.DOTALL)
    return out


def read_snippet(repo_root: Path, path: str, start: int | None, end: int | None, pad: int = 15) -> str:
    if not path or path.startswith("node:"):
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
    return mask_secrets(chunk)[:2500]


def severity_rank(sev: str) -> int:
    return SEVERITY_RANK.get((sev or "UNKNOWN").upper(), 5)


def normalize_trivy_json(path: Path, source: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return findings

    results = data if isinstance(data, list) else data.get("Results") or []
    for result in results:
        target = result.get("Target") or result.get("target") or ""
        class_ = (result.get("Class") or "").lower()
        # Misconfigurations
        for misc in result.get("Misconfigurations") or []:
            cause = misc.get("CauseMetadata") or {}
            start = cause.get("StartLine")
            end = cause.get("EndLine")
            avd = misc.get("AVDID") or misc.get("ID") or "misconfig"
            title = misc.get("Title") or misc.get("Description") or avd
            sev = (misc.get("Severity") or "UNKNOWN").upper()
            fix_type = None
            if "USER" in title.upper() and "ROOT" in title.upper():
                fix_type = "dockerfile_user_root"
            findings.append(
                {
                    "id": f"{source}:{avd}:{target}:{start}",
                    "source": source,
                    "rule_id": avd,
                    "title": title,
                    "severity": sev,
                    "path": target if not target.startswith("infra") else target,
                    "start_line": start,
                    "end_line": end,
                    "message": misc.get("Message") or misc.get("Description") or "",
                    "fixed_version": None,
                    "auto_fix_type": fix_type,
                    "class": class_ or "config",
                }
            )
        # Secrets
        for secret in result.get("Secrets") or []:
            start = secret.get("StartLine")
            end = secret.get("EndLine")
            rule = secret.get("RuleID") or secret.get("Category") or "secret"
            findings.append(
                {
                    "id": f"{source}:{rule}:{target}:{start}",
                    "source": source,
                    "rule_id": rule,
                    "title": secret.get("Title") or rule,
                    "severity": (secret.get("Severity") or "HIGH").upper(),
                    "path": target,
                    "start_line": start,
                    "end_line": end,
                    "message": "Hardcoded secret detected",
                    "fixed_version": None,
                    "auto_fix_type": None,
                    "class": "secret",
                }
            )
        # Vulnerabilities
        for vuln in result.get("Vulnerabilities") or []:
            vid = vuln.get("VulnerabilityID") or vuln.get("PkgID") or "vuln"
            fixed = vuln.get("FixedVersion") or None
            pkg = vuln.get("PkgName") or ""
            fix_type = "dependency_fixed_version" if fixed and source == "trivy-sca" else None
            if fixed and source == "trivy-image" and (vuln.get("PkgPath") or "").endswith("Dockerfile") is False:
                # image OS pkgs: allow base image update suggestion only for node base style
                if "node" in (target or "").lower() or pkg in {"", None}:
                    fix_type = "base_image_update"
            findings.append(
                {
                    "id": f"{source}:{vid}:{pkg}:{target}",
                    "source": source,
                    "rule_id": vid,
                    "title": vuln.get("Title") or vid,
                    "severity": (vuln.get("Severity") or "UNKNOWN").upper(),
                    "path": target,
                    "start_line": None,
                    "end_line": None,
                    "message": (vuln.get("Description") or "")[:500],
                    "package": pkg,
                    "installed_version": vuln.get("InstalledVersion"),
                    "fixed_version": fixed,
                    "auto_fix_type": fix_type,
                    "class": "vuln",
                }
            )
    return findings


def normalize_codeql_sarif(path: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return findings
    for run in data.get("runs") or []:
        rules = {}
        for rule in ((run.get("tool") or {}).get("driver") or {}).get("rules") or []:
            rules[rule.get("id")] = rule
        for result in run.get("results") or []:
            rule_id = result.get("ruleId") or "codeql"
            level = (result.get("level") or "warning").upper()
            sev = "HIGH" if level in {"ERROR", "HIGH"} else "MEDIUM" if level in {"WARNING", "MEDIUM"} else level
            loc = ((result.get("locations") or [{}])[0].get("physicalLocation") or {})
            artifact = (loc.get("artifactLocation") or {}).get("uri") or ""
            region = loc.get("region") or {}
            start = region.get("startLine")
            end = region.get("endLine") or start
            msg = ((result.get("message") or {}).get("text") or "")[:500]
            findings.append(
                {
                    "id": f"codeql:{rule_id}:{artifact}:{start}",
                    "source": "codeql",
                    "rule_id": rule_id,
                    "title": (rules.get(rule_id) or {}).get("shortDescription", {}).get("text") or rule_id,
                    "severity": sev,
                    "path": artifact,
                    "start_line": start,
                    "end_line": end,
                    "message": msg,
                    "fixed_version": None,
                    "auto_fix_type": None,
                    "class": "sast",
                }
            )
    return findings


def normalize_roguepkg(path: Path) -> list[dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not data.get("gate_failed") and int(data.get("malware_found") or 0) == 0:
        return []
    return [
        {
            "id": "roguepkg:malware",
            "source": "roguepkg",
            "rule_id": "malware-or-compromise",
            "title": "RoguePkg supply-chain finding",
            "severity": "CRITICAL" if int(data.get("malware_found") or 0) > 0 else "HIGH",
            "path": "package.json",
            "start_line": 1,
            "end_line": 1,
            "message": (
                f"status={data.get('scan_status')} malware={data.get('malware_found')} "
                f"vulns={data.get('vulnerabilities_found')} scanned={data.get('total_scanned')}"
            ),
            "fixed_version": None,
            "auto_fix_type": None,
            "class": "supply-chain",
        }
    ]


def load_findings(findings_dir: Path, repo_root: Path, max_findings: int) -> list[dict[str, Any]]:
    all_findings: list[dict[str, Any]] = []
    mapping = {
        "trivy-iac.json": "trivy-iac",
        "trivy-sca.json": "trivy-sca",
        "trivy-secrets.json": "trivy-secrets",
        "trivy-image.json": "trivy-image",
    }
    for name, source in mapping.items():
        for path in findings_dir.rglob(name):
            all_findings.extend(normalize_trivy_json(path, source))
    for path in findings_dir.rglob("codeql.sarif"):
        all_findings.extend(normalize_codeql_sarif(path))
    for path in findings_dir.rglob("*.sarif"):
        if path.name == "codeql.sarif":
            continue
        if "codeql" in path.name.lower():
            all_findings.extend(normalize_codeql_sarif(path))
    for path in findings_dir.rglob("roguepkg.json"):
        all_findings.extend(normalize_roguepkg(path))

    # Dedupe by id
    deduped: dict[str, dict[str, Any]] = {}
    for f in all_findings:
        deduped[f["id"]] = f
    findings = list(deduped.values())
    findings.sort(key=lambda f: (severity_rank(f.get("severity", "")), f.get("source", ""), f.get("rule_id", "")))
    findings = findings[:max_findings]

    for f in findings:
        f["snippet"] = read_snippet(repo_root, f.get("path") or "", f.get("start_line"), f.get("end_line"))
    return findings


def call_openrouter(model: str, api_key: str, findings: list[dict[str, Any]], gate_status: str) -> dict[str, Any]:
    system = (
        "You are a senior application security engineer triaging CI scanner findings. "
        "Be precise. Never invent CVEs or file paths. Prefer needs_human when unsure. "
        "Do not claim secrets are fixed by deleting them — recommend rotation. "
        "AI triage is advisory only; it must never override hard security gates. "
        "Return ONLY valid JSON matching the schema."
    )
    schema_hint = {
        "summary": "string",
        "gate_note": "string — remind that Security Gate remains authoritative",
        "findings": [
            {
                "id": "finding id from input",
                "classification": "likely_true_positive|likely_false_positive|needs_human",
                "confidence": 0.0,
                "exploitability": "string",
                "reachability": "string",
                "business_impact": "string",
                "remediation": "string",
                "patch_sketch": "string or empty",
                "auto_fix_eligible": False,
                "auto_fix_type": "dockerfile_user_root|dependency_fixed_version|base_image_update|null",
            }
        ],
    }
    user_payload = {
        "gate_status": gate_status,
        "run_url": env("GITHUB_RUN_URL"),
        "repository": env("GITHUB_REPOSITORY"),
        "findings": findings,
        "response_schema": schema_hint,
        "rules": {
            "never_auto_fix_sources": sorted(NEVER_AUTO_FIX_SOURCES),
            "auto_fix_allowlist": sorted(AUTO_FIX_ALLOWLIST),
        },
    }
    body = {
        "model": model,
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": json.dumps(user_payload)},
        ],
    }
    req = urllib.request.Request(
        "https://openrouter.ai/api/v1/chat/completions",
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": env("GITHUB_SERVER_URL", "https://github.com"),
            "X-Title": "steel-mountain-ng security-workflows AI triage",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"OpenRouter HTTP {exc.code}: {detail}") from exc

    content = payload["choices"][0]["message"]["content"]
    if isinstance(content, list):
        content = "".join(part.get("text", "") for part in content if isinstance(part, dict))
    # Strip markdown fences if model wraps JSON
    content = content.strip()
    if content.startswith("```"):
        content = re.sub(r"^```(?:json)?\s*", "", content)
        content = re.sub(r"\s*```$", "", content)
    return json.loads(content)


def heuristic_triage(findings: list[dict[str, Any]], gate_status: str) -> dict[str, Any]:
    """Fallback when OpenRouter is unavailable — still posts useful PR context."""
    items = []
    for f in findings:
        source = f.get("source") or ""
        cls = "likely_true_positive"
        if source in NEVER_AUTO_FIX_SOURCES or f.get("class") == "secret":
            auto = False
            rem = "Rotate/revoke the credential, purge from git history, and move secrets to a vault/CI secret store."
        elif f.get("auto_fix_type") in AUTO_FIX_ALLOWLIST and f.get("fixed_version"):
            auto = True
            rem = f"Upgrade {f.get('package')} to {f.get('fixed_version')}."
        elif f.get("auto_fix_type") == "dockerfile_user_root":
            auto = True
            rem = "Run as non-root USER (e.g. appuser) after creating the user."
        else:
            auto = False
            rem = f.get("message") or "Review and remediate according to scanner guidance."
        items.append(
            {
                "id": f["id"],
                "classification": cls,
                "confidence": 0.55,
                "exploitability": "Heuristic only — model unavailable; treat as potentially exploitable until proven otherwise.",
                "reachability": "Not analyzed (fallback mode).",
                "business_impact": f.get("severity", "UNKNOWN"),
                "remediation": rem,
                "patch_sketch": "",
                "auto_fix_eligible": auto,
                "auto_fix_type": f.get("auto_fix_type"),
            }
        )
    return {
        "summary": (
            f"Heuristic triage of {len(findings)} finding(s). "
            "OpenRouter was unavailable or returned invalid JSON; Security Gate remains authoritative."
        ),
        "gate_note": f"Security Gate status: {gate_status}. AI triage never overrides the gate.",
        "findings": items,
        "fallback": True,
    }


def render_markdown(
    triage: dict[str, Any],
    findings_by_id: dict[str, dict[str, Any]],
    gate_status: str,
    fix_pr_urls: list[str],
) -> str:
    lines = [
        "### AI Security Triage (advisory)",
        "",
        f"**Security Gate:** `{gate_status}` — the gate is authoritative; this comment does not change pass/fail.",
        "",
        triage.get("summary") or "_No summary_",
        "",
        triage.get("gate_note") or "",
        "",
        "| Finding | Class | Conf. | Exploitability | Reachability | Remediation |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for item in triage.get("findings") or []:
        fid = item.get("id") or ""
        base = findings_by_id.get(fid, {})
        label = f"`{base.get('rule_id', fid)}` ({base.get('source', '?')})"
        if base.get("path"):
            loc = base["path"]
            if base.get("start_line"):
                loc += f":{base['start_line']}"
            label += f"<br>`{loc}`"
        lines.append(
            "| {finding} | {cls} | {conf} | {exp} | {reach} | {rem} |".format(
                finding=label.replace("|", "\\|"),
                cls=(item.get("classification") or "").replace("|", "\\|"),
                conf=item.get("confidence", ""),
                exp=(item.get("exploitability") or "").replace("|", "\\|").replace("\n", " "),
                reach=(item.get("reachability") or "").replace("|", "\\|").replace("\n", " "),
                rem=(item.get("remediation") or "").replace("|", "\\|").replace("\n", " "),
            )
        )
    if fix_pr_urls:
        lines.extend(["", "#### Draft fix PRs", ""])
        for url in fix_pr_urls:
            lines.append(f"- {url}")
    lines.extend(
        [
            "",
            "<details><summary>Raw triage JSON</summary>",
            "",
            "```json",
            json.dumps(triage, indent=2)[:12000],
            "```",
            "</details>",
            "",
            f"_Run: {env('GITHUB_RUN_URL')}_",
        ]
    )
    return "\n".join(lines)


def get_pr_number() -> int | None:
    event_path = env("GITHUB_EVENT_PATH")
    if not event_path or not Path(event_path).is_file():
        return None
    try:
        event = json.loads(Path(event_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    pr = event.get("pull_request") or {}
    num = pr.get("number")
    return int(num) if num else None


def post_pr_comment(body: str) -> None:
    pr = get_pr_number()
    if not pr:
        print("No pull_request in event; skipping comment")
        return
    token = env("GITHUB_TOKEN")
    repo = env("GITHUB_REPOSITORY")
    if not token or not repo:
        print("Missing GITHUB_TOKEN or GITHUB_REPOSITORY; skipping comment")
        return
    # Use sticky comment via gh if available
    marker = "<!-- ai-security-triage -->"
    body_marked = marker + "\n" + body
    Path("ai-triage-comment.md").write_text(body_marked, encoding="utf-8")
    try:
        existing = subprocess.run(
            ["gh", "api", f"repos/{repo}/issues/{pr}/comments", "--jq", ".[].body"],
            check=False,
            capture_output=True,
            text=True,
            env={**os.environ, "GH_TOKEN": token},
        )
        if existing.returncode == 0 and marker in (existing.stdout or ""):
            listing = subprocess.run(
                ["gh", "api", f"repos/{repo}/issues/{pr}/comments"],
                check=True,
                capture_output=True,
                text=True,
                env={**os.environ, "GH_TOKEN": token},
            )
            for comment in json.loads(listing.stdout):
                if marker in (comment.get("body") or ""):
                    payload = json.dumps({"body": body_marked}).encode("utf-8")
                    req = urllib.request.Request(
                        f"https://api.github.com/repos/{repo}/issues/comments/{comment['id']}",
                        data=payload,
                        headers={
                            "Authorization": f"Bearer {token}",
                            "Accept": "application/vnd.github+json",
                            "Content-Type": "application/json",
                            "X-GitHub-Api-Version": "2022-11-28",
                        },
                        method="PATCH",
                    )
                    urllib.request.urlopen(req, timeout=60).read()
                    print(f"Updated sticky PR comment on #{pr}")
                    return
        subprocess.run(
            [
                "gh",
                "pr",
                "comment",
                str(pr),
                "--body-file",
                "ai-triage-comment.md",
            ],
            check=True,
            env={**os.environ, "GH_TOKEN": token},
        )
        print(f"Created PR comment on #{pr}")
    except (subprocess.CalledProcessError, FileNotFoundError, urllib.error.URLError, TimeoutError) as exc:
        print(f"::warning::Failed to post PR comment: {exc}")


def main() -> int:
    api_key = env("OPENROUTER_API_KEY")
    model = env("AI_MODEL", "openai/gpt-4o-mini")
    max_findings = int(env("AI_MAX_FINDINGS", "25") or 25)
    confidence_threshold = float(env("AI_CONFIDENCE_THRESHOLD", "0.7") or 0.7)
    open_fix_prs = env("AI_OPEN_FIX_PRS", "false").lower() == "true"
    findings_dir = Path(env("AI_FINDINGS_DIR", "ai-findings"))
    repo_root = Path(env("AI_REPO_ROOT", ".")).resolve()
    gate_status = env("AI_GATE_STATUS", "unknown")

    findings = load_findings(findings_dir, repo_root, max_findings)
    findings_by_id = {f["id"]: f for f in findings}
    print(f"Loaded {len(findings)} findings for triage")

    triage: dict[str, Any]
    if not findings:
        triage = {
            "summary": "No scanner findings were available for AI triage.",
            "gate_note": f"Security Gate status: {gate_status}.",
            "findings": [],
        }
    elif not api_key:
        print("::warning::OPENROUTER_API_KEY missing; using heuristic triage")
        triage = heuristic_triage(findings, gate_status)
    else:
        try:
            # Minimize payload to model
            slim = []
            for f in findings:
                slim.append({k: v for k, v in f.items() if k != "snippet" or v})
            triage = call_openrouter(model, api_key, slim, gate_status)
        except Exception as exc:  # noqa: BLE001
            print(f"::warning::OpenRouter triage failed: {exc}")
            triage = heuristic_triage(findings, gate_status)

    # Enforce never-auto-fix policy server-side
    for item in triage.get("findings") or []:
        base = findings_by_id.get(item.get("id") or "", {})
        if base.get("source") in NEVER_AUTO_FIX_SOURCES or base.get("class") == "secret":
            item["auto_fix_eligible"] = False
            item["auto_fix_type"] = None
        if item.get("auto_fix_type") not in AUTO_FIX_ALLOWLIST:
            item["auto_fix_eligible"] = False

    out_json = Path("ai-triage-result.json")
    out_json.write_text(json.dumps(triage, indent=2), encoding="utf-8")
    write_output("triage-json-path", str(out_json))

    fix_urls: list[str] = []
    if open_fix_prs and findings:
        fix_urls = open_draft_fix_prs(triage, findings_by_id, repo_root, confidence_threshold)
    write_output("fix-pr-urls", ",".join(fix_urls))

    md = render_markdown(triage, findings_by_id, gate_status, fix_urls)
    out_md = Path("ai-triage-comment.md")
    out_md.write_text(md, encoding="utf-8")
    write_output("comment-path", str(out_md))

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write(md + "\n")

    if env("GITHUB_EVENT_NAME") == "pull_request":
        post_pr_comment(md)
    else:
        print("Not a pull_request event; comment skipped (summary written)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
