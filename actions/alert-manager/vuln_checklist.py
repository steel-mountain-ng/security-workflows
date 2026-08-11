"""In-action vuln-analyst checklist: prompts, schema, enrichment, reports, dismiss policy.

Shared by alert-manager and ai-triage (copied into each action directory for composite packaging).
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

CLASSIFICATIONS = (
    "likely_true_positive",
    "true_positive_not_reachable",
    "true_positive_fix_breaks",
    "likely_false_positive",
    "needs_human",
)

NEVER_AUTO_DISMISS = {
    "likely_true_positive",
    "true_positive_not_reachable",
    "true_positive_fix_breaks",
    "needs_human",
}

CHECKLIST_FIELDS = (
    "advisory_summary",
    "exploit_conditions",
    "public_exploit_known",
    "reachability",
    "user_input_required",
    "mitigations",
    "dependency_role",
    "fix_risk",
    "decision_rationale",
)

_ADVISORY_CACHE: dict[str, str] = {}


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._chunks: list[str] = []
        self._skip = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "noscript"}:
            self._skip = True

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript"}:
            self._skip = False

    def handle_data(self, data: str) -> None:
        if not self._skip:
            text = data.strip()
            if text:
                self._chunks.append(text)

    def text(self) -> str:
        return " ".join(self._chunks)


def bulk_system_prompt() -> str:
    return (
        "You are a senior application security engineer triaging scanner findings with a "
        "vuln-analyst mindset. For EACH finding you MUST complete the exploitability checklist "
        "before classifying. Prefer needs_human when evidence is thin. "
        "Do NOT label image/toolchain CVEs as likely_false_positive merely because they are "
        "not app-reachable — use true_positive_not_reachable instead. "
        "likely_false_positive is only for incorrect findings / wrong component. "
        "Never recommend dismissing secrets or malware. "
        "Never approve auto-dismiss for CRITICAL/HIGH. "
        "High confidence only when checklist evidence is explicit. "
        "Return ONLY valid JSON matching the schema."
    )


def fp_gate_system_prompt() -> str:
    return (
        "You are a senior application security engineer acting as a FALSE-POSITIVE gate. "
        "These alerts were nominated as possible false positives by a cheaper bulk model. "
        "Re-run the full exploitability checklist. "
        "Only mark likely_false_positive when the finding itself is wrong. "
        "If the CVE is real but not reachable from the app, use true_positive_not_reachable "
        "(do not dismiss as false positive). "
        "Prefer needs_human when unsure. Never dismiss secrets/malware or CRITICAL/HIGH. "
        "Return ONLY valid JSON matching the schema."
    )


def finding_schema_item() -> dict[str, Any]:
    return {
        "id": "alert:N or finding id",
        "classification": "|".join(CLASSIFICATIONS),
        "confidence": 0.0,
        "advisory_summary": "string",
        "exploit_conditions": "string — what API/input triggers the bug",
        "public_exploit_known": "yes|no|unknown",
        "reachability": "source_to_sink|library_only|image_toolchain|dev_only|unknown",
        "user_input_required": "yes|no|unknown",
        "mitigations": "string — framework/runtime guards if any",
        "dependency_role": "app_runtime|app_dev|image_toolchain|transitive_unknown",
        "fix_risk": "safe_bump|may_break|unknown",
        "decision_rationale": "2-4 sentences citing the checklist",
        "exploitability": "string",
        "business_impact": "string",
        "remediation": "string",
        "patch_sketch": "string",
        "auto_fix_eligible": False,
        "auto_fix_type": "dockerfile_user_root|dependency_fixed_version|base_image_update|null",
        "dismiss_as_fp": False,
    }


def response_schema() -> dict[str, Any]:
    return {
        "summary": "string",
        "gate_note": "string — Security Gate remains authoritative",
        "findings": [finding_schema_item()],
    }


def checklist_rules() -> dict[str, Any]:
    return {
        "classifications": list(CLASSIFICATIONS),
        "never_auto_dismiss": sorted(NEVER_AUTO_DISMISS),
        "notes": [
            "Image path under usr/local/lib/node_modules/npm/... is usually image_toolchain → true_positive_not_reachable",
            "likely_false_positive means the scanner finding is wrong, not merely non-actionable",
            "true_positive_fix_breaks when remediating would break build/runtime/compat",
        ],
    }


def parse_trivy_message(message: str) -> dict[str, str]:
    out = {"package": "", "installed_version": "", "fixed_version": "", "cve": ""}
    if not message:
        return out
    pkg = re.search(r"(?im)^Package:\s*(.+)$", message)
    inst = re.search(r"(?im)^Installed Version:\s*(.+)$", message)
    fixed = re.search(r"(?im)^Fixed Version:\s*(.+)$", message)
    cve = re.search(r"(?i)\b(CVE-\d{4}-\d+)\b", message)
    if pkg:
        out["package"] = pkg.group(1).strip()
    if inst:
        out["installed_version"] = inst.group(1).strip()
    if fixed:
        out["fixed_version"] = fixed.group(1).strip()
    if cve:
        out["cve"] = cve.group(1).upper()
    return out


def derive_dependency_role(path: str, repo_root: Path | None = None) -> str:
    path_l = (path or "").replace("\\", "/").lower()
    if not path_l:
        return "transitive_unknown"
    if path_l.startswith(("usr/", "opt/", "var/", "lib/", "library/")):
        if "node_modules/npm/" in path_l or "/npm/node_modules/" in path_l or "yarn" in path_l:
            return "image_toolchain"
        return "image_toolchain"
    if "/node_modules/" in path_l and not path_l.startswith(("src/", "app/", "packages/")):
        # Likely image or vendored tree outside app source
        if path_l.startswith(("node_modules/", "./node_modules/")):
            return "app_runtime"
        return "image_toolchain"
    if repo_root and path:
        pkg_json = repo_root / "package.json"
        name = Path(path_l).name
        if name in {"package.json", "package-lock.json"} and (repo_root / path).is_file():
            return "app_runtime"
        # Heuristic: path is app source
        if path_l.startswith(("src/", "app/", "lib/", "services/", "deploy/", "infra/")):
            return "app_runtime"
        if pkg_json.is_file():
            try:
                data = json.loads(pkg_json.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                data = {}
            deps = set((data.get("dependencies") or {}).keys())
            dev = set((data.get("devDependencies") or {}).keys())
            # package folder name guess
            parts = path_l.split("/")
            if "node_modules" in parts:
                idx = parts.index("node_modules")
                if idx + 1 < len(parts):
                    cand = parts[idx + 1]
                    if cand.startswith("@"):
                        cand = "/".join(parts[idx + 1 : idx + 3]) if idx + 2 < len(parts) else cand
                    if cand in dev and cand not in deps:
                        return "app_dev"
                    if cand in deps or cand in dev:
                        return "app_runtime"
    if path_l.endswith(("dockerfile",)) or path_l == "dockerfile":
        return "app_runtime"
    return "transitive_unknown"


def fetch_advisory_text(url: str, *, timeout: int = 12, max_chars: int = 2500) -> str:
    if not url:
        return ""
    if url in _ADVISORY_CACHE:
        return _ADVISORY_CACHE[url]
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "steel-mountain-ng-security-workflows/vuln-checklist"},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        if "html" in (resp.headers.get("Content-Type") or "").lower() or raw.lstrip().startswith("<"):
            parser = _TextExtractor()
            parser.feed(raw)
            text = parser.text()
        else:
            text = raw
        text = re.sub(r"\s+", " ", text).strip()[:max_chars]
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError, OSError):
        text = ""
    _ADVISORY_CACHE[url] = text
    return text


def build_decision_context(
    *,
    path: str,
    message: str,
    help_uri: str = "",
    full_description: str = "",
    sarif_classifications: list[str] | None = None,
    repo_root: Path | None = None,
    fetch_advisory: bool = True,
) -> dict[str, Any]:
    parsed = parse_trivy_message(message)
    role = derive_dependency_role(path, repo_root)
    advisory = ""
    if fetch_advisory and help_uri:
        advisory = fetch_advisory_text(help_uri)
    if not advisory:
        advisory = (full_description or message or "")[:2500]
    return {
        "package": parsed.get("package") or "",
        "installed_version": parsed.get("installed_version") or "",
        "fixed_version": parsed.get("fixed_version") or "",
        "cve": parsed.get("cve") or "",
        "help_uri": help_uri or "",
        "advisory_excerpt": advisory,
        "sarif_classifications": list(sarif_classifications or []),
        "dependency_role_hint": role,
        "example_note": (
            "Paths under usr/local/lib/node_modules/npm/ are image npm toolchain — "
            "prefer true_positive_not_reachable over likely_false_positive "
            "(see alert #3195 brace-expansion pattern)."
            if role == "image_toolchain"
            else ""
        ),
    }


def can_auto_dismiss(
    *,
    classification: str,
    confidence: float,
    severity: str,
    secretish: bool,
    fp_confidence: float,
    gate_confirmed: bool,
) -> bool:
    if secretish:
        return False
    if classification != "likely_false_positive":
        return False
    if not gate_confirmed:
        return False
    if (severity or "").upper() != "MEDIUM":
        return False
    if float(confidence or 0) < float(fp_confidence):
        return False
    return True


def normalize_classification(value: str | None) -> str:
    v = (value or "").strip()
    if v in CLASSIFICATIONS:
        return v
    # Back-compat aliases
    if v in {"tp", "true_positive"}:
        return "likely_true_positive"
    if v in {"fp", "false_positive"}:
        return "likely_false_positive"
    return "needs_human"


def build_decision_report_md(
    items: list[dict[str, Any]],
    findings_by_id: dict[str, dict[str, Any]],
    *,
    title: str = "Security decision report",
    run_url: str = "",
    max_cards: int = 25,
) -> str:
    counts = Counter(normalize_classification(i.get("classification")) for i in items)
    lines = [
        f"### {title}",
        "",
        "Exploitability checklist classifications (in-action):",
        "",
        f"- likely_true_positive: **{counts.get('likely_true_positive', 0)}**",
        f"- true_positive_not_reachable: **{counts.get('true_positive_not_reachable', 0)}**",
        f"- true_positive_fix_breaks: **{counts.get('true_positive_fix_breaks', 0)}**",
        f"- likely_false_positive: **{counts.get('likely_false_positive', 0)}**",
        f"- needs_human: **{counts.get('needs_human', 0)}**",
        "",
    ]
    if run_url:
        lines.append(f"_Run: {run_url}_")
        lines.append("")

    # Prioritize interesting cards
    order = {
        "likely_false_positive": 0,
        "true_positive_not_reachable": 1,
        "true_positive_fix_breaks": 2,
        "needs_human": 3,
        "likely_true_positive": 4,
    }
    ranked = sorted(
        items,
        key=lambda i: (
            order.get(normalize_classification(i.get("classification")), 9),
            -float(i.get("confidence") or 0),
        ),
    )[:max_cards]

    lines.append("#### Decision cards")
    lines.append("")
    for item in ranked:
        fid = item.get("id") or ""
        base = findings_by_id.get(fid, {})
        rule = base.get("rule_id") or item.get("rule_id") or fid
        path = base.get("path") or item.get("path") or ""
        sev = base.get("severity") or item.get("severity") or ""
        cls = normalize_classification(item.get("classification"))
        conf = item.get("confidence", "")
        lines.append(f"##### `{rule}` — {cls} (conf={conf})")
        lines.append("")
        lines.append(f"- Severity/path: `{sev}` / `{path}`")
        for field in CHECKLIST_FIELDS:
            val = item.get(field)
            if val:
                lines.append(f"- {field}: {val}")
        if item.get("remediation"):
            lines.append(f"- remediation: {item.get('remediation')}")
        lines.append("")

    lines.append(
        "_Auto-dismiss only applies to MEDIUM `likely_false_positive` after the FP gate. "
        "`true_positive_not_reachable` / `true_positive_fix_breaks` are documented, never auto-dismissed. "
        "Security Gate remains merge authority._"
    )
    return "\n".join(lines)


def group_findings_for_pr_comment(
    items: list[dict[str, Any]],
    findings_by_id: dict[str, dict[str, Any]],
) -> str:
    """Markdown sections for sticky PR comments, grouped by classification."""
    buckets: dict[str, list[dict[str, Any]]] = {c: [] for c in CLASSIFICATIONS}
    for item in items:
        buckets[normalize_classification(item.get("classification"))].append(item)

    titles = {
        "likely_true_positive": "True positives",
        "true_positive_not_reachable": "TP but not reachable",
        "true_positive_fix_breaks": "TP but fix may break",
        "likely_false_positive": "Likely false positives",
        "needs_human": "Needs human review",
    }
    lines = ["### Vuln decision checklist", ""]
    for cls in CLASSIFICATIONS:
        group = buckets.get(cls) or []
        if not group:
            continue
        lines.append(f"#### {titles[cls]} ({len(group)})")
        lines.append("")
        for item in group[:15]:
            fid = item.get("id") or ""
            base = findings_by_id.get(fid, {})
            rule = base.get("rule_id") or fid
            path = base.get("path") or ""
            rationale = item.get("decision_rationale") or item.get("remediation") or ""
            lines.append(
                f"- `{rule}` `{path}` — conf={item.get('confidence', '')}; "
                f"reachability={item.get('reachability', '')}; {rationale}"
            )
        lines.append("")
    return "\n".join(lines)
