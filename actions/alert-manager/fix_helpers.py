"""Allowlisted mechanical security fixes + draft PR helpers (shared by ai-triage / alert-manager)."""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

AUTO_FIX_ALLOWLIST = {
    "dockerfile_user_root",
    "dependency_fixed_version",
    "base_image_update",
}

NEVER_AUTO_FIX_SOURCES = {"trivy-secrets", "roguepkg", "secret"}

DEFAULT_NODE_BASE = "node:20-bookworm-slim"


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def apply_dockerfile_user_root(repo_root: Path) -> bool:
    dockerfile = repo_root / "Dockerfile"
    if not dockerfile.is_file():
        return False
    text = dockerfile.read_text(encoding="utf-8")
    if re.search(r"(?m)^USER\s+appuser\s*$", text):
        return False
    if re.search(r"(?m)^USER\s+root\s*$", text):
        new_text = re.sub(r"(?m)^USER\s+root\s*$", "USER appuser", text)
    else:
        new_text = text.rstrip() + "\n\n# AI triage draft fix: run as non-root\nUSER appuser\n"
    if "useradd" not in new_text and "adduser" not in new_text:
        return False
    dockerfile.write_text(new_text, encoding="utf-8")
    return True


def apply_dependency_bump(repo_root: Path, package: str, fixed_version: str) -> bool:
    pkg_json = repo_root / "package.json"
    if not pkg_json.is_file() or not package or not fixed_version:
        return False
    try:
        data = json.loads(pkg_json.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return False
    changed = False
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = data.get(section) or {}
        if package in deps:
            deps[package] = fixed_version
            data[section] = deps
            changed = True
    if changed:
        pkg_json.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return changed


def _extract_from_image(patch_sketch: str | None) -> str | None:
    if not patch_sketch:
        return None
    text = patch_sketch.strip()
    match = re.search(r"(?im)^FROM\s+(\S+)", text)
    if match:
        return match.group(1).strip()
    # bare image ref
    if re.match(r"^[a-zA-Z0-9][a-zA-Z0-9._/\-:]+$", text) and " " not in text:
        return text
    return None


def apply_base_image_update(repo_root: Path, patch_sketch: str | None = None) -> bool:
    """Rewrite the first FROM line in Dockerfile to a newer base image."""
    dockerfile = repo_root / "Dockerfile"
    if not dockerfile.is_file():
        return False
    new_image = _extract_from_image(patch_sketch) or DEFAULT_NODE_BASE
    text = dockerfile.read_text(encoding="utf-8")
    match = re.search(r"(?m)^FROM\s+(\S+)\s*$", text)
    if not match:
        return False
    current = match.group(1)
    if current == new_image:
        return False
    new_text = re.sub(r"(?m)^FROM\s+\S+\s*$", f"FROM {new_image}", text, count=1)
    if new_text == text:
        return False
    dockerfile.write_text(new_text, encoding="utf-8")
    return True


def open_draft_fix_prs(
    triage: dict[str, Any],
    findings_by_id: dict[str, dict[str, Any]],
    repo_root: Path,
    confidence_threshold: float,
    *,
    actor_name: str = "security-ai-triage",
    branch_prefix: str = "ai-triage",
) -> list[str]:
    urls: list[str] = []
    token = env("GITHUB_TOKEN")
    repo = env("GITHUB_REPOSITORY")
    if not token or not repo:
        return urls

    seen_fix_types: set[str] = set()

    for item in triage.get("findings") or []:
        conf = float(item.get("confidence") or 0)
        if conf < confidence_threshold:
            continue
        if not item.get("auto_fix_eligible"):
            continue
        fix_type = item.get("auto_fix_type")
        if fix_type not in AUTO_FIX_ALLOWLIST:
            continue
        # One PR per fix type per run (avoid dozens of image CVE PRs)
        if fix_type in seen_fix_types:
            continue

        base = findings_by_id.get(item.get("id") or "", {})
        source = (base.get("source") or "").lower()
        class_ = (base.get("class") or "").lower()
        if source in NEVER_AUTO_FIX_SOURCES or class_ == "secret" or "secret" in source:
            continue

        subprocess.run(["git", "checkout", "--", "."], cwd=repo_root, check=False, capture_output=True)
        subprocess.run(["git", "clean", "-fd"], cwd=repo_root, check=False, capture_output=True)

        changed = False
        branch_suffix = re.sub(r"[^a-zA-Z0-9._-]+", "-", (base.get("rule_id") or fix_type))[:40]
        title = f"fix(security): {fix_type}"
        if fix_type == "dockerfile_user_root":
            changed = apply_dockerfile_user_root(repo_root)
            title = "fix(security): run container as non-root user"
        elif fix_type == "dependency_fixed_version":
            changed = apply_dependency_bump(
                repo_root, base.get("package") or "", base.get("fixed_version") or ""
            )
            title = f"fix(security): bump {base.get('package')} to {base.get('fixed_version')}"
        elif fix_type == "base_image_update":
            changed = apply_base_image_update(repo_root, item.get("patch_sketch"))
            title = "fix(security): upgrade container base image"
        else:
            continue

        if not changed:
            print(f"Skipping {fix_type}: no file changes applied")
            continue

        seen_fix_types.add(fix_type)
        branch = f"{branch_prefix}/{branch_suffix}-{env('GITHUB_RUN_ID', 'local')}"
        try:
            subprocess.run(["git", "config", "user.name", actor_name], cwd=repo_root, check=True)
            subprocess.run(
                ["git", "config", "user.email", f"{actor_name}@users.noreply.github.com"],
                cwd=repo_root,
                check=True,
            )
            # Ensure Actions token can push (checkout credential helper is not always enough)
            remote = f"https://x-access-token:{token}@github.com/{repo}.git"
            subprocess.run(["git", "remote", "set-url", "origin", remote], cwd=repo_root, check=True)
            subprocess.run(["git", "checkout", "-B", branch], cwd=repo_root, check=True)
            subprocess.run(["git", "add", "-A"], cwd=repo_root, check=True)
            subprocess.run(["git", "commit", "-m", title], cwd=repo_root, check=True)
            subprocess.run(
                ["git", "push", "-u", "origin", branch, "--force"],
                cwd=repo_root,
                check=True,
            )
            body = (
                f"Draft fix proposed by security-workflows alert/AI triage (advisory).\n\n"
                f"- Finding: `{base.get('rule_id')}`\n"
                f"- Classification: `{item.get('classification')}`\n"
                f"- Confidence: `{conf}`\n"
                f"- Fix type: `{fix_type}`\n\n"
                f"Security Gate remains authoritative. Review carefully before merging.\n"
            )
            pr = subprocess.run(
                [
                    "gh",
                    "pr",
                    "create",
                    "--draft",
                    "--title",
                    title,
                    "--body",
                    body,
                    "--head",
                    branch,
                ],
                cwd=repo_root,
                check=True,
                capture_output=True,
                text=True,
                env={**os.environ, "GH_TOKEN": token},
            )
            url = (pr.stdout or "").strip()
            if url:
                urls.append(url)
        except subprocess.CalledProcessError as exc:
            stderr = ""
            if exc.stderr:
                stderr = exc.stderr if isinstance(exc.stderr, str) else exc.stderr.decode("utf-8", "replace")
            print(f"::warning::Failed to open draft fix PR for {fix_type}: {exc} {stderr[:500]}")
        except Exception as exc:  # noqa: BLE001
            print(f"::warning::Failed to open draft fix PR for {fix_type}: {exc}")
        finally:
            default_ref = env("GITHUB_REF_NAME") or "main"
            subprocess.run(["git", "checkout", default_ref], cwd=repo_root, check=False)
    return urls
