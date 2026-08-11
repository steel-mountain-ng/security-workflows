# Code Scanning alert manager

Backlog hygiene for **open GitHub Code Scanning alerts**. Complements PR AI triage and does **not** change Security Gate pass/fail.

## Pipeline

1. **Rule 1 (policy):** dismiss all open **LOW** / `note` alerts as `won't fix`
2. **AI review:** classify remaining alerts via OpenRouter
3. **FP dismiss:** dismiss `likely_false_positive` only when confidence ≥ `0.85` and severity is **MEDIUM** (never CRITICAL/HIGH, never secrets)
4. **Draft fix PRs:** allowlisted mechanical fixes (`dockerfile_user_root`, `dependency_fixed_version`, `base_image_update`)

## Dismiss comments (audit trail)

| Action | `dismissed_reason` | Comment |
| --- | --- | --- |
| LOW policy | `won't fix` | `Org policy: LOW severity auto-dismissed by security-workflows alert manager` |
| AI false positive | `false positive` | Includes confidence + short remediation note |

## Guardrails

- Scope: Code Scanning only (not Dependabot, not Secret Protection)
- Never AI-dismiss CRITICAL/HIGH
- Never dismiss secret-like rules
- Draft PRs only; Security Gate remains merge authority
- Job is `continue-on-error: true`

## Usage

### Dedicated consumer workflow (recommended)

```yaml
# .github/workflows/alert-manager.yml
name: Alert Manager
on:
  workflow_dispatch:
  schedule:
    - cron: '15 3 * * 1'
permissions:
  contents: write
  pull-requests: write
  security-events: write
jobs:
  alert-manager:
    uses: steel-mountain-ng/security-workflows/.github/workflows/reusable-alert-manager.yml@v1
    secrets: inherit
    with:
      dismiss-lows: true
      ai-review: true
      open-fix-prs: true
```

### Optional hook from Security CI

```yaml
with:
  run-alert-manager: true              # default false (avoid mid-PR dismissals)
  alert-manager-open-fix-prs: false
```

## Components

- Action: [`actions/alert-manager`](../actions/alert-manager/)
- Shared fixes: [`actions/shared/fix_helpers.py`](../actions/shared/fix_helpers.py) (copied into each action directory for composite packaging)
- Workflow: [`reusable-alert-manager.yml`](../.github/workflows/reusable-alert-manager.yml)

## Interview one-liner

*“LOWs are policy noise we auto-dismiss. AI only closes clear MEDIUM false positives. Real risk still fails the Security Gate until fixed.”*
