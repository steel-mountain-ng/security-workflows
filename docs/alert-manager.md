# Code Scanning alert manager

Backlog hygiene for **open GitHub Code Scanning alerts**. Complements PR AI triage and does **not** change Security Gate pass/fail.

## Pipeline

1. **Rule 1 (policy):** dismiss all open **LOW** / `note` alerts as `won't fix`
2. **Tier 1 bulk AI:** classify remaining alerts via `openrouter/auto` (`cost-tier: medium` by default)
3. **Tier 2 FP gate:** re-score bulk `likely_false_positive` candidates with `anthropic/claude-opus-5`
4. **FP dismiss:** dismiss only after the FP gate confirms `likely_false_positive` with confidence ≥ `0.85` and severity **MEDIUM** (never CRITICAL/HIGH, never secrets)
5. **Draft fix PRs:** allowlisted mechanical fixes from bulk tier (`dockerfile_user_root`, `dependency_fixed_version`, `base_image_update`)

## Dismiss comments (audit trail)

| Action | `dismissed_reason` | Comment |
| --- | --- | --- |
| LOW policy | `won't fix` | `Org policy: LOW severity auto-dismissed by security-workflows alert manager` |
| AI false positive | `false positive` | FP gate model + confidence + bulk opinion + remediation note |

## Guardrails

- Scope: Code Scanning only (not Dependabot, not Secret Protection)
- Never AI-dismiss CRITICAL/HIGH
- Never dismiss secret-like rules
- Draft PRs only; Security Gate remains merge authority
- Job is `continue-on-error: true`
- LOW dismiss runs even without OpenRouter; AI FP dismiss requires a valid `OPENROUTER_API_KEY`
- If OpenRouter fails (e.g. 401), heuristic review can still open allowlisted draft fix PRs; it never auto-dismisses FPs
- Draft PRs need org/repo **Allow GitHub Actions to create and approve pull requests** (plus workflow `pull-requests: write`). If blocked, the action pushes a fix branch and prints a compare URL instead.

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
      model: openrouter/auto              # Tier 1 bulk
      cost-tier: medium
      fp-model: anthropic/claude-opus-5   # Tier 2 FP dismiss gate
      max-alerts: '0'                     # 0 = all open non-LOW alerts
      batch-size: '40'
      concurrency: '8'
```

See also [`docs/confidence-benchmark-report.md`](confidence-benchmark-report.md) for model cost/accuracy rationale.


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

*“LOWs are policy. Bulk Auto@medium triages the backlog; Opus only signs off MEDIUM false-positive dismissals. The Security Gate still owns merge.”*
