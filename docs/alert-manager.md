# Code Scanning alert manager

Backlog hygiene for **open GitHub Code Scanning alerts**. Complements PR AI triage and does **not** change Security Gate pass/fail.

## Pipeline

1. **Rule 1 (policy):** dismiss all open **LOW** / `note` alerts as `won't fix`
2. **Enrich:** package/version, path-based dependency role, SARIF advisory text (`help_uri` fetched for FP-gate candidates)
3. **Tier 1 bulk AI:** classify via `openrouter/auto` (`cost-tier: medium`) using an in-action **exploitability checklist**
4. **Tier 2 FP gate:** re-score bulk `likely_false_positive` candidates with `anthropic/claude-opus-5`
5. **FP dismiss:** only after the FP gate confirms `likely_false_positive` with confidence ≥ `0.85` and severity **MEDIUM** (never CRITICAL/HIGH, never secrets, never “not reachable”)
6. **Report:** markdown decision report → Actions step summary + rolling GitHub Issue `Security alert triage digest`
7. **Draft fix PRs:** allowlisted mechanical fixes only for `likely_true_positive`

## Exploitability checklist (in-action)

Classifications: `likely_true_positive` | `true_positive_not_reachable` | `true_positive_fix_breaks` | `likely_false_positive` | `needs_human`

Each finding must address: advisory summary, exploit conditions, public exploit known, reachability, user-input requirement, mitigations, dependency role, fix risk, decision rationale.

**Example — alert [#3195](https://github.com/steel-mountain-ng/vulnerable-app/security/code-scanning/3195):** Trivy image CVE `brace-expansion` / `CVE-2026-69152` under `usr/local/lib/node_modules/npm/node_modules/...` is a **real** CVE in the Node image npm toolchain. Correct class is usually `true_positive_not_reachable` (not app-reachable), **not** `likely_false_positive`. It must not be auto-dismissed as a false positive.

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
- Checklist module: [`actions/shared/vuln_checklist.py`](../actions/shared/vuln_checklist.py) (copied into alert-manager + ai-triage)
- Workflow: [`reusable-alert-manager.yml`](../.github/workflows/reusable-alert-manager.yml)

## Interview one-liner

*“LOWs are policy. Bulk Auto@medium triages the backlog; Opus only signs off MEDIUM false-positive dismissals. The Security Gate still owns merge.”*
