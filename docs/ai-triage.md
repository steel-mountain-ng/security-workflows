# AI security triage

Advisory layer on top of the hard **Security Gate**. It explains findings and can propose draft fixes; it never overrides pass/fail policy.

## What it does

1. Downloads scanner JSON/SARIF artifacts from the same workflow run
2. Builds a capped finding list with short, redacted code snippets
3. Calls [OpenRouter](https://openrouter.ai) with a strict JSON schema
4. Posts a sticky PR comment covering:
   - likely true/false positive
   - confidence
   - exploitability / reachability
   - remediation guidance
5. Optionally opens **draft** fix PRs for allowlisted mechanical fixes

## Hard guardrails

| Rule | Behavior |
| --- | --- |
| Security Gate | Deterministic; AI job is `continue-on-error` and **not** in `needs` of the gate |
| Secrets / RoguePkg | Comment only — never auto-fix |
| Auto-fix allowlist | Dockerfile non-root user; dependency bump when Trivy provides `fixedVersion`; base image `FROM` upgrade |
| Confidence | Draft PRs only when confidence ≥ threshold (default `0.7`) |
| Missing API key | Heuristic triage still comments so demos work offline |

## Setup

1. Create repo or org secret: `OPENROUTER_API_KEY`
2. Ensure the consumer workflow passes it (usually `secrets: inherit`)
3. Caller permissions:

```yaml
permissions:
  contents: write          # draft fix branches when enabled
  actions: read
  security-events: write
  pull-requests: write
```

4. Orchestrator inputs:

```yaml
with:
  run-ai-triage: true
  ai-model: openai/gpt-4o-mini
  ai-max-findings: '25'
  ai-open-fix-prs: false   # set true only where draft PRs are desired
secrets:
  OPENROUTER_API_KEY: ${{ secrets.OPENROUTER_API_KEY }}
```

AI triage runs only on `pull_request` events.

## Artifacts consumed

| Artifact | Contents |
| --- | --- |
| `security-findings-codeql` | `codeql.sarif` |
| `security-findings-trivy-sca` | `trivy-sca.json` (+ sarif) |
| `security-findings-trivy-iac` | `trivy-iac.json` (+ sarif) |
| `security-findings-trivy-secrets` | `trivy-secrets.json` (+ sarif) |
| `security-findings-trivy-image` | `trivy-image.json` (+ sarif) |
| `security-findings-roguepkg` | `roguepkg.json` |

## Components

- Workflow: [`.github/workflows/reusable-ai-triage.yml`](../.github/workflows/reusable-ai-triage.yml)
- Composite action: [`actions/ai-triage`](../actions/ai-triage/)
- Pure function boundary: `actions/ai-triage/triage.py` (`findings → report`) so a future GitHub App can reuse the same logic on webhooks

## Related: alert manager

For **open Code Scanning alerts** (Security tab backlog), see [`alert-manager.md`](alert-manager.md): auto-dismiss LOWs, AI FP dismiss, draft fix PRs.

## Evolution: GitHub App (phase 2)

Move to a GitHub App when you need:

- Stable bot identity (`security-ai[bot]`)
- `check_run` / `workflow_run` webhooks without workflow bloat
- Central OpenRouter key + org-wide install
- Slash commands (`/triage`, `/fix-this`)

Keep `triage.py` as the shared brain; swap the trigger from Actions → App webhook.

## Interview one-liner

*“Policy is code (Security Gate). Judgment is assisted (AI triage). Humans own residual risk — especially secrets and design-level IaC.”*
