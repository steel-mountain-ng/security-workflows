# security-workflows

Reusable GitHub Actions security workflows for the `steel-mountain-ng` organization.

**Controls (no DAST):**

| Control | Tool | Quality gate |
| --- | --- | --- |
| SAST | CodeQL | Fail on error/warning SARIF findings |
| SCA | Trivy (`fs`) | Fail on `CRITICAL`/`HIGH` (default) |
| IaC | Trivy (`config`) | Fail on `CRITICAL`/`HIGH` (default) |
| Secrets | Trivy (`secret`) | Fail on any finding |
| Container image | Docker build (local) + Trivy (`image`) | Fail on `CRITICAL`/`HIGH` |
| Supply chain | [RoguePkg](https://github.com/radioactivetobi/roguepkg) | Fail on malware |
| AI triage (advisory) | OpenRouter | **Never** changes Security Gate; PR comments + optional draft fix PRs |
| Alert manager (backlog) | Code Scanning API + OpenRouter | Auto-dismiss LOWs; AI FP dismiss (MEDIUM only); draft fix PRs |

The orchestrator ends with a single **Security Gate** job you can require in branch protection.

No third-party SAST token is required — CodeQL uses GitHub’s built-in Code Scanning.

## Quick start (consumer app)

1. Ensure the calling repository can use workflows from this org repo (same org, or grant Actions access).
2. Add `.github/workflows/security.yml` (see [`examples/consumer-security.yml`](examples/consumer-security.yml)):

```yaml
name: Security

on:
  pull_request:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: write
  actions: read
  security-events: write
  pull-requests: write

jobs:
  security:
    uses: steel-mountain-ng/security-workflows/.github/workflows/reusable-security-ci.yml@v1
    secrets: inherit
    with:
      fail-severity: HIGH
      codeql-languages: javascript
      run-ai-triage: true
```

3. Optional secret: `OPENROUTER_API_KEY` (AI triage). Without it, heuristic triage still comments on PRs.
4. In branch protection / rulesets, require the check named **Security Gate** (do **not** require AI Triage for merges).

## Reusable workflows

| Workflow | Purpose |
| --- | --- |
| [`reusable-security-ci.yml`](.github/workflows/reusable-security-ci.yml) | Orchestrator + Security Gate + AI triage hook |
| [`reusable-codeql.yml`](.github/workflows/reusable-codeql.yml) | SAST (CodeQL) |
| [`reusable-trivy-sca.yml`](.github/workflows/reusable-trivy-sca.yml) | Dependency / filesystem SCA |
| [`reusable-trivy-iac.yml`](.github/workflows/reusable-trivy-iac.yml) | Dockerfile / K8s / Terraform / etc. |
| [`reusable-trivy-secrets.yml`](.github/workflows/reusable-trivy-secrets.yml) | Secret scanning |
| [`reusable-trivy-image.yml`](.github/workflows/reusable-trivy-image.yml) | Build + image scan (no registry push) |
| [`reusable-roguepkg.yml`](.github/workflows/reusable-roguepkg.yml) | Malicious npm package detection |
| [`reusable-ai-triage.yml`](.github/workflows/reusable-ai-triage.yml) | OpenRouter triage + PR comment |
| [`reusable-alert-manager.yml`](.github/workflows/reusable-alert-manager.yml) | Dismiss LOWs / AI FP / draft fixes |

Composite actions: [`actions/ai-triage`](actions/ai-triage/), [`actions/alert-manager`](actions/alert-manager/)

### Common inputs

- `fail-severity`: `CRITICAL` \| `HIGH` (default) \| `MEDIUM` \| `LOW`
- `upload-sarif`: upload results to the GitHub Security tab (default `true`)
- `working-directory`: scan root (default `.`)
- CodeQL: `codeql-languages`, `codeql-queries`
- Image extras: `dockerfile`, `context`, `image-name`
- Scanner toggles: `run-codeql`, `run-trivy-*`, `run-roguepkg`
- AI triage: `run-ai-triage`, `ai-model`, `ai-max-findings`, `ai-open-fix-prs`

### Permissions

```yaml
permissions:
  contents: write           # draft AI fix branches when enabled; otherwise read is enough for scans
  actions: read             # CodeQL + artifact download
  security-events: write    # SARIF → Code Scanning
  pull-requests: write      # AI sticky comments
```

## AI triage + alert manager

- PR assist: [`docs/ai-triage.md`](docs/ai-triage.md)
- Security-tab backlog: [`docs/alert-manager.md`](docs/alert-manager.md) (auto-dismiss **all LOW** alerts first)

**Policy is code (Security Gate). Judgment is assisted (AI). Humans own residual risk.**

## Versioning

```yaml
uses: steel-mountain-ng/security-workflows/.github/workflows/reusable-security-ci.yml@v1
```

The orchestrator calls sibling reusable workflows / the AI action with full `owner/repo/path@v1` refs (not `./`).

## Demo consumer

[`steel-mountain-ng/vulnerable-app`](https://github.com/steel-mountain-ng/vulnerable-app) calls these workflows. It is intentionally insecure, so gates are expected to fail — useful for interview walkthroughs.

## Interview notes

See [`docs/interview-cheatsheet.md`](docs/interview-cheatsheet.md).
