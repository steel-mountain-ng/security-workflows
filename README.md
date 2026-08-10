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
  contents: read
  actions: read
  security-events: write

jobs:
  security:
    uses: steel-mountain-ng/security-workflows/.github/workflows/reusable-security-ci.yml@v1
    with:
      fail-severity: HIGH
      codeql-languages: javascript
```

3. In branch protection / rulesets, require the check named **Security Gate**.

## Reusable workflows

| Workflow | Purpose |
| --- | --- |
| [`reusable-security-ci.yml`](.github/workflows/reusable-security-ci.yml) | Orchestrator + Security Gate |
| [`reusable-codeql.yml`](.github/workflows/reusable-codeql.yml) | SAST (CodeQL) |
| [`reusable-trivy-sca.yml`](.github/workflows/reusable-trivy-sca.yml) | Dependency / filesystem SCA |
| [`reusable-trivy-iac.yml`](.github/workflows/reusable-trivy-iac.yml) | Dockerfile / K8s / Terraform / etc. |
| [`reusable-trivy-secrets.yml`](.github/workflows/reusable-trivy-secrets.yml) | Secret scanning |
| [`reusable-trivy-image.yml`](.github/workflows/reusable-trivy-image.yml) | Build + image scan (no registry push) |
| [`reusable-roguepkg.yml`](.github/workflows/reusable-roguepkg.yml) | Malicious npm package detection |

### Common inputs

- `fail-severity`: `CRITICAL` \| `HIGH` (default) \| `MEDIUM` \| `LOW` — maps to Trivy severity lists that fail the job
- `upload-sarif`: upload results to the GitHub Security tab (default `true`)
- `working-directory`: scan root (default `.`)
- CodeQL: `codeql-languages` (default `javascript`), `codeql-queries` (default `security-and-quality`)
- Image extras: `dockerfile`, `context`, `image-name`
- Toggles: `run-codeql`, `run-trivy-sca`, `run-trivy-iac`, `run-trivy-secrets`, `run-trivy-image`, `run-roguepkg`

### Permissions

Caller workflows should grant at least:

```yaml
permissions:
  contents: read
  actions: read             # CodeQL
  security-events: write    # SARIF → Code Scanning
```

Reusable workflows themselves request least privilege per job.

## Versioning

Prefer a tag for stability:

```yaml
uses: steel-mountain-ng/security-workflows/.github/workflows/reusable-security-ci.yml@v1
```

Use `@main` only when you intentionally want floating updates.

**Note:** The orchestrator calls sibling reusable workflows with full
`owner/repo/path@v1` refs (not `./`). Relative nested `uses:` paths resolve
against the *caller* repo and break cross-repo reuse.

## Demo consumer

[`steel-mountain-ng/vulnerable-app`](https://github.com/steel-mountain-ng/vulnerable-app) calls these workflows. It is intentionally insecure, so gates are expected to fail — useful for interview walkthroughs.

## Interview notes

See [`docs/interview-cheatsheet.md`](docs/interview-cheatsheet.md) for a short GitHub Actions refresher (reusable workflows, secrets inheritance, SARIF, quality gates).
