# GitHub Actions security pipelines — interview cheatsheet

## Core concepts

| Trigger / construct | When to use it |
| --- | --- |
| `on: pull_request` / `push` | Run checks on code changes |
| `on: workflow_dispatch` | Manual / demo runs |
| `on: schedule` | Periodic drift detection |
| `on: workflow_call` | Makes a workflow **reusable** (callable from other repos) |

**Reusable workflow** = a workflow file with `workflow_call` that other workflows invoke via:

```yaml
jobs:
  security:
    uses: org/repo/.github/workflows/reusable-security-ci.yml@v1
    secrets: inherit
    with:
      fail-severity: HIGH
```

**Composite action** = a reusable *step* bundle (`action.yml`). Different from reusable workflows (which are full jobs/workflows).

## Why a central `security-workflows` repo?

- One place to update CodeQL/Trivy/RoguePkg versions and gate policy
- App repos stay thin: a few lines of YAML
- Consistent org-wide quality bars (no CRITICAL/HIGH to main / deploy)

## Secrets

- `secrets: inherit` passes the caller repo’s secrets into the reusable workflow
- Nested reusable workflows only see secrets the parent explicitly maps (or inherits)
- Prefer least privilege: CodeQL needs no third-party token (uses `GITHUB_TOKEN` + `security-events: write`)

## Quality gates (this repo)

1. Each scanner job fails on its own criteria (e.g. Trivy `exit-code: 1` for CRITICAL/HIGH)
2. Orchestrator `Security Gate` job runs `if: always()`, inspects `needs.*.result`, and fails if any enabled scanner is not `success`
3. Branch protection requires **Security Gate** so merges/deploys cannot skip a red check

Interview talking point: *“We don’t block on every Medium forever — we set a severity bar (CRITICAL/HIGH), always block secrets/malware, and report the rest via SARIF.”*

## SARIF → Security tab

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
    category: trivy-sca
```

Needs `permissions: security-events: write` (and `actions: read` for CodeQL). Categories keep CodeQL vs Trivy results distinct.

## Control types (no DAST here)

| Layer | Question it answers | Tool here |
| --- | --- | --- |
| SAST | Is my *code* dangerous? | CodeQL |
| SCA | Are my *dependencies* vulnerable? | Trivy FS |
| IaC | Is my *config/Dockerfile* misconfigured? | Trivy config |
| Secrets | Did we commit credentials? | Trivy secret |
| Image | What’s in the *built container*? | Build + Trivy image |
| Supply chain | Is a dependency *malware / compromised*? | RoguePkg (OSV) |
| DAST | Is the *running app* exploitable? | Out of scope |

## Version pinning

- `@v1` tag → stable for consumers; bump intentionally
- `@main` → always latest (good for demos, riskier for prod)
- Pin third-party actions (`aquasecurity/trivy-action@v0.36.0`, `radioactivetobi/roguepkg@v1`)
- Nested reusable workflows called from another repo must use
  `owner/repo/.github/workflows/file.yml@ref` — relative `./` paths look in the
  top-level caller repo and fail with “workflow was not found”

## Branch protection checklist

1. Require status check: **Security Gate**
2. Require PR before merge (optional but recommended)
3. Restrict who can bypass required checks
4. Optionally block force-pushes to `main`

## Demo script with `vulnerable-app`

1. Open a PR or run **Security** via `workflow_dispatch`
2. Show parallel jobs: CodeQL, Trivy SCA/IaC/Secrets/Image, RoguePkg
3. Open a failed Trivy/RoguePkg log — explain CRITICAL/HIGH or malware
4. Show Security tab SARIF alerts
5. Explain how fixing deps/base image would turn the gate green
6. Mention: intentional failures are the point of this sample app

## Common interview Q&A

**Q: Reusable workflow vs composite action?**  
A: Workflows reuse jobs/pipelines across repos; composites reuse steps inside a job.

**Q: How do you stop CRITICAL from deploying?**  
A: Fail CI on severity + require the gate check in branch protection; keep deploy jobs `needs: [security-gate]` in real CD.

**Q: Why Trivy for both SCA and image?**  
A: Same engine/policy language for FS deps, IaC, secrets, and images — one operational model.

**Q: Why RoguePkg if Trivy SCA exists?**  
A: SCA finds known CVEs; RoguePkg focuses on OSV malware/compromise advisories for npm supply-chain incidents.
