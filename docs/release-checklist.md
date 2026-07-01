# Release Checklist

Use this checklist before publishing a v1.x SSS release. The goal is a fresh clone that can build, run the demo target, scan it, and export reports without hidden local state.

## Scope Freeze

- Confirm the release is stabilization-only unless a specific feature branch was approved.
- Do not add attack automation, brute force, credential stuffing, fuzzing, exploit execution, or high-volume request behavior.
- Confirm examples do not contain raw credentials, real tokens, or secret-like literals.
- Review `README.md`, `docs/quickstart.md`, `docs/reporting.md`, `docs/scan-policy.md`, and `docs/verification.md` for current behavior.

## Working Tree

```bash
git status --short
git diff --check
make guardrails
```

Success criteria:

- `git status --short` contains only intentional release changes.
- `git diff --check` reports no whitespace errors.
- Guardrail scripts report no secret-like literals or CRLF line endings.

## Docker Build

Scripted path:

```bash
make verify-release
```

Manual path:

```bash
docker compose config
DOCKER_CONFIG=/tmp/docker-empty-config timeout 300 docker compose build backend worker worker-browser
DOCKER_CONFIG=/tmp/docker-empty-config timeout 300 docker compose build frontend
```

Use `DOCKER_CONFIG=/tmp/docker-empty-config` when Docker credential helper configuration blocks local builds.

Set `RUN_E2E_STACK=0 make verify-release` only when Docker services are intentionally unavailable and the remaining local checks still need to run.

## E2E Stack

```bash
timeout 300 docker compose --profile e2e up -d --force-recreate backend worker worker-browser vulnerable-site
docker compose ps
```

Success criteria:

- `postgres` and `redis` are healthy.
- `backend`, `worker`, `worker-browser`, and `vulnerable-site` are running.
- Host preview is reachable at `http://localhost:8081`.
- SSS scan target is `http://vulnerable-site` from inside the Docker network.

## Backend Tests

```bash
cd backend
.venv/bin/python -m pytest tests/ -v
```

Success criteria:

- All backend tests pass.
- Scan policy, report generation, evidence bundle, finding triage, recurrence, and PDF fallback regression tests pass.

## Frontend Build

```bash
cd frontend
npm run build
```

Success criteria:

- TypeScript compile succeeds.
- Vite production build succeeds.

## PDF Smoke

```bash
docker compose exec worker python -c "from weasyprint import HTML; HTML(string='<h1>SSS PDF OK</h1><p>한글 테스트</p>').write_pdf('/tmp/sss_pdf_smoke.pdf')"
docker compose exec worker ls -lh /tmp/sss_pdf_smoke.pdf
```

Success criteria:

- `/tmp/sss_pdf_smoke.pdf` exists.
- File size is non-zero.

## Manual Demo

- Register and log in at `http://localhost`.
- Create a project.
- Run a No Auth scan against `http://vulnerable-site`.
- Run a Browser Login scan against the same target.
- Generate a Cross-scan Auth Delta comparison report.
- Generate KISA and Full reports.
- Generate PDF reports or confirm HTML fallback behavior.
- Download evidence bundle and inspect `manifest.json`, `reports/`, and `evidence/artifact_index.json`.
- Confirm outside-scope and redirect blocking events appear in policy events for the relevant fixtures.

## Release Notes

Use this summary for the v1.4.0 scan policy release:

- URL based No Auth / Browser Login scan
- Cross-scan Auth Delta comparison
- Finding triage and recurrence tracking
- Evidence Artifact and evidence bundle export
- KISA/Full/Markdown/JSON/PDF report generation
- Report Metadata Builder
- Scan Policy/Safety Guardrails
- Outside-scope and redirect blocking events
- WeasyPrint PDF generation support

## Publish

After all checks pass:

```bash
git log --oneline -5
git push origin main
git tag -a v1.4.0-scan-policy -m "SSS v1.4.0 scan policy guardrails"
git push origin v1.4.0-scan-policy
```

If GitHub Actions fails, fix only CI/release hardening issues. Do not add new scanner behavior during release stabilization.
